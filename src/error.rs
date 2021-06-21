use std::{
    error::Error,
    fmt::{self, Formatter},
    ptr, slice,
};

use winapi::{
    shared::minwindef::HLOCAL,
    um::{
        errhandlingapi::GetLastError,
        winbase::{
            FormatMessageA, LocalFree, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM,
            FORMAT_MESSAGE_IGNORE_INSERTS,
        },
        winnt::LPSTR,
    },
};

pub type MemMapResult<T> = Result<T, WinAPIError>;

#[derive(Debug)]
pub struct WinAPIError {
    description: String,
}

impl WinAPIError {
    pub fn new() -> Self {
        let mut message_buffer = ptr::null_mut();

        let description = unsafe {
            let message_size = FormatMessageA(
                FORMAT_MESSAGE_ALLOCATE_BUFFER
                    | FORMAT_MESSAGE_FROM_SYSTEM
                    | FORMAT_MESSAGE_IGNORE_INSERTS,
                ptr::null(),
                GetLastError(),
                0,
                (&mut message_buffer as *mut LPSTR) as LPSTR,
                0,
                ptr::null_mut(),
            );

            let slice = slice::from_raw_parts(message_buffer as *const u8, message_size as usize);

            LocalFree(message_buffer as HLOCAL);
            String::from_utf8_lossy(slice).trim_end().to_owned()
        };

        Self { description }
    }
}

impl Default for WinAPIError {
    fn default() -> Self {
        WinAPIError::new()
    }
}

impl Error for WinAPIError {}

impl fmt::Display for WinAPIError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description)
    }
}
