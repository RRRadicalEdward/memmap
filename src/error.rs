use std::{
    error::Error,
    fmt::{self, Formatter},
    ptr,
};
use widestring::U16String;
use winapi::{
    shared::minwindef::HLOCAL,
    um::{
        errhandlingapi::GetLastError,
        winbase::{
            FormatMessageW, LocalFree, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM,
            FORMAT_MESSAGE_IGNORE_INSERTS,
        },
        winnt::LPWSTR,
    },
};

pub type MemMapResult<T> = Result<T, WinAPIError>;

#[derive(Debug)]
pub struct WinAPIError {
    description: String,
}

impl WinAPIError {
    pub fn new() -> Self {
        let mut message_buffer: LPWSTR = ptr::null_mut();

        let description = unsafe {
            let message_size = FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER
                    | FORMAT_MESSAGE_FROM_SYSTEM
                    | FORMAT_MESSAGE_IGNORE_INSERTS,
                ptr::null(),
                GetLastError(),
                0,
                (&mut message_buffer as *mut LPWSTR) as LPWSTR,
                0,
                ptr::null_mut(),
            );

            let message = U16String::from_ptr(message_buffer, message_size as usize);
            LocalFree(message_buffer as HLOCAL);
            message.to_string_lossy().trim_end().to_string()
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
