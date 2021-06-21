use std::mem::size_of_val;

use winapi::{
    shared::{minwindef::FALSE, ntdef::HANDLE},
    um::{
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        processthreadsapi::OpenProcess,
        tlhelp32::{
            CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
            TH32CS_SNAPPROCESS,
        },
        winnt::PROCESS_ALL_ACCESS,
    },
};

use crate::{
    error::{MemMapResult, WinAPIError},
    utils::array_i8_to_string,
};

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub handle: HANDLE,
    pub process_id: u32,
}

impl ProcessInfo {
    pub fn new(process_name: String) -> MemMapResult<ProcessInfo> {
        let mut process_info = PROCESSENTRY32::default();
        process_info.dwSize = size_of_val(&process_info) as u32;

        let processes_snapshot: HANDLE = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if processes_snapshot == INVALID_HANDLE_VALUE {
            return Err(WinAPIError::new());
        }

        let mut process_id = None;
        unsafe {
            Process32First(processes_snapshot, &mut process_info);
        }

        if array_i8_to_string(&process_info.szExeFile).contains(process_name.as_str()) {
            process_id = Some(process_info.th32ProcessID);
        } else {
            while unsafe { Process32Next(processes_snapshot, &mut process_info) } != FALSE {
                if array_i8_to_string(&process_info.szExeFile).contains(process_name.as_str()) {
                    process_id = Some(process_info.th32ProcessID);
                    break;
                }
            }
        }

        unsafe { CloseHandle(processes_snapshot) };

        match process_id {
            Some(process_id) => {
                let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id) };
                if handle.is_null() {
                    return Err(WinAPIError::new());
                }

                Ok(Self { handle, process_id })
            }
            None => Err(WinAPIError::new()),
        }
    }
}

impl Drop for ProcessInfo {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}
