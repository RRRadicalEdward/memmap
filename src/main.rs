use std::{env, mem::size_of_val};

use memmap::{
    error::{MemMapResult, WinAPIError},
    memory::VMQuery,
};

use winapi::{
    shared::minwindef::FALSE,
    um::{
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        processthreadsapi::OpenProcess,
        tlhelp32::{
            CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
            TH32CS_SNAPPROCESS,
        },
        winnt::{HANDLE, PROCESS_ALL_ACCESS},
    },
};

fn main() -> Result<(), WinAPIError> {
    let process_name = env::args().nth(1).expect("Process name must be present");

    let process = find_process_by_name(process_name)?;

    if process.is_null() {
        return Err(WinAPIError::new());
    }

    let vmquery = VMQuery::new(process)?;

    println!("{}", vmquery);

    Ok(())
}

fn find_process_by_name(process_name: String) -> MemMapResult<HANDLE> {
    let mut process_info = PROCESSENTRY32::default();
    process_info.dwSize = size_of_val(&process_info) as u32;

    let processes_snapshot: HANDLE = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if processes_snapshot == INVALID_HANDLE_VALUE {
        return Err(WinAPIError::new());
    }

    let array_i8_to_string = |array: &[i8]| -> String {
        String::from_utf8(array.iter().map(|&symbol| symbol as u8).collect())
            .expect("Failed to convert process file name to UTF8 string")
    };

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
        Some(process_id) => Ok(unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id) }),
        None => Err(WinAPIError::new()),
    }
}
