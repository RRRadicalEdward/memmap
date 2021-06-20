use std::{
    fmt::{self, Formatter},
    mem::size_of_val,
    ptr,
    rc::Rc,
};

use winapi::{
    shared::{
        minwindef::{BYTE, FALSE, TRUE},
        shared::ntdef::LPSTR,
    },
    um::{
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        memoryapi::VirtualQueryEx,
        processthreadsapi::OpenProcess,
        psapi::GetMappedFileNameA,
        sysinfoapi::{GetSystemInfo, SYSTEM_INFO},
        tlhelp32::{
            CreateToolhelp32Snapshot, Module32First, Module32Next, Process32First, Process32Next,
            MODULEENTRY32, PROCESSENTRY32, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
            TH32CS_SNAPPROCESS,
        },
        winnt::{
            HANDLE, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_FREE, MEM_RESERVE, PAGE_GUARD,
            PROCESS_ALL_ACCESS, PVOID,
        },
    },
};

use crate::{
    enums::{MemState, MemoryPageProtection, PagesType},
    error::{MemMapResult, WinAPIError},
};

#[derive(Debug)]
pub struct VMQuery {
    rng_base_address: PVOID,
    rng_size: usize,
    rng_blocks_count: usize,
    rng_guard_blocks_count: usize,
    memory_blocks: Vec<MemoryBlock>,
}

impl VMQuery {
    pub fn new(process: ProcessInfo) -> MemMapResult<Self> {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();

        let mut system_info = SYSTEM_INFO::default();
        unsafe {
            GetSystemInfo(&mut system_info);
        }

        let mut address = system_info.lpMinimumApplicationAddress;

        let mut memory_blocks = Vec::new();
        let process_info = Rc::new(process.clone());
        while address <= system_info.lpMaximumApplicationAddress {
            let vmqeuery_result =
                unsafe { VirtualQueryEx(process.handle, address, &mut mbi, size_of_val(&mbi)) };

            if vmqeuery_result == 0 {
                return Err(WinAPIError::new());
            }

            memory_blocks.push(MemoryBlock::new(&mbi, process_info.clone()));

            address = unsafe { address.add(mbi.RegionSize) };
        }

        let rng_base_address = memory_blocks
            .first()
            .map(|block| block.block_base_address)
            .unwrap_or(ptr::null_mut());
        let rng_size = memory_blocks.iter().map(|block| block.block_size).sum();
        let rng_guard_blocks_count = memory_blocks
            .iter()
            .filter(|block| block.block_protection == MemoryPageProtection::Guard)
            .count();

        Ok(Self {
            rng_base_address,
            rng_size,
            rng_blocks_count: memory_blocks.len(),
            rng_guard_blocks_count,
            memory_blocks,
        })
    }
}

impl fmt::Display for VMQuery {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rng_base_address: {:p}\nrng_size: {} bytes\nrng_blocks_count: {}\nrng_guard_blocks_count: {}\nmemory blocks: {:#?}",
            self.rng_base_address,
            self.rng_size,
            self.rng_blocks_count,
            self.rng_guard_blocks_count,
            self.memory_blocks
        )
    }
}

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

struct MemoryBlock {
    block_base_address: PVOID,
    block_protection: MemoryPageProtection,
    block_size: usize,
    block_storage: MemState,
    page_type: PagesType,
    is_stack: bool,
    process_info: Rc<ProcessInfo>,
}

impl MemoryBlock {
    fn new(mbi: &MEMORY_BASIC_INFORMATION, process_info: Rc<ProcessInfo>) -> Self {
        let (block_protection, block_storage, page_type, is_stack) = match mbi.State {
            MEM_FREE => (
                MemoryPageProtection::CallerDoesNotHaveAccess,
                MemState::MemFree,
                PagesType::Undefined,
                false,
            ),
            MEM_RESERVE => (
                MemoryPageProtection::from(mbi.AllocationProtect),
                MemState::MemReserve,
                PagesType::from(mbi.Type),
                false,
            ),
            MEM_COMMIT => (
                MemoryPageProtection::from(mbi.AllocationProtect),
                MemState::MemCommit,
                PagesType::from(mbi.Type),
                mbi.Protect & PAGE_GUARD == PAGE_GUARD,
            ),
            _ => unreachable!("No others mem states exist"),
        };

        Self {
            block_base_address: mbi.BaseAddress,
            block_protection,
            block_size: mbi.RegionSize,
            block_storage,
            is_stack,
            page_type,
            process_info,
        }
    }

    pub fn find_module(&self) -> MemMapResult<Option<String>> {
        let mut module_entry = MODULEENTRY32::default();
        module_entry.dwSize = size_of_val(&module_entry) as u32;

        let processes_snapshot: HANDLE = unsafe {
            CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                self.process_info.process_id,
            )
        };

        if processes_snapshot == INVALID_HANDLE_VALUE {
            return Err(WinAPIError::new());
        }

        let mut module_name = None;
        unsafe {
            Module32First(processes_snapshot, &mut module_entry);
        }

        if unsafe { Module32First(processes_snapshot, &mut module_entry) } == TRUE {
            if module_entry.modBaseAddr == self.block_base_address as *mut BYTE {
                module_name = Some(array_i8_to_string(&module_entry.szExePath));
            }
        } else {
            while unsafe { Module32Next(processes_snapshot, &mut module_entry) } != FALSE {
                if module_entry.modBaseAddr == self.block_base_address as *mut BYTE {
                    module_name = Some(array_i8_to_string(&module_entry.szExePath));
                }
            }
        }

        unsafe { CloseHandle(processes_snapshot) };

        Ok(module_name)
    }

    pub fn mapped_file(&self) -> Option<String> {
        let mut filename: [i8; 260] = [0; 260];
        let read: u32 = unsafe {
            GetMappedFileNameA(
                self.process_info.handle,
                self.block_base_address,
                &mut filename as LPSTR,
                260,
            )
        };

        if read == 0 {
            return None;
        }

        Some(array_i8_to_string(&filename[0..read as usize]))
    }
}

impl fmt::Debug for MemoryBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut address_description = if self.is_stack {
            String::from("THREAD STACK")
        } else if let Ok(module_path) = self.find_module() {
            module_path
                .map(|module_path| format!("MODULE: {}", module_path))
                .unwrap_or_default()
        } else {
            String::new()
        };

        if let Some(mapped_file) = self.mapped_file() {
            address_description.push_str(&format!(" MAPPED FILE: {}", mapped_file))
        }

        write!(f, "[\n\tblock_base_address: {:p} {}\n\tblock_size: {} bytes\n\tblock_protection: {:?}\n\tblock_storage: {:?}\n\tpage type: {:?}\n]",
               self.block_base_address, address_description, self.block_size, self.block_protection, self.block_storage, self.page_type
        )
    }
}

fn array_i8_to_string(array: &[i8]) -> String {
    String::from_utf8_lossy(
        &array
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&symbol| symbol as u8)
            .collect::<Vec<u8>>(),
    )
    .to_string()
}
