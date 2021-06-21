use std::{
    fmt::{self, Formatter},
    mem::size_of_val,
    ptr,
    rc::Rc,
};

use winapi::{
    shared::{
        minwindef::{BYTE, FALSE, MAX_PATH, TRUE},
        ntdef::LPSTR,
    },
    um::{
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        memoryapi::VirtualQueryEx,
        psapi::GetMappedFileNameA,
        sysinfoapi::{GetSystemInfo, SYSTEM_INFO},
        tlhelp32::{
            CreateToolhelp32Snapshot, Module32First, Module32Next, MODULEENTRY32,
            TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
        },
        winnt::{
            HANDLE, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_FREE, MEM_RESERVE, PAGE_GUARD, PVOID,
        },
    },
};

use crate::{
    enums::{MemState, MemoryPageProtection, PagesType},
    error::{MemMapResult, WinAPIError},
    process_info::ProcessInfo,
    utils::array_i8_to_string,
};

#[derive(Debug)]
pub struct ProcessMemory {
    base_address: PVOID,
    size: usize,
    blocks_count: usize,
    guard_blocks_count: usize,
    memory_blocks: Vec<MemoryBlock>,
}

impl ProcessMemory {
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
            .map(|block| block.base_address)
            .unwrap_or(ptr::null_mut());
        let rng_size = memory_blocks.iter().map(|block| block.size).sum();
        let rng_guard_blocks_count = memory_blocks
            .iter()
            .filter(|block| block.protection == MemoryPageProtection::Guard || block.is_stack)
            .count();

        Ok(Self {
            base_address: rng_base_address,
            size: rng_size,
            blocks_count: memory_blocks.len(),
            guard_blocks_count: rng_guard_blocks_count,
            memory_blocks,
        })
    }
}

impl fmt::Display for ProcessMemory {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "base_address: {:p}\nsize: {} bytes\nblocks_count: {}\nguard_blocks_count: {}\nmemory blocks: {:#?}",
            self.base_address,
            self.size,
            self.blocks_count,
            self.guard_blocks_count,
            self.memory_blocks
        )
    }
}

struct MemoryBlock {
    base_address: PVOID,
    protection: MemoryPageProtection,
    size: usize,
    storage: MemState,
    page_type: PagesType,
    is_stack: bool,
    process_info: Rc<ProcessInfo>,
}

impl MemoryBlock {
    fn new(mbi: &MEMORY_BASIC_INFORMATION, process_info: Rc<ProcessInfo>) -> Self {
        let (block_protection, storage, page_type, is_stack) = match mbi.State {
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
            base_address: mbi.BaseAddress,
            protection: block_protection,
            size: mbi.RegionSize,
            storage,
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
            if module_entry.modBaseAddr == self.base_address as *mut BYTE {
                module_name = Some(array_i8_to_string(&module_entry.szExePath));
            }
        } else {
            while unsafe { Module32Next(processes_snapshot, &mut module_entry) } != FALSE {
                if module_entry.modBaseAddr == self.base_address as *mut BYTE {
                    module_name = Some(array_i8_to_string(&module_entry.szExePath));
                }
            }
        }

        unsafe { CloseHandle(processes_snapshot) };

        Ok(module_name)
    }

    pub fn mapped_file(&self) -> MemMapResult<Option<String>> {
        let mut filename: [i8; 260] = [0; MAX_PATH];
        let read: u32 = unsafe {
            GetMappedFileNameA(
                self.process_info.handle,
                self.base_address,
                &mut filename as LPSTR,
                MAX_PATH as u32,
            )
        };

        if read == 0 {
            return Err(WinAPIError::new());
        }

        Ok(Some(array_i8_to_string(&filename[0..read as usize])))
    }
}

impl fmt::Debug for MemoryBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut address_description = if self.is_stack {
            String::from("THREAD STACK")
        } else if let Ok(Some(module_path)) = self.find_module() {
            format!("MODULE: {}", module_path)
        } else {
            String::new()
        };

        if let Ok(Some(mapped_file)) = self.mapped_file() {
            address_description.push_str(&format!(" MAPPED FILE: {}", mapped_file))
        }

        write!(f, "[\n\tbase_address: {:p} {}\n\tsize: {} bytes\n\tprotection: {:?}\n\tstorage: {:?}\n\tpage type: {:?}\n]",
               self.base_address, address_description, self.size, self.protection, self.storage, self.page_type
        )
    }
}
