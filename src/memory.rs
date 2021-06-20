use std::{
    fmt::{self, Formatter},
    mem::size_of_val,
    ptr,
};

use winapi::um::{
    memoryapi::VirtualQueryEx,
    sysinfoapi::{GetSystemInfo, SYSTEM_INFO},
    winnt::{
        HANDLE, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_FREE, MEM_RESERVE, PAGE_GUARD, PVOID,
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
    pub fn new(process: HANDLE) -> MemMapResult<Self> {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();

        let mut system_info = SYSTEM_INFO::default();
        unsafe {
            GetSystemInfo(&mut system_info);
        }

        let mut address = system_info.lpMinimumApplicationAddress;

        let mut memory_blocks = Vec::new();
        while address <= system_info.lpMaximumApplicationAddress {
            let vmqeuery_result =
                unsafe { VirtualQueryEx(process, address, &mut mbi, size_of_val(&mbi)) };

            if vmqeuery_result == 0 {
                return Err(WinAPIError::new());
            }

            memory_blocks.push(MemoryBlock::new(&mbi));

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
            "rng_base_address: {:p}\nrng_size: {} bytes\nrng_blocks_count: {}\nrng_guard_blocks_count: {}\nmemory_blocs: {:#?}",
            self.rng_base_address,
            self.rng_size,
            self.rng_blocks_count,
            self.rng_guard_blocks_count,
            self.memory_blocks
        )
    }
}

#[derive(Debug)]
struct MemoryBlock {
    block_base_address: PVOID,
    block_protection: MemoryPageProtection,
    block_size: usize,
    block_storage: MemState,
    page_type: PagesType,
    is_stack: bool,
}

impl MemoryBlock {
    fn new(mbi: &MEMORY_BASIC_INFORMATION) -> Self {
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
        }
    }
}

impl fmt::Display for MemoryBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "block_base_address: {:p}\n,block_size: {} bytes, block_protection: {:?}, block_storage: {:?}, is_stack: {}, page type: {:?}",
               self.block_base_address, self.block_size, self.block_protection, self.block_storage, self.is_stack, self.page_type
        )
    }
}
