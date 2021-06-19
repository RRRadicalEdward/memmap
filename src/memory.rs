use std::{
    ffi::c_void,
    fmt::{self, Formatter},
    mem::{size_of, size_of_val},
    ptr,
};

use winapi::{
    shared::minwindef::{DWORD, LPCVOID, PBYTE},
    um::{
        memoryapi::VirtualQueryEx,
        winnt::{
            RtlMoveMemory, HANDLE, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_FREE, MEM_PRIVATE,
            MEM_RESERVE, PAGE_GUARD, PVOID,
        },
    },
};

use crate::{
    enums::{MemState, MemoryPageProtection},
    error::{MemMapResult, WinAPIError},
};

#[derive(Debug)]
pub struct VMQuery {
    rng_base_address: PVOID,
    rng_protection: MemoryPageProtection,
    rng_size: usize,
    rng_mem_state: MemState,
    rng_blocks_count: u32,
    rng_guard_blocks_count: u32,
    rng_is_stack: bool,
    memory_blocks: Vec<MemoryBlock>,
}

impl VMQuery {
    pub fn new(process: HANDLE, address: LPCVOID) -> MemMapResult<Self> {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let vmqeuery_result =
            unsafe { VirtualQueryEx(process, address, &mut mbi, size_of_val(&mbi)) };

        if vmqeuery_result == 0 {
            return Err(WinAPIError::new());
        }

        let memory_blocks = vec![MemoryBlock::new(&mbi)];

        let (
            rng_base_address,
            rng_protection,
            rng_size,
            rng_storage,
            rng_blocks,
            rng_guard_blocks,
            rng_is_stack,
        ) = match mbi.State {
            MEM_FREE => (
                mbi.BaseAddress,
                MemoryPageProtection::from(mbi.AllocationProtect),
                mbi.RegionSize,
                MemState::MemFree,
                0,
                0,
                false,
            ),
            MEM_RESERVE | MEM_COMMIT => {
                let vmquery_help = VmQueryHelp::new(process, address)?;
                (
                    mbi.AllocationBase,
                    MemoryPageProtection::from(mbi.AllocationProtect),
                    vmquery_help.rng_size,
                    vmquery_help.mem_state,
                    vmquery_help.rng_blocks,
                    vmquery_help.rng_guard_blocks,
                    vmquery_help.rng_is_stack,
                )
            }
            _ => unreachable!("No others mem states exist"),
        };

        Ok(Self {
            rng_base_address,
            rng_protection,
            rng_size,
            rng_mem_state: rng_storage,
            rng_blocks_count: rng_blocks,
            rng_guard_blocks_count: rng_guard_blocks,
            rng_is_stack,
            memory_blocks,
        })
    }
}

impl fmt::Display for VMQuery {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rng_base_address: {:p}\nrng_protection: {:?}\nrng_size: {} bytes\nrng_mem_state: {:?}\nrng_blocks: {}\nrng_guard_blocks: {}\nrng_is_stack: {}\nmemory_blocs: {:?}",
            self.rng_base_address,
            self.rng_protection,
            self.rng_size,
            self.rng_mem_state,
            self.rng_blocks_count,
            self.rng_guard_blocks_count,
            self.rng_is_stack,
            self.memory_blocks
        )
    }
}

struct VmQueryHelp {
    rng_size: usize,
    mem_state: MemState,
    rng_blocks: u32,
    rng_guard_blocks: u32,
    rng_is_stack: bool,
}

impl VmQueryHelp {
    fn new(process: HANDLE, address: LPCVOID) -> MemMapResult<Self> {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();

        let vmqueury_result: usize =
            unsafe { VirtualQueryEx(process, address, &mut mbi, size_of_val(&mbi)) };

        if vmqueury_result != size_of_val(&mbi) {
            return Err(WinAPIError::new());
        }

        let range_base_address: PVOID = mbi.AllocationBase;
        let mut address_block: PVOID = range_base_address;

        let mut rng_storage: u32 = mbi.Type;

        let mut protected_block = [0u32; 4];
        let mut rng_blocks = 0;
        let mut rng_guard_blocks = 0;
        let mut rng_size = 0;

        loop {
            let vmqueury_result: usize =
                unsafe { VirtualQueryEx(process, address_block, &mut mbi, size_of_val(&mbi)) };

            if vmqueury_result != size_of_val(&mbi) || mbi.AllocationBase != range_base_address {
                break;
            }

            if rng_blocks < 4 {
                protected_block[rng_blocks] = if mbi.State == MEM_RESERVE {
                    0
                } else {
                    mbi.Protect
                };
            } else {
                unsafe {
                    RtlMoveMemory(
                        protected_block[0] as *mut c_void,
                        protected_block[1] as *const c_void,
                        size_of_val(&mbi) - size_of::<DWORD>(),
                    );
                }

                protected_block[3] = if mbi.State == MEM_RESERVE {
                    0
                } else {
                    mbi.Protect
                }
            }

            rng_blocks += 1;
            rng_size += mbi.RegionSize;

            if mbi.Protect & PAGE_GUARD == PAGE_GUARD {
                rng_guard_blocks += 1;
            }

            if rng_storage == MEM_PRIVATE {
                rng_storage = mbi.Type;
            }

            address_block = unsafe { (address_block as PBYTE).add(mbi.RegionSize) } as PVOID;
        }

        let rng_is_stack = rng_guard_blocks > 0;

        Ok(Self {
            rng_size,
            mem_state: MemState::from(rng_storage),
            rng_blocks: rng_blocks as u32,
            rng_guard_blocks,
            rng_is_stack,
        })
    }
}

#[derive(Debug)]
struct MemoryBlock {
    block_base_address: PVOID,
    block_protection: MemoryPageProtection,
    block_size: usize,
    block_storage: MemState,
}

impl MemoryBlock {
    fn new(mbi: &MEMORY_BASIC_INFORMATION) -> Self {
        let (block_base_address, block_size, block_protection, block_storage) = match mbi.State {
            MEM_FREE => (
                ptr::null_mut(),
                0,
                MemoryPageProtection::CallerDoesNotHaveAccess,
                MemState::MemFree,
            ),
            MEM_RESERVE => (
                mbi.BaseAddress,
                mbi.RegionSize,
                MemoryPageProtection::from(mbi.AllocationProtect),
                MemState::MemReserve,
            ),
            MEM_COMMIT => (
                mbi.BaseAddress,
                mbi.RegionSize,
                MemoryPageProtection::from(mbi.Protect),
                MemState::from(mbi.Type),
            ),
            _ => unreachable!("No others mem states exist"),
        };

        Self {
            block_base_address,
            block_protection,
            block_size,
            block_storage,
        }
    }
}

impl fmt::Display for MemoryBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "block_base_address: {:p}\n,block_size: {} bytes, block_protection: {:?}, block_storage: {:?}",
               self.block_base_address, self.block_size, self.block_protection, self.block_storage
        )
    }
}
