use lazy_static::lazy_static;
use std::{
    env,
    error::Error,
    ffi::c_void,
    fmt::{self, Formatter, Display},
    mem::{size_of, size_of_val},
    ptr::{self, null, null_mut},
    slice,
};

use winapi::{
    shared::minwindef::{DWORD, FALSE, LPCVOID, PBYTE},
    um::{
        errhandlingapi::GetLastError,
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        memoryapi::VirtualQueryEx,
        processthreadsapi::OpenProcess,
        sysinfoapi::{GetSystemInfo, SYSTEM_INFO},
        tlhelp32::{
            CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
            TH32CS_SNAPPROCESS,
        },
        winbase::{
            FormatMessageW, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM,
            FORMAT_MESSAGE_IGNORE_INSERTS, LocalFree,
        },
        winnt::{
            RtlMoveMemory, HANDLE, LANG_NEUTRAL, LPWSTR, MAKELANGID, MEMORY_BASIC_INFORMATION,
            MEM_COMMIT, MEM_FREE, MEM_PRIVATE, MEM_RESERVE, PAGE_GUARD, PVOID, SUBLANG_DEFAULT,
        },
    },
};

lazy_static! {
    static ref ALLOCATION_GRANUALATION: u32 = {
        let mut si = SYSTEM_INFO::default();
        unsafe {
            GetSystemInfo(&mut si as *mut SYSTEM_INFO);
        }
        si.dwAllocationGranularity
    };
}

type MemMapResult<T> = Result<T, WinAPIError>;

#[derive(Debug)]
struct WinAPIError(u32);

impl WinAPIError {
    fn new() -> Self {
        Self(unsafe { GetLastError() })
    }
}

impl Error for WinAPIError {}

impl fmt::Display for WinAPIError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let message: LPWSTR  = ptr::null_mut();

        let message_size = unsafe {
            FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER
                    | FORMAT_MESSAGE_FROM_SYSTEM
                    | FORMAT_MESSAGE_IGNORE_INSERT,
                null(),
                self.0,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT).into(),
                message ,
                0,
                null_mut(),
            )
        };

        if message_size == 0 {
            panic!("FormatMessageW failed!!!");
        }

        let message_buffer = unsafe { slice::from_raw_parts(message as *const u16, message_size as usize) }.to_vec();

        unsafe {LocalFree(message as *mut c_void)};

       write!(f, "{}",
            String::from_utf16(&message_buffer)
                .expect("Failed to build error message info")
        )
    }
}

struct VmQueryHelp {
    rng_size: usize,
    rng_storage: u32,
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

        let mut address_blk: PVOID = range_base_address;

        let mut rng_storage: u32 = mbi.Type;

        let mut protected_block = [0u32; 4];
        let mut rng_blocks = 0;
        let mut rng_guard_blocks = 0;
        let mut rng_size = 0;

        loop {
            let vmqueury_result: usize =
                unsafe { VirtualQueryEx(process, address_blk, &mut mbi, size_of_val(&mbi)) };

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

            address_blk = unsafe { (address_blk as PBYTE).add(mbi.RegionSize) } as PVOID;
        }

        let rng_is_stack = rng_guard_blocks > 0;

        Ok(Self {
            rng_size,
            rng_storage,
            rng_blocks: rng_blocks as u32,
            rng_guard_blocks,
            rng_is_stack,
        })
    }
}

#[derive(Debug)]
struct VMQuery {
    rng_base_address: PVOID,
    rng_protection: u32,
    rng_size: usize,
    rng_storage: u32,
    rng_blocks: u32,
    rng_guard_blocks: u32,
    rng_is_stack: bool,
    block_base_address: PVOID,
    block_protection: u32,
    block_size: usize,
    block_storage: u32,
}

impl VMQuery {
    fn new(process: HANDLE, address: LPCVOID) -> MemMapResult<Self> {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let vmqeuery_result =
            unsafe { VirtualQueryEx(process, address, &mut mbi, size_of_val(&mbi)) };

        if vmqeuery_result == 0 {
            return Err(WinAPIError::new());
        }

        let (block_base_address, block_size, block_protection, block_storage) = match mbi.State {
            MEM_FREE => (ptr::null_mut(), 0, 0, MEM_FREE),
            MEM_RESERVE => (
                mbi.BaseAddress,
                mbi.RegionSize,
                mbi.AllocationProtect,
                MEM_RESERVE,
            ),
            MEM_COMMIT => (mbi.BaseAddress, mbi.RegionSize, mbi.Protect, mbi.Type),
            _ => unreachable!(),
        };

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
                mbi.AllocationProtect,
                mbi.RegionSize,
                MEM_FREE,
                0,
                0,
                false,
            ),
            MEM_RESERVE | MEM_COMMIT => {
                let vmquery_help = VmQueryHelp::new(process, address)?;
                (
                    mbi.AllocationBase,
                    mbi.AllocationProtect,
                    vmquery_help.rng_size,
                    vmquery_help.rng_storage,
                    vmquery_help.rng_blocks,
                    vmquery_help.rng_guard_blocks,
                    vmquery_help.rng_is_stack,
                )
            }
            _ => unreachable!(),
        };

        Ok(Self {
            rng_base_address,
            rng_protection,
            rng_size,
            rng_storage,
            rng_blocks,
            rng_guard_blocks,
            rng_is_stack,
            block_base_address,
            block_protection,
            block_size,
            block_storage,
        })
    }
}

fn main() {
    let process_name = env::args().nth(1).expect("Process name must be present");

    let process_id = get_process_id(process_name).unwrap();

    let process: HANDLE = unsafe { OpenProcess(0, FALSE, process_id) };

    let vmquery = VMQuery::new(process, ptr::null()).map_err(|e| e.to_string()).unwrap();
    println!("{:?}", vmquery);
}

fn get_process_id(process_name: String) -> MemMapResult<u32> {
    let mut process_info = PROCESSENTRY32::default();
    process_info.dwSize = size_of_val(&process_info) as u32;

    let processes_snapshot: HANDLE = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if processes_snapshot == INVALID_HANDLE_VALUE {
        return Err(WinAPIError::new());
    }

    unsafe {
        Process32First(processes_snapshot, &mut process_info);
    }

    let array_i8_to_string = |array: &[i8]| -> String {
        String::from_utf8(array.iter().map(|&symbol| symbol as u8).collect())
            .expect("Failed to convert process file name to UTF8 string")
    };

    if array_i8_to_string(&process_info.szExeFile).contains(process_name.as_str()) {
        unsafe {
            CloseHandle(processes_snapshot);
        }
        return Ok(process_info.th32ProcessID);
    }

    while unsafe { Process32Next(processes_snapshot, &mut process_info) } != FALSE {
        if array_i8_to_string(&process_info.szExeFile).contains(process_name.as_str()) {
            unsafe {
                CloseHandle(processes_snapshot);
            }
            return Ok(process_info.th32ProcessID);
        }
    }

    unsafe { CloseHandle(processes_snapshot) };
    Err(WinAPIError::new())
}
