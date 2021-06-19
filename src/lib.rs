pub mod enums;
pub mod error;
pub mod memory;

use lazy_static::lazy_static;
use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};

lazy_static! {
    pub static ref ALLOCATION_GRANUALATION: u32 = {
        let mut si = SYSTEM_INFO::default();
        unsafe {
            GetSystemInfo(&mut si as *mut SYSTEM_INFO);
        }
        si.dwAllocationGranularity
    };
}
