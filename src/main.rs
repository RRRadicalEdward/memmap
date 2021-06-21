use std::env;

use memmap::{error::MemMapResult, memory::ProcessMemory, process_info::ProcessInfo};

fn main() -> MemMapResult<()> {
    let process_name = env::args().nth(1).expect("Process name must be present");
    let process_info = ProcessInfo::new(process_name)?;
    let vmquery = ProcessMemory::new(process_info)?;

    println!("{}", vmquery);

    Ok(())
}
