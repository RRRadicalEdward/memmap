use std::env;

use memmap::{
    error::MemMapResult,
    memory::{ProcessInfo, VMQuery},
};

fn main() -> MemMapResult<()> {
    let process_name = env::args().nth(1).expect("Process name must be present");
    let process_info = ProcessInfo::new(process_name)?;
    let vmquery = VMQuery::new(process_info)?;

    println!("{}", vmquery);

    Ok(())
}
