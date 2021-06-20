#[derive(Debug, PartialEq)]
pub enum MemState {
    MemCommit,
    MemFree,
    MemReserve,
    Undefined,
}

impl From<u32> for MemState {
    fn from(state: u32) -> Self {
        match state {
            0x1000 => MemState::MemCommit,
            0x2000 => MemState::MemReserve,
            0x10000 => MemState::MemFree,
            _ => MemState::Undefined,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum PagesType {
    MemImage,
    MemMapped,
    MemPrivate,
    Undefined,
}

impl From<u32> for PagesType {
    fn from(_type: u32) -> Self {
        match _type {
            0x20000 => PagesType::MemPrivate,
            0x40000 => PagesType::MemMapped,
            0x1000000 => PagesType::MemImage,
            _ => PagesType::Undefined,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum MemoryPageProtection {
    Undefined,
    CallerDoesNotHaveAccess,
    NoAccess,
    ReadOnly,
    ReadWrite,
    WriteCopy,
    Execute,
    ExecuteRead,
    ExecuteReadWrite,
    ExecuteWriteCopy,
    TargetsInvalid,
    TargetsNoUpdateORInvalid,
    Guard,
    NoCache,
    WriteCombine,
}

impl From<u32> for MemoryPageProtection {
    fn from(val: u32) -> Self {
        match val {
            0x00 => MemoryPageProtection::CallerDoesNotHaveAccess,
            0x01 => MemoryPageProtection::NoAccess,
            0x02 => MemoryPageProtection::ReadOnly,
            0x04 => MemoryPageProtection::ReadWrite,
            0x08 => MemoryPageProtection::WriteCopy,
            0x10 => MemoryPageProtection::Execute,
            0x20 => MemoryPageProtection::ExecuteRead,
            0x40 => MemoryPageProtection::ExecuteReadWrite,
            0x80 => MemoryPageProtection::ExecuteWriteCopy,
            0x40000000 => MemoryPageProtection::TargetsNoUpdateORInvalid,
            _ => MemoryPageProtection::Undefined,
        }
    }
}
