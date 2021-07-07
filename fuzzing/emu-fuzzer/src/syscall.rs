/// Handle syscalls, in a way that is not super locked in to a specific arch.
///
/// Each arch we implement must do the  number -> syscall transition, as well as the argument
/// parsing by itself.

use crate::emu::VmExit;
use crate::mmu::{Mmu, VirtAddr};

pub fn sys_exit(exit_code: u64) -> Result<i64, VmExit> {
    Err(VmExit::Exit(exit_code))
}

pub fn write(mmu: &Mmu, fd: i64, p_buf: VirtAddr, count: u64) -> Result<i64, VmExit> {
    // Read from the buffer
    let mut tmp = vec![0u8; count as usize];
    mmu.read_into(p_buf, &mut tmp)?;

    // print to stdin / stdout / stderr
    if fd == 0 || fd == 1 || fd == 2 {
        if crate::ALLOW_GUEST_PRINT {
            // TODO; This is not accurate, we should also be printing unprintable chars
            print!("{}", String::from_utf8_lossy(&tmp));
        }

        // Return the number of bytes written.
        return Ok(count as i64);
    }

    // failed to write, return -1;
    Ok(!0)
}

pub fn sbrk(mmu: &mut Mmu, increment: i64) -> Result<i64, VmExit> {
    let increment = core::cmp::max(0i64, increment) as usize;
    let base: i64 = mmu.allocate(increment)
                       .unwrap_or(VirtAddr(!0)).0 as i64;
    Ok(base)
}

