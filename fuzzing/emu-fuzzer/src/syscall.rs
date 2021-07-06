/// Handle syscalls, in a way that is not super locked in to a specific arch.
///
/// Each arch we implement must do the  number -> syscall transition, as well as the argument
/// parsing by itself.

use crate::emu::VmExit;

pub fn sys_exit(exit_code: u64) -> Result<(), VmExit> {
    Err(VmExit::Exit(exit_code))
}


