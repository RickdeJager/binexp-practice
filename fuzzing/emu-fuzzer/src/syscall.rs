/// Handle syscalls, in a way that is not super locked in to a specific arch.
///
/// Each arch we implement must do the  number -> syscall transition, as well as the argument
/// parsing by itself.


// https://sourceware.org/newlib/libc.html#Syscalls

use crate::emu::VmExit;
use crate::mmu::{Mmu, VirtAddr};
use crate::files::FilePool;

/// Error out with a clean VmExit::exit.
pub fn exit(exit_code: i64) -> Result<i64, VmExit> {
    Err(VmExit::Exit(exit_code))
}

/// Return the (effective) UID of the emulator user.
/// -> Assuming 1000 for now
pub fn getuid() -> Result<i64, VmExit> {
    Ok(1000)
}

/// Return the (effective) GID of the emulator user.
/// -> Assuming 1000 for now
pub fn getgid() -> Result<i64, VmExit> {
    Ok(1000)
}

/// We will never actually close Fd's, but we could invalidate it so we can catch a program
/// using a closed Fd.  (TODO)
pub fn close(_fd: i64) -> Result<i64, VmExit> {
    Ok(0)
}

/// Set pointer to thread id.
/// TODO; Implement
pub fn set_tid_address(mmu: &mut Mmu, tidptr: VirtAddr) -> Result<i64, VmExit> {
    let tid = 0i32;
    mmu_write!(mmu, tidptr, tid)?;
    Ok(0)
}

/// Set pointer to thread id.
/// TODO; Implement
pub fn set_robust_list(mmu: &mut Mmu, headprt: VirtAddr, len: i32) -> Result<i64, VmExit> {
    Ok(-1)
}

/// Take's a pointer from user space, and fills it with a utsname struct containing some kernel
/// information.
/// Returns 0 on success, -1 on failure.
pub fn uname(mmu: &mut Mmu, p_uname: VirtAddr) -> Result<i64, VmExit> {
    // sysname, nodename, release, version, machine, (domainname)
    // Each field is 64+1 bytes in size.
    let values = ["Linux", "Fuzzy", "5.4.0-84-generic",
                  "#94-Ubuntu SMP Thu Aug 26 20:27:37 UTC 2021", "riscv64"];
    let mut buf = [0u8; 65*6];
    for (idx, value) in values.iter().enumerate() {
        let addr = 65usize.checked_mul(idx).unwrap();
        buf[addr..addr+value.len()].copy_from_slice(value.as_bytes());
    }
    // Write the buffer in one go, s.t. RAW bits are correctly cleared.
    mmu.write_from(p_uname, &buf)?;
    Ok(0)
}


/// Stat a file discriptor, write the result into p_statbuf
pub fn fstat(mmu: &mut Mmu, file_pool: &FilePool, fd: i64, p_statbuf: VirtAddr) 
        -> Result<i64, VmExit> {

    match file_pool.fstat(fd as usize) {
        Some(data) => {
            // Attempt to write stat struct
            mmu.write_from(p_statbuf, data)?;
            Ok(0)
        },
        None => Ok(-1),
    }
}

pub fn write(mmu: &Mmu, fd: i64, p_buf: VirtAddr, count: u64) -> Result<i64, VmExit> {
    // Read from the buffer
    let mut tmp = vec![0u8; count as usize];
    mmu.read_into(p_buf, &mut tmp)?;

    // print to stdin / stdout / stderr
    if fd == 0 || fd == 1 || fd == 2 {
        if crate::ALLOW_GUEST_PRINT {
            // TODO; This is not accurate, we should also be printing unprintable chars.
            print!("{}", String::from_utf8_lossy(&tmp));
        }

        // Return the number of bytes written.
        return Ok(count as i64);
    }

    // failed to write, return -1;
    Ok(!0)
}

pub fn brk(mmu: &mut Mmu, size: i64) -> Result<i64, VmExit> {
    // If our current allocation suffices, just ret here.
    if size <= mmu.cur_alloc.0 as i64 {
        return Ok(mmu.cur_alloc.0 as i64);
    }

    let increment = size as usize - mmu.cur_alloc.0;
    // If we managed to allocate something, return it.
    match mmu.allocate(increment) {
        Some(_) => Ok(mmu.cur_alloc.0 as i64),
           None => Ok(-1),
    }
}

pub fn open(fp: &mut FilePool, filepath: &str, flags: i64) -> Result<i64, VmExit> {
    assert!(flags == 0, "We only support O_RDONLY files");

    match fp.open(filepath) {
        Some(fd) => Ok(fd as i64),
            None => Ok(-1),
    }
}

pub fn read(fp: &mut FilePool, mmu: &mut Mmu, fd: i64, p_buf: VirtAddr, 
            count: usize) -> Result<i64, VmExit> {
    
    match fp.read(fd as usize, count) {
        Some(data) => {
            mmu.write_from(p_buf, data)?;
            Ok(data.len() as i64)
        },
        None => Ok(-1)
    }
}

pub fn lseek(fp: &mut FilePool, fd: i64, offset: i64, whence: i32) -> Result<i64, VmExit> {
    match fp.lseek(fd as usize, offset, whence) {
        Some(num) => Ok(num),
        None => Ok(-1),
    }
}

