from z3 import *


# Some constant information about the flag
FLAG_LEN     = 25
FLAG_START   = "TUCTF{"
FLAG_END     = "}"

#flag_len_var = FLAG_LEN - len(FLAG_START) - len(FLAG_END)

# Setup a flag with a certain length
flag = [BitVec(f"flag_arr[{i}]", 8) for i in range(FLAG_LEN)]

s = Solver()


# Add some initial constraints based on the flag format

for i, c in enumerate(FLAG_START):
    s.add(flag[i] == ord(c))

for i, c in enumerate(FLAG_END):
    j = FLAG_LEN - i - 1
    s.add(flag[j] == ord(c))

# Add constraints to make each character printable
for i in range(FLAG_LEN):
    s.add(flag[i] > 0x20)
    s.add(flag[i] < 0x7f)


# Challenge password (as bytes, since we'll be doing arithmetic on this later)
chal_pass = b"\x8b\xce\xb0\x89\x7b\xb0\xb0\xee\xbf\x92\x65\x9d\x9a\x99\x99\x94\xad\xe4"



# Create a 5x5 matrix
mat = [[0 for _ in range(5)] for _ in range(5)]

# Translation of the array initialization
for i in range(25):
    m = (i * 2) % 25
    f = (i * 7) % 25
    mat[m//5][m%5] = flag[f]


# Add the challenge constraints
s.add(chal_pass[0]  == mat[0][0] + mat[4][4])
s.add(chal_pass[1]  == mat[2][1] + mat[0][2])
s.add(chal_pass[2]  == mat[4][2] + mat[4][1])
s.add(chal_pass[3]  == mat[1][3] + mat[3][1])
s.add(chal_pass[4]  == mat[3][4] + mat[1][2])
s.add(chal_pass[5]  == mat[1][0] + mat[2][3])
s.add(chal_pass[6]  == mat[2][4] + mat[2][0])
s.add(chal_pass[7]  == mat[3][3] + mat[3][2] + mat[0][3])
s.add(chal_pass[8]  == mat[0][4] + mat[4][0] + mat[0][1])
s.add(chal_pass[9]  == mat[3][3] + mat[2][0])
s.add(chal_pass[10] == mat[4][0] + mat[1][2])
s.add(chal_pass[11] == mat[0][4] + mat[4][1])
s.add(chal_pass[12] == mat[0][3] + mat[0][2])
s.add(chal_pass[13] == mat[3][0] + mat[2][0])
s.add(chal_pass[14] == mat[1][4] + mat[1][2])
s.add(chal_pass[15] == mat[4][3] + mat[2][3])
s.add(chal_pass[16] == mat[2][2] + mat[0][2])
s.add(chal_pass[17] == mat[1][1] + mat[4][1])



if s.check() == sat:
    print("Found a solution")

    # Hacky way to convert a model into an array
    flag_arr = [1]*FLAG_LEN
    for statement in str(s.model())[1:-1].replace(' ', '').split(','):
        exec(statement)

    flag_string = ''.join([chr(i) for i in flag_arr])
    print(flag_string)
else:
    print("Failed to find a solution. Very sad :(")
