import angr
import claripy
import time
from pwn import *

base_addr = 0x100000
flag_len = 0xe

#seting up the angr project
p = angr.Project('./fairlight', main_opts={'base_addr': base_addr})

flag_chars = [claripy.BVS(f"flag_{i}", 8) for i in range(flag_len)]

flag = claripy.Concat( *flag_chars )

# enable unicorn engine for fast efficient solving
st = p.factory.entry_state(
        args=["./fairlight", flag],
        add_options=angr.options.unicorn,
       )

#constrain to non-newline bytes
#constrain to ascii-only characters
for k in flag_chars:
    st.solver.add(k < 0x7f)
    st.solver.add(k > 0x20)

# Construct a SimulationManager to perform symbolic execution.
# Step until there is nothing left to be stepped.
sm = p.factory.simulation_manager(st)
sm.run()

#grab all finished states, that have the win function output in stdout
y = []
for x in sm.deadended:
    if not b"NOPE" in x.posix.dumps(1):
        y.append(x)

#grab the first ouptut
valid = y[0].solver.eval(flag, cast_to=bytes)
print(f"Found flag: >>>{valid}<<<")

