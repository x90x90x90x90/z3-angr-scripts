import angr
import claripy

# Enable Debugging
angr.manager.l.setLevel("DEBUG")

# Define binary 
p = angr.Project("binary.exe")

# Define 40 char bit vector for argument
arg = claripy.BVS('arg', 0x28 * 8)

# Happy Landing Function
good = 0x402298
# Sad times Function to avoid
bad = 0x4022B1

# Start the program at this location
start = 0x4021D0
# As this one needed to start mid program flow, this sets the data location where the arguement will be stored as it missed the capture bit.
data = 0x406020

# This would zero fill memory and registers but didn't need this in the end
#state = p.factory.entry_state(args=["releaseme.exe",arg], add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})

# Set the state, Lazy solves reduces the verification in the solves, wasn't actually needed for this, the symbol fill stopped the wave of fill messages
state = p.factory.entry_state(args=["releaseme.exe",arg],addr=start, add_options={angr.options.LAZY_SOLVES,angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY})

# Set the timeout, wasn't needed in the end for this one but could be useful
state.solver._solver.timeout=30000000

# Copy the arguement in to the data location because we started the program execution mid flow.
state.memory.store(data, arg)

# Prepare simulation manager
sm = p.factory.simulation_manager(state)

# Find path to happy place!
print(sm.explore(find = good))

# Wassup bitches 
result = sm.found[0]
print (result.solver.eval(arg,cast_to=bytes))
