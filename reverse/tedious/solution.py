import angr
import sys
import claripy

def success(curr_state):
    # Get the value of the stdout at the current state
    stdout_str = curr_state.posix.dumps(sys.stdout.fileno())
    return b"GOOD JOB!" in stdout_str # Will return whether or not it matches
def fail(curr_state):
    # Get the value of the stdout at the current state
    stdout_str = curr_state.posix.dumps(sys.stdout.fileno())
    return b"WRONG" in stdout_str # Will return whether or not it matches

flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(38)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

p = angr.Project('challenge')
state = p.factory.entry_state(args=['./challenge'], stdin=flag)

for c in flag_chars:
    state.solver.add(c >= ord("!"))
    state.solver.add(c <= ord("~"))

sm = p.factory.simulation_manager(state)
sm.explore(find=success, avoid=fail)

found = sm.found[0]
flag_str = found.solver.eval_upto(flag, 7, cast_to = bytes)
print(flag_str)