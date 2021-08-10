# Tedious Solution

This challenge requires users to enter in a flag. A correct flag will get you a "GOOD JOB" while an incorrect flag will get you "WRONG." The flag itself is 38 characters long.

This challenge pretty much irreversible. People can reverse it to see the code, but actually manually reversing all the code will take forever and will be extremely tedious. The only option is to use angr.  

### The correct angr code looks like this:

```python
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
```

### Full file can be found in folder
