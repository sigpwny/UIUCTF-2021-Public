The module implements a finite state machine that recognizes the byte sequence
corresponding to the flag string.  Invalid inputs reset the state to "idle",
while inputs that get closer to the flag cause a transition into a different
state.  By exposing the internal state as an additional output of the module,
inputs can be fed into the state machine to see how they affect the state.  If
the state changes to a value that has not been seen before, that character must
be correct.  If the state changes to a value that has been seen before, that
character must not be correct.  For any prefix, every character can be tried to
see what the next character must be.  Starting from `uiuctf{`, characters can
be successively determined in this way until the complete flag is obtained.
