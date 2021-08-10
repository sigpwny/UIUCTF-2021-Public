# Solution

### TLDR
see solve.cpp for code

Order of the function calls don't matter and the functions are cumulative.
Thus all you have to do is find the total of all function calls and then
use that information to reverse each of the functions one time. The total is
calculated using the sum of the first 1337 primes.

### How do the functions work

```cpp
rot("abcd", 2) -> "cdef" //shifts letters up 2 places in the alphabet
shift("abcd", 2) -> "cdab" //rotates string by 2 places
```

These functions are cumulative: 
```cpp
rot(input, 2) + rot(input, 4) = rot(input, 6)
```

Order does not actually matter: 
```cpp
rot("abcd", 2) + shift("abcd", 2) = shift("abcd", 2) + rot("abcd", 2)
```

### How to calculate primes
We start with a vector containing just 2. For a given number, we check if 
any primes in the list divide the number, if none of them do, then the given 
number is prime. We then append this number to the vector and repeat until 
we reach the desired length for the list

### Solution

The code for the functions rot and shift can be determined from opening
the binary in a tool like Ghidra. The function rot preserves underscores.
Next it can be determined that the third function is a generating function
generate(int n) that returns a list of the first n primes

To undo rot:
```cpp
string unscrambled = rot(scrambled, 26 - (total % 26))
```

To undo shift: 

```cpp
string unscrambled = rot(scrambled, scramble.length() - (total % scramble.length()))
```

Do these in succession (again, order doesn't matter) to find the desired 
input for the output. Since the functions are cumulative. Determine the total 
number of inputs by finding the sum of the first 1337 primes.

And so we have: uiuctf{i_propose_to_consider_the_question_can_machines_think}

I've included solution and source code.