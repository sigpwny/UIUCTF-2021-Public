# Solution to speakeasy
1. Throw binary in reverse engineering tool of choice
2. Notice segment name with `vmp` in it and conclude binary is protected by VMProtect
3. Find and download [NoVmp](https://github.com/can1357/NoVmp) and [VTIL-Utils](https://github.com/vtil-project/VTIL-Utils)
4. Use [NoVmp](https://github.com/can1357/NoVmp) to dump out all VMProtected functions to VTIL files
5. Use [VTIL-Utils](https://github.com/vtil-project/VTIL-Utils) to dump VTIL functions to human readable instructions
6. Put VTIL dumps alongside reverse engineering tool of choice and reference corresponding VTIL dump whenever a VMProtected function is found
7. Analyze binary and see that input from `gets` in `main` is passed into `sub_140001630`
8. Analyze `sub_140001630` and notice that it first iterates `0x28` times and calls VMProtected function `sub_1400014C0` each iteration with with inputs `i` and `user_input[i]`
9. Notice that the output from `sub_1400014C0` is stored in `unknown_buffer[i]` each iteration
10. Analyze `0000000000028270.optimized.vtil` and conclude that it xors `(uint8_t*)(base + 0x14378)[i]` with `user_input[i]`
11. Go back to analyzing `sub_140001630` and notice that the second thing it does is iterate over the length of user input calling VMProtected function `sub_1400014F0` with inputs `i` and `unknown_buffer[i]`
12. Analyze `00000000000262C9.optimized.vtil` and conclude that it xors `unknown_buffer[i]` with `(uint8_t*)(base + 0x143C8)[i] << 1`
13. Go back to analyzing `sub_140001630` and notice that the last thing it does is call VMProtected function `sub_1400015D0` with input `unknown_buffer`
14. Analyze `000000000012B360.optimized.vtil` and conclude that it calls a function pointer read from `base + 0x1C` with the inputs `0` and `unknown_buffer`
15. Realize that your reverse engineering tool shows the binary starting at `base + 0x1000` making the contents of `base + 0x1C` invisible
16. Look to `file + 0x1C` in a hex editor and realize the function pointer was hidden in the binary's DOS header
17. Analyze the hidden function `sub_140001520` and notice that it is VMProtected
18. Analyze `000000000012B2EF.optimized.vtil` and conclude that it calls `memcmp` with inputs `unknown_buffer`, `base + 0x4E`, and `0x22`
19. Realize that `base + 0x4E` is the correct final state of `unknown_buffer` in order to pass the challenge and that `base + 0x4E` must contain an encrypted form of the flag
20. Extract the final state of length `0x22` bytes from `file + 0x4E`
21. Xor each byte of the final state with `(uint8_t*)(base + 0x143C8)[i] << 1`
22. Xor each byte of that result with `base + 0x0x14378`
23. Profit?