import sys

exe_base = 0x140000000

hidden_function_name = "e_hidden_function"
hidden_function_patch_point = 0x1C

final_state = b"\x3d\x44\x71\x89\xd5\xc1\x36\xa6\x83\x83\xdf\xc6\x96\xa9\x20\x57\x74\xe4\xde\xb4\xd7\xa6\x46\x33\x42\x8a\xdb\x76\x1e\x0b\xae\xfa\x76\x69"
final_state_patch_point = 0x4E

def find_hidden_function(map_file_name):
    hidden_function = None
    with open(map_file_name, "r") as map_file:
        for line in map_file:
            if hidden_function_name in line:
                print("[" + hidden_function_name + "]")

                address = int(line.split()[2], 16)
                print("\tAddress:\t" + hex(address))

                base_offset = address - exe_base
                print("\tOffset:\t\t" + hex(base_offset))

                # Offset as little endian pointer
                return base_offset.to_bytes(8, 'little')


def patch_exe(exe_file_name, map_file_name):
    hidden_function = find_hidden_function(map_file_name)
    
    with open(exe_file_name, "rb+") as exe_file:
        print("[Patching " + hex(hidden_function_patch_point) + "] (&__ImageBase.e_res[0])")
        exe_file.seek(hidden_function_patch_point)
        print("\tOriginal Bytes:\t" + str(exe_file.read(8)))
        exe_file.seek(hidden_function_patch_point)
        exe_file.write(hidden_function)
        exe_file.seek(hidden_function_patch_point)
        print("\tNew Bytes:\t" + str(exe_file.read(8)))

        print("[Patching " + hex(final_state_patch_point) + "] (&__ImageBase.e_res2[0])")
        exe_file.seek(final_state_patch_point)
        print("\tOriginal Bytes:\t" + str(exe_file.read(len(final_state))))
        exe_file.seek(final_state_patch_point)
        exe_file.write(final_state)
        exe_file.seek(final_state_patch_point)
        print("\tNew Bytes:\t" + str(exe_file.read(len(final_state))))

if len(sys.argv) != 3:
    print("Usage: python patch_exe.py exe_file map_file")
else:
    patch_exe(sys.argv[1], sys.argv[2])