from random import randint, random
from multiprocessing import Pool
from main import *

ITERATIONS = 16
MAX_ITER = 10
MAX_FLAG_LENGTH = 50000000
CHANGE_BASE_PROB = 0

def generate_flag(flag, process):
	global id
	bases = []
	for i in range(ITERATIONS):
		if len(flag) > MAX_FLAG_LENGTH: return
		if random() > (CHANGE_BASE_PROB)**i or i > MAX_ITER:
				base = randint(2,36)
				print(f"{process}: iteration {i}, Encoding with base {base}")
				bases.append(base)
				flag = base_n_encode(flag, base)
				print(f"{process}:", i, len(flag))
		else:
			while True:
				base = randint(2,36)
				print(f"{process}: iteration {i}, Attempting encoding with base {base}")
				temp = base_n_encode(flag, base)
				if guess_base(temp) != base:
					bases.append(base)
					flag = temp
					print(f"{process}:", i, len(flag))
					break
	key = "".join([ALPHABET[i] for i in bases][::-1])
	f = open(f"{process}_flag_enc", "wb")
	f.write(flag)
	f.close()
	g = open(f"{process}_key", "w")
	g.write(key)
	g.close()
#	return flag, bases, key

flag = b"flag{r4DixAL}"
f = lambda x: generate_flag(flag, x)
with Pool(8) as p:
	for i in p.starmap(generate_flag, [(flag,i) for i in range(10)]):
		pass
