from Crypto.Util.number import long_to_bytes, bytes_to_long
from gmpy2 import mpz, to_binary

ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ#"

def base_n_encode(bytes_in, base):
	return mpz(bytes_to_long(bytes_in)).digits(base).upper().encode()

def base_n_decode(bytes_in, base):
	bytes_out = to_binary(mpz(bytes_in, base=base))[:1:-1]
	return bytes_out

def encrypt(bytes_in, key):
	out = bytes_in
	for i in key:
		out = base_n_encode(out, ALPHABET.index(i))
	return out

def decrypt(bytes_in, key):
	out = bytes_in
	for i in key:
		out = base_n_decode(out, ALPHABET.index(i))
	return out

def guess_base(bytes_in):
	return 1+max([ALPHABET.index(chr(i)) for i in bytes_in])
