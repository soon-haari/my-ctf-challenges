import random
from pwn import *
import hashlib
import os

def seed(s):
	if type(s) == int:
		n = abs(s)
	elif type(s) == str or type(s) == bytes or type(s) == bytearray:
		if type(s) == str:
			s = s.encode()

		n = int.from_bytes(s + hashlib.sha512(s).digest(), "big")
	elif s == None:
		print("NoneType seed leads to random result")
		exit()
	elif type(s) == float:
		raise NotImplementedError # cuz I was lazy..

	uint32_mask = 1 << 32

	mt = [0 for i in range(624)]

	mt[0] = 0x12bd6aa
	for i in range(1, 624):
		mt[i] = (0x6c078965 * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i) % uint32_mask

	keys = []
	while n:
		keys.append(n % uint32_mask)
		n >>= 32

	if len(keys) == 0:
		keys.append(0)

	i, j = 1, 0
	for _ in range(max(624, len(keys))):
		mt[i] = ((mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 0x19660d)) + keys[j] + j) % uint32_mask
		i += 1
		j += 1
		if i >= 624:
			mt[0] = mt[623]
			i = 1
		j %= len(keys)

	for _ in range(623):
		mt[i] = ((mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 0x5d588b65)) - i) % uint32_mask
		i += 1
		if i >= 624:
			mt[0] = mt[623]
			i = 1

	mt[0] = 0x80000000

	state = (3, tuple(mt + [624]), None)

	return state


def state2seed(state, keylen = 624, lower = None):
	# The mersenne Twister consists on 19936 = 623 * 32 bits.
	# But the modified seed calculator also consists on 19936 bits, rest of the bits are free!
	# How interesting..

	if keylen < 624:
		print("This is very dangerous, if you really need a small seed, implement your own logic to find one.")
		exit()

	step1_rnd = max(624, keylen)

	N = 624
	uint32_mask = 1 << 32
	state = list(state[1][:-1])
	final_state = state[:]
	assert state[0] == 0x80000000
	assert len(state) == N
	state[0] = state[N-1]
	i = (1 + step1_rnd) % 623

	for k in range(N - 1):
		i = i - 1
		if i <= 0:
			i += 623
		state[i] = ((state[i] + i) ^ ((state[i-1] ^ (state[i-1] >> 30)) * 1566083941)) % uint32_mask
		state[0] = state[N-1]

	mt = state[:]

	i = (1 + step1_rnd) % 623
	if i == 0:
		i = 623

	for _ in range(623):
		mt[i] = ((mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 0x5d588b65)) - i) % uint32_mask
		i += 1
		if i >= 624:
			mt[0] = mt[623]
			i = 1

	mt[0] = 0x80000000
	try:
		assert mt == final_state
	except:
		for i in range(624):
			if mt[i] != final_state[i]:
				print(i)
		exit()

	origin_state = [0 for _ in range(N)]
	origin_state[0] = 19650218
	for i in range(1,N):
		origin_state[i] = (1812433253 * (origin_state[i-1] ^ (origin_state[i-1] >> 30)) + i) % uint32_mask


	key = [0 for i in range(keylen)]

	if lower == None:
		for i in range(keylen - 623):
			key[i] = 1
	else:
		if lower.bit_length() > 32 * (keylen - 623):
			print("Too much fixed bits")
			exit()
		for i in range(keylen - 623):
			key[i] = lower % uint32_mask
			lower >>= 32

	i, j = 1, 0
	for _ in range(step1_rnd - 623):
		origin_state[i] = ((origin_state[i] ^ ((origin_state[i-1] ^ (origin_state[i-1] >> 30)) * 0x19660d)) + key[j] + j) % uint32_mask
		i += 1
		j += 1
		if i >= 624:
			origin_state[0] = origin_state[623]
			i = 1

	for _ in range(N - 1):
		x = ((origin_state[i] ^ ((origin_state[i-1] ^ (origin_state[i-1] >> 30)) * 1664525)) + j) % uint32_mask
		key[j] = (state[i] - x) % uint32_mask
		origin_state[i] = ((origin_state[i] ^ ((origin_state[i-1] ^ (origin_state[i-1] >> 30)) * 1664525)) + key[j] + j) % uint32_mask

		i += 1
		if i == N:
			origin_state[0] = origin_state[N-1]
			i = 1
		j += 1

	if key[-1] == 0:
		print("This seed won't work because key length doesn't match.")
		print("Try setting another lower bits.")
		exit()

	mySeed = 0
	for i in range(keylen-1,-1,-1):
		mySeed = mySeed << 32
		mySeed += key[i]
	return mySeed


def check():
	# seed check
	assert random.Random(0).getstate() == seed(0)
	for _ in range(10):
		s = os.urandom(16)
		assert random.Random(s).getstate() == seed(s)

		s = int.from_bytes(os.urandom(5000), "big")
		assert random.Random(s).getstate() == seed(s) == random.Random(-s).getstate() == seed(-s)

	# seed recovery check
	for _ in range(10):
		state = seed(os.urandom(16))

		seed1 = state2seed(state)
		seed2 = state2seed(state, lower = int.from_bytes(os.urandom(4)))
		
		assert seed(seed1) == seed(seed2) == state

	# longer seed check
	for _ in range(10):
		state = seed(os.urandom(16))

		seed1 = state2seed(state)
		keylen = (int.from_bytes(os.urandom(2), "big") % 2000) + 624
		seed2 = state2seed(state, keylen = keylen)

		assert seed(seed1) == seed(seed2) == state



if __name__ == "__main__":
	check()
	__import__('sys').set_int_max_str_digits(100000)

	imp = "Merry Christmas! You are the True winner, regardless of the ranking, running nonstop towards your dreams! Thanks for playing, and have fun!!"

	s_str = imp
	state = seed(s_str)

	s_bytes = s_str.encode()
	assert seed(s_bytes) == state


	s_int1 = state2seed(state, keylen = 1800, lower = int.from_bytes(imp.encode(), "big"))
	assert seed(s_int1) == state

	s_int2 = state2seed(state, keylen = 750)
	assert seed(s_int2) == state

	s_int3 = state2seed(state, keylen = 624)
	assert seed(s_int3) == state

	s_int4 = int.from_bytes(s_bytes + hashlib.sha512(s_bytes).digest(), "big")
	assert seed(s_int4) == state

	s_int5 = -s_int4
	assert seed(s_int5) == state

	assert 2**40000 <= s_int1
	assert 2**20000 <= s_int2 < 2**40000
	assert 2**2000  <= s_int3 < 2**20000
	assert 0        <= s_int4 < 2**2000
	assert             s_int5 < 0
	assert s_str == s_int1.to_bytes(10000, "big")[-len(s_str):].decode() == imp


	io = remote("haari.me", 1225)

	io.sendlineafter(b": ", str(s_int1).encode())
	io.sendlineafter(b": ", str(s_int2).encode())
	io.sendlineafter(b": ", str(s_int3).encode())
	io.sendlineafter(b": ", str(s_int4).encode())
	io.sendlineafter(b": ", str(s_int5).encode())
	io.sendlineafter(b": ", s_str.encode())
	io.sendlineafter(b": ", bytes.hex(s_bytes).encode())

	io.interactive()