import random
import hashlib
import os

def _seed(s):
	if type(s) == int:
		_n = abs(s)
	elif type(s) == str or type(s) == bytes or type(s) == bytearray:
		if type(s) == str:
			s = s.encode()

		_n = int.from_bytes(s + hashlib.sha512(s).digest(), "big")
	elif s == None:
		print("NoneType seed leads to random result")
		exit()
	elif type(s) == float:
		raise NotImplementedError # cuz I was lazy..
	else:
		return None

	uint32_mask = 1 << 32

	mt = [0 for i in range(624)]

	mt[0] = 0x12bd6aa
	for i in range(1, 624):
		mt[i] = (0x6c078965 * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i) % uint32_mask

	keys = []

	while _n:
		keys.append(_n % uint32_mask)
		_n >>= 32

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

	keylen = int(keylen)

	step1_rnd = max(624, keylen)

	init_state = state

	N = 624
	uint32_mask = 1 << 32
	state = list(state[1][:-1])

	assert state[0] == 0x80000000
	assert len(state) == N
	state[0] = state[N-1]
	i = (1 + step1_rnd) % 623

	for k in range(N - 1):
		i = i - 1
		if i <= 0:
			i += 623
		state[i] = ((state[i] + i) ^ ((state[i-1] ^ (state[i-1] >> 30)) * 0x5d588b65)) % uint32_mask
		state[0] = state[N-1]

	origin_state = [0 for _ in range(N)]
	origin_state[0] = 0x12bd6aa
	for i in range(1,N):
		origin_state[i] = (0x6c078965 * (origin_state[i-1] ^ (origin_state[i-1] >> 30)) + i) % uint32_mask


	key = [0 for i in range(keylen)]

	if lower == None:
		for i in range(keylen - 623):
			key[i] = 1
	else:
		if lower.bit_length() > 32 * (keylen - 623):
			print("Too much fixed bits.")
			return None
		for i in range(keylen - 623):
			key[i] = lower % uint32_mask
			lower >>= 32

	i, j = 1, 0
	if keylen >= 624:
		for _ in range(step1_rnd - 623):
			origin_state[i] = ((origin_state[i] ^ ((origin_state[i-1] ^ (origin_state[i-1] >> 30)) * 0x19660d)) + key[j] + j) % uint32_mask
			i += 1
			j += 1
			if i >= 624:
				origin_state[0] = origin_state[623]
				i = 1

	for _ in range(N - 1):
		x = ((origin_state[i] ^ ((origin_state[i-1] ^ (origin_state[i-1] >> 30)) * 0x19660d)) + j) % uint32_mask
		key[j] = (state[i] - x) % uint32_mask
		origin_state[i] = ((origin_state[i] ^ ((origin_state[i-1] ^ (origin_state[i-1] >> 30)) * 0x19660d)) + key[j] + j) % uint32_mask

		i += 1
		if i == N:
			origin_state[0] = origin_state[N-1]
			i = 1
		j += 1
		j %= keylen

	if key[-1] == 0:
		print("This seed won't work because key length doesn't match.")
		print("Try setting another lower bits.")
		return None

	mySeed = 0

	for i in range(keylen-1,-1,-1):
		mySeed = mySeed << 32
		mySeed += key[i]

	if _seed(mySeed) != init_state:
		print("Fail.")
		return None

	return mySeed


def check():
	# seed check
	assert random.Random(0).getstate() == _seed(0)
	for _ in range(10):
		s = os.urandom(16)
		assert random.Random(s).getstate() == _seed(s)

		s = int.from_bytes(os.urandom(5000), "big")
		assert random.Random(s).getstate() == _seed(s) == random.Random(-s).getstate() == _seed(-s)

	# seed recovery check
	for _ in range(10):
		state = _seed(os.urandom(16))

		seed1 = state2seed(state)
		seed2 = state2seed(state, lower = int.from_bytes(os.urandom(4)))
		
		assert _seed(seed1) == _seed(seed2) == state

	# longer seed check
	for _ in range(10):
		state = _seed(os.urandom(16))

		seed1 = state2seed(state)
		keylen = (int.from_bytes(os.urandom(2), "big") % 2000) + 624
		seed2 = state2seed(state, keylen = keylen)

		assert _seed(seed1) == _seed(seed2) == state

	# small seed check
	for _ in range(10):
		keylen = os.urandom(1)[0]
		seed1 = random.randrange(2**(32 * (keylen - 1)), 2**(32 * keylen))
		state = _seed(seed1)
		
		assert state2seed(state, keylen=keylen) == seed1

if __name__ == "__main__":
	check()
