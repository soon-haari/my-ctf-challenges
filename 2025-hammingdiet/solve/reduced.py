class MT19937:
	def __init__(self, st):
		self.mt = list(st)
		self.index = 624

	def temper(self, x):
		x ^= x >> 11
		x ^= (x << 7) & 0x9d2c5680
		x ^= (x << 15) & 0xefc60000
		x ^= x >> 18
		return x

	def single_twist_extract(self):
		x = (self.mt[0] & 0x80000000) | (self.mt[1] & 0x7fffffff)
		self.mt[0] = self.mt[397] ^ (x >> 1)

		if x & 1:
			self.mt[0] ^= 0x9908b0df

		x = self.temper(self.mt[0])

		self.mt = self.mt[1:] + self.mt[:1]

		return x

if __name__ == "__main__":
	import random

	st = random.getstate()[1][:-1]
	r = MT19937(st)

	NDAT = 10000

	for i in range(NDAT):
		assert random.getrandbits(32) == r.single_twist_extract()
