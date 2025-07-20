from pwn import *
context.log_level = "critical"

import ast

def dig():
	while True:
		io = remote("localhost", 9999r)
		io.recvuntil(b"K = Finite Field of size ")
		p = int(io.recvline())
		
		# make p large as possible since the parameter is tight
		if p > 0.9 * 2^35:
			break
		io.close()


	K = GF(p)
	R = K["x"]

	d = 20

	dat = []

	for _ in range(d + 3):
		io.recvuntil(b"f(")
		x = int(io.recvuntil(b")")[:-1])
		io.recvuntil(b"some two values of ")
		r = ast.literal_eval(io.recvline().decode()[:-1])

		dat.append([x, r])

	ndat = len(dat)

	M0 = Matrix(K, [[K(x)^i for i in range(d + 1)] for x, r in dat])
	lker = M0.left_kernel_matrix()

	l = lker.nrows()
	assert l == ndat - (d + 1)

	M = Matrix(ZZ, 4 * ndat + l + 1, 4 * ndat + l + 1)

	weight = p^2

	for i in range(ndat):
		x, r = dat[i]
		assert len(r) == 4

		M[4 * i + 0, 4 * i + 0] = p^2
		M[4 * i + 1, 4 * i + 0] = p^2
		M[4 * i + 2, 4 * i + 0] = p^2
		M[4 * i + 3, 4 * i + 0] = p^2

		M[4 * i + 1, 4 * i + 1] = p * 10
		M[4 * i + 2, 4 * i + 2] = p * 10
		M[4 * i + 3, 4 * i + 3] = p * 10

		for j in range(l):
			M[4 * i + 0, 4 * ndat + j] = ZZ(r[0]) * ZZ(lker[j, i]) * weight
			M[4 * i + 1, 4 * ndat + j] = ZZ(r[1]) * ZZ(lker[j, i]) * weight
			M[4 * i + 2, 4 * ndat + j] = ZZ(r[2]) * ZZ(lker[j, i]) * weight
			M[4 * i + 3, 4 * ndat + j] = ZZ(r[3]) * ZZ(lker[j, i]) * weight

	for i in range(l):
		M[4 * ndat + i, 4 * ndat + i] = weight * p


	vec = [2 * p^2, 5 * p, 5 * p, 5 * p] * ndat + [0] * l + [p]
	M[4 * ndat + l] = vector(ZZ, vec)

	M = M.LLL()

	bound = 3 * ndat + 1

	M2 = []
	for v in M[:bound]:
		assert max(max(v), max(-v)) < p^(3/2)

		v2 = []
		for i in range(ndat):
			block = v[4 * i:4 * (i + 1)]
			assert block[0] == 0
			v2 += list(block[1:])
		assert set(v[4 * ndat:-1]) == set([0])
		v2 += [v[-1]]
		M2.append(v2)

	for v in M[bound:]:
		assert max(max(v), max(-v)) > p^(3/2)

	M = Matrix(ZZ, M2)

	import time

	st = time.time()
	print(f"BKZ {M.nrows()}x{M.ncols()} start.")
	M = M.BKZ(block_size=40)
	en = time.time()
	print(f"BKZ took {en - st:.2f}s.")

	for v in M:
		if v[-1] < 0:
			v = -v
		if v[-1] == p:
			v = v[:3 * ndat]
			break
	else:
		io.close()
		return None

	correct = []

	for i in range(ndat):
		block = v[3 * i:3 * (i + 1)]
		try:
			assert set(block) == set([5 * p, -5 * p])
		except:
			io.close()
			print("fail")
			return None

		block = [int(b == -5 * p) for b in block]
		block = [2 - sum(block)] + block

		cor = sum(a * b for a, b in zip(dat[i][1], block))
		correct.append(cor)

	root = M0.solve_right(vector(K, correct))
	f = R(list(root))

	io.sendline(str(f(42)).encode())

	io.interactive()
	exit()

while True:
	dig()
	# multiprocess if you wish