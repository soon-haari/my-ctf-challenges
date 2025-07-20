o = 37^49
assert o.bit_length() == 256

from pwn import *
context.log_level = "critical"

def recv():
	io = remote("localhost", 9999r)

	io.sendline(hex(o).encode())

	io.recvuntil(b": ")
	dat = bytes.fromhex(io.recvline().decode())
	io.close()

	return dat

from tqdm import trange

cand = [set(range(32, 128)) for _ in range(44)]

while True:
	A, b, pad = loads(recv())
	assert len(b) == 52

	F = A.base_ring()

	v1, v2 = A.T.right_kernel_matrix()
	v = (b * v2) * v1 - (b * v1) * v2
	# v * flag = 0

	vs = []

	for j in range(45):
		vv = [val[j] for val in v]
		vs.append(vv)

	vs = Matrix(vs)

	idxs = list(range(7)) + [-1]
	flag_format = b"Alpaca{}"
	known = [pad[j] ^^ flag_format[j] for j in idxs]
	pad = pad[7:-1]

	target = -sum(vs.column(j) * known[j] for j in idxs)
	M = vs[:, 7:-1]
	if M.right_kernel_matrix().nrows() > 0:
		continue
	res = M.solve_right(target)

	for j in range(44):
		newcand = set()
		for c in cand[j]:
			if (c ^^ pad[j]) % 37 == int(res[j]):
				newcand.add(c)
		cand[j] = newcand

	pos = [len(cnd) for cnd in cand]
	print(pos)

	if all(cnt == 1 for cnt in pos):
		flag = [cnd.pop() for cnd in cand]
		flag = b"Alpaca{" + bytes(flag) + b"}"

		print(flag.decode())

		break