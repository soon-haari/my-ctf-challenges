from pwn import *
context.log_level = "critical"

def recv():
	io = remote("localhost", 9999r)
	
	dat = bytes.fromhex(io.recvline().decode())
	io.close()

	return dat

from tqdm import trange

vs = []

for i in trange(2):
	A, b = loads(recv())

	F = A.base_ring()

	v1, v2 = A.T.right_kernel_matrix()
	v = (b * v2) * v1 - (b * v1) * v2
	# v * flag = 0

	for j in range(6):
		vv = [val[j] for val in v]
		vs.append(vv)


weight = 2^200

M = block_matrix([[1, weight * Matrix(ZZ, vs).T],
				  [0, weight * 6821063305943]])

M = M.BKZ()

flag = bytes((-M[0])[:52]).decode()
print(flag)

# probabablistic
# Can use flag format, or the fact every bytes is centered at 70 or something, instead of 0
# or more queries than 2, but minimum possible is 2.]
