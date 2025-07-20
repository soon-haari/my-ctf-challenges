from pwn import *
context.log_level = "critical"

def recv():
	io = remote("localhost", 9999r)
	
	dat = bytes.fromhex(io.recvline().decode())
	io.close()

	return dat

from tqdm import trange

vs = []

for i in trange(9):
	A, b = loads(recv())

	F = A.base_ring()

	v1, v2 = A.T.right_kernel_matrix()
	v = (b * v2) * v1 - (b * v1) * v2

	for j in range(6):
		vv = [val[j] for val in v]
		vs.append(vv)

flag = Matrix(vs).right_kernel_matrix()[0]
flag *= b"A"[0]
flag = bytes([int(c) for c in flag]).decode()
print(flag)
