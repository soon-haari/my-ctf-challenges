from pwn import *
import random
from tqdm import trange, tqdm
from Crypto.Util.number import getPrime

bitlen = 1024

p, q = getPrime(bitlen), getPrime(bitlen)
N, e = p * q, 0x10001
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = random.randrange(N)
c = pow(m, e, N)


# 1
_ = (N, p)
_ = (_[0] - (_[0] % _[1]), _[1], _[1], _[1] * 2, 0, 1)
for i in range(bitlen * 2):
	_ = (_[0] - ((_[0] % _[3]) > 0) * _[2], _[1], _[2], _[3], _[4] + ((_[0] % _[3]) > 0) * _[5], _[5])
	_ = (_[0], _[1], _[2] * 2, _[3] * 2, _[4], _[5] * 2)
_ = (_[4])
_ = ((p - 1) * (_ - 1))

# assert _ == phi


# 2
#    x, y, z, w, k, t, e,             h, j, ans
#    0, 1, 2, 3, 4, 5, 6,             7, 8, 9
_ = (1, 0, 0, 1, 0, 0, 8*8*8*8*8*2+1, _, _, 0)
for i in range(30):
	_ = ((_[7] - (_[7] % (_[6] + 1 * (_[6] < 1))), _[6], _[6], _[6] * 2, 0, 1) + _)
	for i in range(bitlen * 2):
		_ = ((_[0] - ((_[0] % (_[3] + 1 * (_[3] < 1))) > 0) * _[2], _[1], _[2], _[3], _[4] + ((_[0] % (_[3] + 1 * (_[3] < 1))) > 0) * _[5], _[5]) + _[6:])
		_ = ((_[0], _[1], _[2] * 2, _[3] * 2, _[4], _[5] * 2) + _[6:])
	_ = (_[6:] + _[4:5])
	_ = (_[0], _[1], _[2], _[3], _[5 + 5], _[5], _[6], _[7], _[8], _[9])
	_ = (_[0], _[1], _[2], _[3], _[4], _[7], _[6], _[7], _[8], _[9])
	_ = (_[0], _[1], _[2], _[3], _[4], _[5], _[6], _[6], _[8], _[9])
	_ = (_[0], _[1], _[2], _[3], _[4], _[5], _[5] % (_[6] + 1 * (_[6] < 1)), _[7], _[8], _[9])
	_ = (_[0], _[1], _[2], _[3], _[4], _[0], _[6], _[7], _[8], _[9])
	_ = (_[1], _[1], _[2], _[3], _[4], _[5], _[6], _[7], _[8], _[9])
	_ = (_[0], _[5] - _[4] * _[1], _[2], _[3], _[4], _[5], _[6], _[7], _[8], _[9])
	_ = (_[0], _[1], _[2], _[3], _[4], _[2], _[6], _[7], _[8], _[9])
	_ = (_[0], _[1], _[3], _[3], _[4], _[5], _[6], _[7], _[8], _[9])
	_ = (_[0], _[1], _[2], _[5] - _[4] * _[3], _[4], _[5], _[6], _[7], _[8], _[9])
	_ = (_[0], _[1], _[2], _[3], _[4], _[5], _[6], _[7], _[8], (_[2] % _[8]) * (((_[6] < 1) & (_[7] > 0))) + _[9] * (1 - ((_[6] < 1) & (_[7] > 0))))
_ = (_[9])

# assert _ == d


# 3
#    m, q, d, b
#    0, 1, 2, 3
_ = (1, c, _, 1)
for i in range(bitlen * 2 + 100):
	_ = (((((_[2] & _[3]) > 0) * (_[1] - 1) + 1) * _[0]) % N, _[1], _[2], _[3])
	_ = (_[0], (_[1] * _[1]) % N, _[2], _[3] * 2)
_ = (_[0])

assert _ == m

sol = ""

# 1
sol += """
_ = (N, p)
_ = (_[0] - (_[0] % _[1]), _[1], _[1], _[1] * 2, 0, 1)
"""
sol += """
_ = (_[0] - ((_[0] % _[3]) > 0) * _[2], _[1], _[2], _[3], _[4] + ((_[0] % _[3]) > 0) * _[5], _[5])
_ = (_[0], _[1], _[2] * 2, _[3] * 2, _[4], _[5] * 2)
""" * bitlen * 2
sol += """
_ = (_[4])
_ = ((p - 1) * (_ - 1))
"""

# 2
sol += """
_ = (1, 0, 0, 1, 0, 0, 8*8*8*8*8*2+1, _, _, 0)
"""
phase2 = """
_ = ((_[7] - (_[7] % (_[6] + 1 * (_[6] < 1))), _[6], _[6], _[6] * 2, 0, 1) + _)
"""
phase2 += """
_ = ((_[0] - ((_[0] % (_[3] + 1 * (_[3] < 1))) > 0) * _[2], _[1], _[2], _[3], _[4] + ((_[0] % (_[3] + 1 * (_[3] < 1))) > 0) * _[5], _[5]) + _[6:])
_ = ((_[0], _[1], _[2] * 2, _[3] * 2, _[4], _[5] * 2) + _[6:])
""" * bitlen * 2
phase2 += """
_ = (_[6:] + _[4:5])
_ = (_[0], _[1], _[2], _[3], _[5 + 5], _[5], _[6], _[7], _[8], _[9])
_ = (_[0], _[1], _[2], _[3], _[4], _[7], _[6], _[7], _[8], _[9])
_ = (_[0], _[1], _[2], _[3], _[4], _[5], _[6], _[6], _[8], _[9])
_ = (_[0], _[1], _[2], _[3], _[4], _[5], _[5] % (_[6] + 1 * (_[6] < 1)), _[7], _[8], _[9])
_ = (_[0], _[1], _[2], _[3], _[4], _[0], _[6], _[7], _[8], _[9])
_ = (_[1], _[1], _[2], _[3], _[4], _[5], _[6], _[7], _[8], _[9])
_ = (_[0], _[5] - _[4] * _[1], _[2], _[3], _[4], _[5], _[6], _[7], _[8], _[9])
_ = (_[0], _[1], _[2], _[3], _[4], _[2], _[6], _[7], _[8], _[9])
_ = (_[0], _[1], _[3], _[3], _[4], _[5], _[6], _[7], _[8], _[9])
_ = (_[0], _[1], _[2], _[5] - _[4] * _[3], _[4], _[5], _[6], _[7], _[8], _[9])
_ = (_[0], _[1], _[2], _[3], _[4], _[5], _[6], _[7], _[8], (_[2] % _[8]) * (((_[6] < 1) & (_[7] > 0))) + _[9] * (1 - ((_[6] < 1) & (_[7] > 0))))
"""
sol += phase2 * 30
sol += """
_ = (_[9])
"""

# 3
sol += """
_ = (1, c, _, 1)
"""
sol += """
_ = (((((_[2] & _[3]) > 0) * (_[1] - 1) + 1) * _[0]) % N, _[1], _[2], _[3])
_ = (_[0], (_[1] * _[1]) % N, _[2], _[3] * 2)
""" * (bitlen * 2 + 100)
sol += """
_ = (_[0])
_ = (X(_))
"""

sol_bytes = []

for line in sol.split("\n"):
	if line == "":
		continue
	assert line[:4] == "_ = "
	line = line[4:]

	for c in line:
		if c == " ":
			continue
		sol_bytes.append(c.encode())

io = process(["python3", "chall.py"])

batch = 30000
for i in trange(0, len(sol_bytes), batch):
	send_block = sol_bytes[i:i + batch]
	l = len(send_block)
	io.sendlines(send_block)
	
	for _ in range(l):
		io.recvuntil(b">>> ")

io.sendline()

io.interactive()