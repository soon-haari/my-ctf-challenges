from pwn import *
import random
from tqdm import trange, tqdm

io = process(["python3", "chall.py"])

lines = """
(
q:=
N//
p,
phi
:=(
p-1
)*(
q-1
),
d:=
pow
(2
**
16+
1,
-1,
phi
),
m:=
pow
(c,
d,N
))
X(
m)
"""
real_lines = []

for line in lines.split("\n"):
	if len(line) == 0 or line[0] == "#":
		continue
	real_lines.append(line.encode())

batch = 10000
for i in trange(0, len(real_lines), batch):
	send_block = real_lines[i:i + batch]
	l = len(send_block)
	io.sendlines(send_block)
	
	for _ in range(l):
		io.recvuntil(b">>> ")

io.sendline()
io.interactive()