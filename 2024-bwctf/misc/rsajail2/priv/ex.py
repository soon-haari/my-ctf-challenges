from pwn import *
import random, time
from tqdm import trange, tqdm

io = process(["python3", "chall.py"])

lines = """
# q = N // p
((
q
:=
N
//
p)
*0
)
# h = (p - 1) * (q - 1)
((
h
:=
(p
-1
)*
(q
-1
))
*0
)
# e = 0x10001
((
e
:=
2
**
16
+1
)*
0)
"""

def inv(e, h):
	j = h
	x, y, z, w = 1, 0, 0, 1

	while e:
		k, h, e = h // e, e, h % e
		x, y = y, x - k * y
		z, w = w, z - k * w
	return z % j

def inv2(e, h):
	j = h
	x, y, z, w = 1, 0, 0, 1

	for _ in range(20):
		if e:
			k, h, e = h // e, e, h % e
			x, y = y, x - k * y
			z, w = w, z - k * w
	return z % j

def inv3(e, h):
	((j := h)*0)
	((x := 1)*0)
	((y := 0)*0)
	((z := 0)*0)
	((w := 1)*0)

	for _ in range(20):
		(((e < 1) or (
			k := h // e,
			t := h,
			h := e,
			e := t % e,
			t := x,
			x := y,
			y := t - k * y,
			t := z,
			z := w,
			w := t - k * w
			))*0)
	((d := z % j)*0)
	return d

def inv4(e, h):
	((
	j
	:=
	h)
	*0
	)
	((
	x
	:=
	1)
	*0
	)
	((
	y
	:=
	0)
	*0
	)
	((
	z
	:=
	0)
	*0
	)
	((
	w
	:=
	1)
	*0
	)
	for _ in range(20):
		((
		(e
		<1
		)
		or
		(
		k
		:=
		h
		//
		e,
		t
		:=
		h,
		h
		:=
		e,
		e
		:=
		t%
		e,
		t
		:=
		x,
		x
		:=
		y,
		y
		:=
		t-
		k*
		y,
		t
		:=
		z,
		z
		:=
		w,
		w
		:=
		t-
		k*
		w)
		)*
		0)
	((
	d
	:=
	z%
	j)
	*0
	)
	return d

phi = random.getrandbits(200)
if phi % 0x10001 == 0:
	phi += 1
assert inv(65537, phi) == pow(65537, -1, phi)
assert inv2(65537, phi) == pow(65537, -1, phi)
assert inv3(65537, phi) == pow(65537, -1, phi)
assert inv4(65537, phi) == pow(65537, -1, phi)

lines += """
((
j
:=
h)
*0
)
((
x
:=
1)
*0
)
((
y
:=
0)
*0
)
((
z
:=
0)
*0
)
((
w
:=
1)
*0
)
"""

lines += """
((
(e
<1
)
or
(
k
:=
h
//
e,
t
:=
h,
h
:=
e,
e
:=
t%
e,
t
:=
x,
x
:=
y,
y
:=
t-
k*
y,
t
:=
z,
z
:=
w,
w
:=
t-
k*
w)
)*
0)
""" * 20

lines += """
((
d
:=
z%
j)
*0
)
"""

def mypow(c, d, N):
	m = 1
	q = c
	while d:
		if d & 1:
			m *= q
		m %= N
		q **= 2
		q %= N
		d >>= 1
	return m

def mypow2(c, d, N):
	((m := 1)*0)
	((q := c)*0)
	for i in range(3000):
		(((d < 1) or (
		m := q**(d & 1) * m,
		m := m % N,
		q := q**2 % N,
		d := d >> 1
		))*0)
	return m

def mypow3(c, d, N):
	((
	m
	:=
	1)
	*0
	)
	((
	q
	:=
	c)
	*0
	)
	for i in range(3000):
		((
		(d
		<1
		)
		or
		(
		m
		:=
		q
		**
		(d
		&1
		)*
		m,
		m
		:=
		m%
		N,
		q
		:=
		q
		**
		2%
		N,
		d
		:=
		d
		>>
		1)
		)*
		0)
	return m

c, d, N = [12345, 67891, random.getrandbits(200)]
assert mypow(c, d, N) == pow(c, d, N)
assert mypow2(c, d, N) == pow(c, d, N)
assert mypow3(c, d, N) == pow(c, d, N)

lines += """
((
m
:=
1)
*0
)
((
q
:=
c)
*0
)
"""

lines += """
((
(d
<1
)
or
(
m
:=
q
**
(d
&1
)*
m,
m
:=
m%
N,
q
:=
q
**
2%
N,
d
:=
d
>>
1)
)*
0)
""" * 3000

lines += """
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