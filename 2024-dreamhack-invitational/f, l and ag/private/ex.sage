from Crypto.Util.number import *
from tqdm import trange

exec(open("output.txt", "r").read())
N, e, f_enc, l_enc, ag_enc, flag_enc = map(ZZ, (N, e, f_enc, l_enc, ag_enc, flag_enc))

# Step 1.

Q.<y> = PolynomialRing(Zmod(N))
P.<x> = PolynomialRing(Q)

f1 = P((x * 256^51 + y * 256^34 + 1)^e - (flag_enc / ag_enc) % N)
f2 = P(x^e - (f_enc / ag_enc) % N)
f3 = Q(y^e - (l_enc / ag_enc) % N)

for _ in trange(513): # work same as while f2.degree() > 0, but with progress bar
	f1_coef = f1[f1.degree()]
	f2_coef = f2[f2.degree()]

	f1 *= f2_coef
	f2 *= f1_coef

	f1 = P([coef % f3 for coef in list(f1)])
	f2 = P([coef % f3 for coef in list(f2)])

	f1 -= f2 * x^(f1.degree() - f2.degree())

	if f1.degree() < f2.degree():
		f1, f2 = f2, f1

g = f2[0]


# Step 2.

g1 = g
g2 = f3

while g2.degree() > 0:
	g1 = g1 % g2
	g1, g2 = g2, g1

assert g1.degree() == 1
b = ZZ(-g1.monic()[0]) # recovered b

P.<x> = PolynomialRing(Zmod(N))

f1 = P((x * 256^51 + b * 256^34 + 1)^e - (flag_enc / ag_enc) % N)
f2 = P(x^e - (f_enc / ag_enc) % N)

while f2.degree() > 0:
	f1 = f1 % f2
	f1, f2 = f2, f1

assert f1.degree() == 1
a = ZZ(-f1.monic()[0]) # recovered a


# Step 3.

M = Matrix([[1, a], [0, N]])
ag_base = ZZ(M.LLL()[0][0])
ag_base = abs(ag_base)

ag = ag_base

while True:
	try:
		long_to_bytes(ag).decode()
		break
	except:
		ag += ag_base

f = a * ag % N
l = b * ag % N

flag = int(f).to_bytes(17, "big") + int(l).to_bytes(17, "big") + int(ag).to_bytes(34, "big")

print(flag.decode())