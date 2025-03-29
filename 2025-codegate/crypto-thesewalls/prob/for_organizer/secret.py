from sage.all import *
from Crypto.Util.number import getPrime

flag = "codegate2025{If_these_weils_could_talk_(I_can_feel_your_reign_when_it_cries_supersingular_curves_inside_of_you)}"

primes = []
mods = []
Gx = []
Gy = []
aa = []
bb = []
oo = []


# 1. Generate singular curve for Fp2
p = 3562548874780288796769030192977
o = p + 1
assert is_prime(p)
assert o == 2 * 3 * 19 * 2745521 * 377214161 * 30174718114417

Fp = GF(p)
P = PolynomialRing(Fp, names='x')
x = P.gens()[0]
while True:
	a = Fp.random_element()
	poly = (x - 2 * a) * (x + a)**2
	# ((x + a) - 3 * a) * (x + a)^2

	if (-3 * a).sqrt() in Fp:
		continue

	assert poly[3] == 1
	assert poly[2] == 0
	a, b = ZZ(poly[1]), ZZ(poly[0])
	break

while True:
	p_tmp = getPrime(50)
	E_tmp = EllipticCurve(GF(p_tmp), [a, b])
	o_tmp = E_tmp.order()
	if gcd(o_tmp, o) == 1:
		break

G_tmp = E_tmp.gens()[0]
assert G_tmp.order() == o_tmp

E2 = EllipticCurve(Zmod(p * p_tmp), [a, b])

while True:
	x = randrange(p)
	y = Fp(x**3 + a * x + b).sqrt()
	if y not in Fp:
		continue
	y = ZZ(y)

	x2, y2 = crt([x, ZZ(G_tmp[0])], [p, p_tmp]), crt([y, ZZ(G_tmp[1])], [p, p_tmp])

	G2 = E2(x2, y2)

	try:
		for fac in [2, 3, 19, 2745521, 377214161, 30174718114417]:
			G2 * (o // fac)
	except ZeroDivisionError:
		continue

	break

primes.append(p)
mods.append(p)
Gx.append(x)
Gy.append(y)
aa.append(a)
bb.append(b)
oo.append(o)


# 2. Generate supersingular curve, but nonzero a, b, and power 2
p = 3692983360407686094702508373879
assert p % 3 == 2
o = p + 1
assert is_prime(p)
assert o == 2**3 * 3**2 * 5 * 31 * 3517 * 673063 * 139792886025540383

E_base = EllipticCurve(GF(p), [0, randrange(p)])
assert E_base.is_supersingular()

while True:
	E = E_base.isogeny(E_base.random_element() * 3517 * 673063 * 139792886025540383, algorithm='factored').codomain()
	assert E.is_supersingular()

	a, b = map(ZZ, E.a_invariants()[-2:])
	G = E.gens()[0]
	if G.order() != o:
		continue
	break

while True:
	to_mul = randrange(p)
	if gcd(to_mul, o) == 1:
		break
G *= to_mul
assert G.order() == o

x, y = map(ZZ, G.xy())

R = Zp(p, 2)

a += p * randrange(p)
b += p * randrange(p)
x += p * randrange(p)
y = ZZ(R(x**3 + a * x + b).sqrt())
o *= p

primes.append(p)
mods.append(p**2)
Gx.append(x)
Gy.append(y)
aa.append(a)
bb.append(b)
oo.append(o)


# 3. Generate supersingular curve, zero a, and power 3
p = 2717597692908121319788497985451
assert p % 3 == 2
o = p + 1
assert is_prime(p)
assert o == 2**2 * 3 * 11 * 53 * 388450213394528490535805887
while True:
	a, b = 0, randrange(p)
	E = EllipticCurve(GF(p), [a, b])
	assert E.is_supersingular()
	G = E.gens()[0]
	if G.order() != o:
		continue
	break

while True:
	to_mul = randrange(p)
	if gcd(to_mul, o) == 1:
		break
G *= to_mul
assert G.order() == o

x, y = map(ZZ, G.xy())

R = Zp(p, 3)

a += p * randrange(p**2)
b += p * randrange(p**2)
x += p * randrange(p**2)
y = ZZ(R(x**3 + a * x + b).sqrt())
o *= p**2

primes.append(p)
mods.append(p**3)
Gx.append(x)
Gy.append(y)
aa.append(a)
bb.append(b)
oo.append(o)


# 4. Generate supersingular curve, zero b, and power 2
p = 324094280281900209908870811008292068290746348301400744740589987
assert p % 4 == 3
o = p + 1
assert is_prime(p)
assert o == 2**2 * 3 * 349 * 55050007 * 1405747484361299393418580978953630281779614293727193

while True:
	a, b = randrange(p), 0
	E = EllipticCurve(GF(p), [a, b])
	assert E.is_supersingular()
	G = E.gens()[0]
	if G.order() != o:
		continue
	break

while True:
	to_mul = randrange(p)
	if gcd(to_mul, o) == 1:
		break
G *= to_mul
assert G.order() == o

x, y = map(ZZ, G.xy())

R = Zp(p, 4)

a += p * randrange(p)
b += p * randrange(p)
x += p * randrange(p)
y = ZZ(R(x**3 + a * x + b).sqrt())
o *= p

primes.append(p)
mods.append(p**2)
Gx.append(x)
Gy.append(y)
aa.append(a)
bb.append(b)
oo.append(o)


mod = prod(mods)
Gx = crt(Gx, mods)
Gy = crt(Gy, mods)
a = crt(aa, mods)
b = crt(bb, mods)
o = lcm(oo)

E = EllipticCurve(Zmod(mod), [a, b])
P = E(Gx, Gy)

o = int(o)
# :)

def get_random_coprime_mod(mod_):
	while True:
		val = randrange(mod_)
		if gcd(val, mod_) == 1:
			return val

factors = [[2, 3], [3, 2], [5, 1], [11, 1], [19, 1], [31, 1], [53, 1], [349, 1], [3517, 1], [673063, 1], 
	[2745521, 1], [55050007, 1], [377214161, 1], [30174718114417, 1], [139792886025540383, 1], 
	[388450213394528490535805887, 1], [1405747484361299393418580978953630281779614293727193, 1],
	[primes[1], 1], [primes[2], 2], [primes[3], 1]
]

assert o == prod([a**b for a, b in factors])

s = get_random_coprime_mod(o)

wrong = []

for fac, exp in factors:
	for e in range(1, min(exp + 1, 3)):
		torsion = fac**e
		while True:
			w = (s + o // torsion * get_random_coprime_mod(torsion)) % o
			if gcd(o, w) == 1:
				break
		wrong.append(w)

for i in range(4):
	wrong.append(get_random_coprime_mod(o))

assert mod.bit_length() == 1024
