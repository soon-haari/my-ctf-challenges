## 출제자
김민순(soon_haari)

## 문제 세팅 방법
`./prob/for_user/` 내의 파일 공개

## 출제 지문
`If these walls could talk...`

## 문제 풀이(writeup)

**chall.py**
```python
from secret import P, s, o, wrong, flag
from Crypto.Cipher import AES
import random, os, math

assert P * o == P.curve()(0)
assert all(math.gcd(o, w) == 1 for w in wrong + [s])
assert all(P * s != P * w for w in wrong)

key = os.urandom(32)
enc_flag = AES.new(key, AES.MODE_CTR, nonce=bytes(12)).encrypt(flag.encode())

print(f"{enc_flag.hex() = }\n{o = }")

key = int.from_bytes(key)
for i in range(32 * 8):
	P *= [random.choice(wrong), s][(key >> i) & 1]
	print(P.xy())
```

`output.txt`를 확인하면 `P`는 타원곡선의 한 점임을 유추할 수 있습니다. 해당 점의 order `o`가 주어져 있고(물론 해당 조건만으로는 order의 배수입니다, 배수라고 가정하여도 풀이에는 변함이 없습니다), `s, wrong` 의 모든 값은 `o`와 서로소이며, `wrong`의 모든 원소 `w`에 대하여 `P * s != P * w`임이 보장되어 있습니다.

`P`로 시작하여 256회 비트값에 따라서 `s` 혹은 `wrong`의 임의의 값을 곱하여, 256회의 결과를 알고 있습니다. `s, wrong` 의 모든 값은 `o`와 서로소이기 때문에, 점의 order은 모두 동일함에 유의합니다. 따라서 DLP가 해결된다면 가능한 키의 가짓수가 유일함이 보장됩니다. 맨 첫 비트는 이전 상태를 모르기 때문에 0, 1을 모두 시도해보면 됩니다.

---

### 1. 곡선 분석
점의 x, y좌표를 여럿 알고 있기 때문에, $a * (x) + b + (x^3 - y^2) = 0$의 등식을 여럿 얻을 수 있고, 3개를 골라 determinant를 계산하면 curve modulus의 배수가 되기 때문에 그 값들의 GCD를 계산하여 curve modulus, 그리고 `a, b` 값을 연산할 수 있습니다.

```python
...

dat = open("output.txt", "r").readlines()[2:]
assert len(dat) == 256

from ast import literal_eval

dat = [literal_eval(d) for d in dat]

n = 0

for i in range(10):
	M = []
	for j in range(3):
		x, y = dat[i + j]
		M.append([x, 1, x^3 - y^2])
	det = Matrix(M).determinant()
	n = gcd(n, det)

assert n.bit_length() == 1024

M = []
r = []
for i in range(2):
	x, y = dat[i]
	M.append([x, 1])
	r.append(y^2 - x^3)
a, b = map(ZZ, Matrix(Zmod(n), M).solve_right(vector(Zmod(n), r)))

for x, y in dat:
	assert (y^2 - (x^3 + a * x + b)) % n == 0
```

유의할 점은 구한 curve modulus $n$이 합성수이기 때문에 소인수분해하기 전까지는 곡선의 성질을 분석하기 어렵습니다.

주어진 `o`를 사용하여 소인수분해 시도를 할 수 있지만 이전에 다음과 같은 성질을 눈치챌 수 있습니다.
```python
E = EllipticCurve(Zmod(n), [a, b])
P = E(dat[0])

# P * 1
# Error
# discriminant not coprime to modulus, thus include singular curve
singular_mod = gcd(n, -16 * (4 * a^3 + 27 * b^2))
# 3562548874780288796769030192977
```
만든 타원곡선을 가지고 간단한 곱셈을 시도하더라도 `ZeroDivisionError`가 일어나는 것을 확인할 수 있고, 그 원인은 discriminant가 modulus와 서로소가 아니고, 즉 최소 하나 이상의 소인수 modulus에 대해서는 discriminant가 0이 되어 singular curve가 되는 것입니다. SageMath에서는 Singular Curve를 지원하지 않기 때문에 바로 저런 에러가 일어납니다.

discriminant와 modulus의 GCD를 구하면 소수 하나를 확인할 수 있고, n은 단 1회 해당 소수로 나누어집니다. 이 소수를 $p_1$이라고 하겠습니다.

---

### 2. `o`를 사용한 curve modulus 소인수분해

합성수 modulus를 가진 타원곡선의 경우, 한 소인수를 법으로는 Infinite point가 연산되지만, 다른 소인수를 법으로는 아닐 경우, `ZeroDivisionError`가 일어나게 됩니다.

이를 사용하여, `o`에서 작은 약수들을 제거하여 주어진 점 중 하나에 곱해보면 `ZeroDivisionError`를 통한 인수 추출이 또한 가능할 것으로 추측됩니다.

```python

from sage.rings.factorint import factor_trial_division

# o_facs = list(factor_trial_division(o, 2^30))
# print(o_facs)
o_facs = [(2, 3), (3, 2), (5, 1), (11, 1), (19, 1), (31, 1), (53, 1), (349, 1), (3517, 1), (673063, 1), (2745521, 1), (55050007, 1), (377214161, 1), (20360574113233812481685439263671789261817936006577330964336962473923517498497934703871787394487722776320255054270961305081467007402360235551783832230924586862762774225807963988136283635452040243476642685484746146943283864002000148190191387194458228613505267579173, 1)]
```

`o`에서 작은 소인수들을 추출해내고, 남은 큰 값을 주어진 점 중 하나에 곱하더라도 `ZeroDivisionError`가 일어나지 않았고, 이는 curve modulus의 어떤 소인수를 법으로 한 곡선에서도 Infinite Point가 아니라는 의미입니다. 작은 소인수들을 `itertools.product`를 사용해 모두 확인하면 커브들을 분류해낼 수 있습니다.

주의할 점은, $p^k$를 법으로 한 커브는 $o_p * p^{k - 1}$의 order을 가집니다. 이때 $o_p$는 $p$를 법으로 한 커브에서의 order입니다. 위와 같은 상황에서는 $p^{k - 1}$은 전부 소인수분해가 마무리되지 않은 큰 값에 들어가 있을 것으로 추측 가능합니다.

따라서 `ZeroDivisionError`가 일어나는 상황에서도 추출되는 인수는 $p, p^2, \cdots p^{k - 1}$이 아닌 $p^{k}$가 추출됩니다.

```python
iter_range = [range(v[1] + 1) for v in o_facs[:-1]]

E = EllipticCurve(Zmod(n), [a, b])
P = E(dat[0])

import itertools
from tqdm import tqdm, trange
import time


# for p^k | k
# p^(k - 1) | o
# the following can factor to every p^k


gs = set()
for it in tqdm(itertools.product(*iter_range)):
	mul = o
	for i in range(len(it)):
		mul //= o_facs[i][0]^it[i]
	assert o % mul == 0

	g = gcd(ZZ((P * (mul - 1))[0] - P[0]), n)

	if g == 1:
		continue

	gs.add(g)

for g in gs:
	for exp in range(100, 0, -1):
		if g^(1 / exp) in ZZ:
			p = ZZ(g^(1 / exp))
			if is_prime(p):
				break
	else:
		continue
	print(p, exp)
```

이의 결과는 다음과 같습니다.
```
2717597692908121319788497985451 3
3692983360407686094702508373879 2
324094280281900209908870811008292068290746348301400744740589987 2
```

Curve modulus 소인수분해가 마무리된 것을 확인할 수 있습니다.
```python
p2 = 3692983360407686094702508373879
p3 = 2717597692908121319788497985451
p4 = 324094280281900209908870811008292068290746348301400744740589987

assert original_mod == p1^1 * p2^2 * p3^3 * p4^2
```

주어진 점들은 모두 4개의 타원곡선에 대하여 generator임을 확인할 수 있습니다, 다른 말로, 점의 order이 curve order과 동일합니다. 따라서 이론상으로 완벽한 구별이 가능하려면 모든 커브의 order의 모든 소인수에 대하여 확인이 이루어져야 합니다.

DLP를 진행할 때, 모든 확인은 $s$과 곱셈이 동일한지에 대한 확인이나, $s$값을 모르기 때문에 올바른 인덱스를 하나 선택하여 기준으로 사용해야 합니다. `os.urandom`으로 생성한 키이므로, 절반의 확률로 사용 가능한 인덱스로 생각 가능합니다. 풀이에서는 2를 사용했습니다.
```python
correct_idx = 2
# index to compare
```

---

### 3. Prime power modulus 타원곡선의 subgroup

$p_2, p_3, p_4$에 대하여, 해당 소수의 거듭제곱이 modulus로 사용되는 것을 확인할 수 있습니다. 위에서 말했듯이, 이 경우는 $o_p * p^{k - 1}$의 order을 가집니다. 이러한 prime power modulus의 경우는 $p^{k - 1}$을 법으로 한 subgroup으로의 mapping이 가능하여, 간편히 $p^{k - 1}$를 법으로 한 DLP가 해결 가능합니다.

다음은 예시로 $p_2^2$를 modulus로 한 곡선에서 $p_2$를 법으로 한 DLP를 이용해 틀린 후보들을 걸러내는 부분입니다. $p_3^3, p_4^2$에 대한 풀이도 동일합니다.

```python
def dlog_power(P, Q, p, o, E):
	EQp = E.change_ring(Qp(p))
	Pmul = EQp(P) * o
	Qmul = EQp(Q) * o

	dlog = ZZ((Qmul[0] / Qmul[1]) / (Pmul[0] / Pmul[1]))

	# assert Pmul * dlog == Qmul
	return dlog

E = EllipticCurve(Zmod(p2^2), [a, b])
dat_p2 = [E(P) for P in dat]

dlog_correct = dlog_power(dat_p2[correct_idx + 1], dat_p2[correct_idx], p2, o, E)
res_p2_power = [dlog_power(dat_p2[i + 1], dat_p2[i], p2, o, E) == dlog_correct for i in trange(255)]

assert 255 > res_p2_power.count(True) > 130
```

---

### 4. Singular Curve의 DLP

앞서 $p_1$을 법으로 한 곡선은 Singular Curve임을 확인하였습니다. Singular Curve는 $\mathbb{F}_p$ 혹은 $\mathbb{F}_{p^2}$와 동형사상이므로, 매핑을 진행한 후, 해당 체에서 DLP를 수행하면 더 수월하게 DLP문제를 해결할 수 있습니다. 다음의 코드는 $\mathbb{F}_{p^2}$로 매핑을 진행시켜 DLP문제를 해결하였습니다. $\mathbb{F}_{p^2}$의 경우, Singular Curve의 order은 $p + 1$이 되고, 이 값은 `2 * 3 * 19 * 2745521 * 377214161 * 30174718114417`로 소인수분해되어, 가장 큰 값이 45비트로 빠르게 DLP가 가능합니다. SageMath 내장 `Fp2.log` 함수로 4.04초가 걸렸습니다.

```python
# E = EllipticCurve(GF(p1), [a, b])
# ArithmeticError: y^2 = x^3 + 3250676836264928831089904907357*x + 3033513073637482920220005561471 defines a singular curve
Fp = GF(p1)
P.<x> = PolynomialRing(Fp)
poly = x^3 + a * x + b

# print(factor(poly))
# exit()
# (x + 588502641389499913346519754422) * (x + 3268297554085538840095770315766)^2
# ((x + 3268297554085538840095770315766) + 882753962084249870019779631633) * (x + 3268297554085538840095770315766)^2
alpha = 882753962084249870019779631633

# print(Fp(882753962084249870019779631633).sqrt())
# sqrt882753962084249870019779631633
# need to extend to Fp2
Fp2 = GF(p1^2)
alpha = Fp2(alpha)
asqrt = alpha.sqrt()


def singular_map(P):
	x, y = map(Fp2, P)
	x = x + 3268297554085538840095770315766
	res = (y + asqrt * x) / (y - asqrt * x)
	assert res.multiplicative_order() == p1 + 1
	return res

dat_p1 = [singular_map(P) for P in dat]

st = time.time()
dlog = dat_p1[correct_idx + 1].log(dat_p1[correct_idx])
en = time.time()
print(f"{dlog = }, took {en - st:.2f}s.")
# dlog = 1688818121111580066310934554129, took 4.04s.

dlog = 1688818121111580066310934554129
assert gcd(dlog, p1 + 1) == 1

res_p1 = [dat_p1[i]^dlog == dat_p1[i + 1] for i in range(255)]
assert 255 > res_p1.count(True) > 130
```

---

### 5. Supersingular Curve의 MOV attack을 이용한 DLP

$p_2$의 경우는 다음과 같은 곡선을 형성합니다.
```
Elliptic Curve defined by y^2 = x^3 + 986063441805532048667620077607*x + 387728752840944215658366504283 over Finite Field of size 3692983360407686094702508373879
```
특징으로는 Supersingular하다는 성질, 즉 order이 $p_2 + 1$입니다. 이는 `2**3 * 3**2 * 5 * 31 * 3517 * 673063 * 139792886025540383`으로 소인수분해되고, 가장 큰 소인수는 57비트의 사이즈를 가집니다. Meet in the middle attack이 불가능한 범위는 아니지만 꽤나 오랜 시간이 걸릴 것으로 예상됩니다. MOV attack을 사용하면 이 또한 $\mathbb{F}_{p^2}$로 매핑시켜 더 빠른 DLP가 가능합니다.

MOV attack의 과정은 다음과 같습니다.
1. 곡선을 $\mathbb{F}_{p^2}$로 확장한 후, quadratic twist 부분의 generator 점을 하나 생성합니다. 이를 $R$이라고 하겠습니다.
2. $P * s = Q$에 대하여, $\textnormal{weil\_pairing}(P, R)^s = \textnormal{weil\_pairing}(Q, R)$를 만족하기 때문에 $\mathbb{F}_{p^2}$에서 DLP가 가능합니다. 이는 CADO-NFS로 해결도 가능하고, SageMath 내당 `log` 함수로도 가능합니다.

제 로컬 환경에서는 DLP를 계산하는 데 563.14초가 걸렸습니다.

```python
E = EllipticCurve(GF(p2), [a, b])
assert E.is_supersingular()
# print(E)
# Elliptic Curve defined by y^2 = x^3 + 986063441805532048667620077607*x + 387728752840944215658366504283 over Finite Field of size 3692983360407686094702508373879
o = E.order()
assert o == p2 + 1
Fp2 = GF(p2^2)
E = EllipticCurve(Fp2, [a, b])
dat_p2 = [E(P) for P in dat]

while True:
	x = Fp2(randrange(p2))
	G = E.lift_x(x)
	if G[1] in GF(p2):
		continue
	if G.order() != p2 + 1:
		continue
	break
w1 = dat_p2[correct_idx].weil_pairing(G, p2 + 1)
w2 = dat_p2[correct_idx + 1].weil_pairing(G, p2 + 1)
st = time.time()
dlog = w2.log(w1)
en = time.time()
print(f"{dlog = }, took {en - st:.2f}s.")
# dlog = 860437940168965817900625942259, took 403.81s.

dlog = 860437940168965817900625942259
res_p2 = [dat_p2[i] * dlog == dat_p2[i + 1] for i in range(255)]
assert 255 > res_p2.count(True) > 130
```

---

### 6. $a, b$가 0인 Supersingular Curve

$p_3, p_4$로 생성된 곡선을 각각 확인해보면 다음과 같습니다.
```
Elliptic Curve defined by y^2 = x^3 + 1508611169675476373544814188711 over Finite Field of size 2717597692908121319788497985451
Elliptic Curve defined by y^2 = x^3 + 201486157873867982115091945503042086637219431930076933476606014*x over Finite Field of size 324094280281900209908870811008292068290746348301400744740589987
```
각각 인자 $a, b$가 0임을 알 수 있고, 두 곡선 모두 Supersingular합니다.

$p_3 + 1$을 소인수분해한 값은 `2**2 * 3 * 11 * 53 * 388450213394528490535805887`이고, $p_4 + 1$을 소인수분해한 값은 `2^2 * 3 * 349 * 55050007 * 1405747484361299393418580978953630281779614293727193`로, 가장 큰 소인수는 각각 89, 170비트로 MOV attack으로도 DLP 난이도가 높은 편에 속합니다.

그러나 인자 $a, b$가 0인 Supersingular Curve에 대해서는 $\mathbb{F}_p$ 위에서의 곡선의 점을 그의 quadratic twist 위로 매핑시키는 distortion map이 존재합니다.

- $a = 0$인 경우 $z^3 = 1, z \in \mathbb{F}_{p^2}, z \not \in \mathbb{F}_{p}$인 $z$에 대하여 $(x, y) \rarr (xz, y)$
- $b = 0$인 경우, $z^2 = -1, z \in \mathbb{F}_{p^2}, z \not \in \mathbb{F}_{p}$인 $z$에 대하여 $(x, y) \rarr (-x, yz)$

해당 mapping 이후에도 그대로 점 덧셈 연산이 성립함은 쉽게 증명 가능합니다.

$z^3 = 1, z \in \mathbb{F}_{p^2}, z \not \in \mathbb{F}_{p}$인 $z$의 존재 여부는 $p \not \equiv 1 \pmod 3$와 필요충분조건입니다. 마찬가지로 $z^2 = -1, z \in \mathbb{F}_{p^2}, z \not \in \mathbb{F}_{p}$인 $z$의 존재 여부는 $p \not \equiv 1 \pmod 4$와 필요충분조건입니다. $p_3, p_4$는 각각 해당 조건을 만족시키는 것을 확인할 수 있습니다. 이 조건이 성립하지 않게 된다면, $a, b$가 0이더라도 Supersingular curve가 되지 않게 됩니다.

$P_0 * s = Q_0$을 알고 있는 상태에서 $P_1 * s = Q_1$의 여부 확인을 위해 위 distortion map과 weil pairing을 다시 사용할 수 있습니다.

$P_1 * s = Q_1$이라면 $\textnormal{distortion\_map}(P_1) * s = \textnormal{distortion\_map}(Q_1)$를 만족하게 되고, 다음 식을 만족합니다.

$$\textnormal{weil\_pairing}(P_0, \textnormal{distortion\_map}(Q_1)) \\ = \textnormal{weil\_pairing}(P_0, \textnormal{distortion\_map}(P_1) * s) \\ = \textnormal{weil\_pairing}(P_0, \textnormal{distortion\_map}(P_1))^s \\ = \textnormal{weil\_pairing}(P_0 * s, \textnormal{distortion\_map}(P_1)) \\ =\textnormal{weil\_pairing}(P_1, \textnormal{distortion\_map}(Q_0))$$

따라서 $\textnormal{weil\_pairing}(P_0, \textnormal{distortion\_map}(Q_1)) = \textnormal{weil\_pairing}(P_1, \textnormal{distortion\_map}(Q_0))$을 만족하는지의 여부로 Decisional Diffie-Hellman 문제를 해결할 수 있습니다.

```python
E = EllipticCurve(GF(p3), [a, b])
assert E.is_supersingular()
# print(E)
# Elliptic Curve defined by y^2 = x^3 + 1508611169675476373544814188711 over Finite Field of size 2717597692908121319788497985451
# a = 0
o = E.order()
assert o == p3 + 1
Fp2 = GF(p3^2)
z = Fp2(1).nth_root(3)
assert z != 1

E = EllipticCurve(Fp2, [a, b])

def distorsion_map(P):
	x, y = P.xy()
	return E(x * z, y)

dat_p3 = [E(P) for P in dat]
assert dat_p3[0].order() == o
dat_p3_distorsion = [distorsion_map(P) for P in dat_p3]

res_p3 = [ dat_p3[correct_idx].weil_pairing(dat_p3_distorsion[i + 1], p3 + 1)
		== dat_p3[correct_idx + 1].weil_pairing(dat_p3_distorsion[i], p3 + 1)
		for i in trange(255)]

assert 255 > res_p3.count(True) > 130
```

### 7. key 복구
모든 커브에 대하여 불가능한 후보들을 골라낸 후, 그 중 하나에도 속하지 않는다면 그 곱셈에는 $s$와 완전히 동일한 값이 곱해졌다고 생각 가능합니다.

```python
res_list = [res_p1, res_p2, res_p2_power, res_p3, res_p3_power, res_p4, res_p4_power]

res = [all(r[i] for r in res_list) for i in range(255)]

# check
for i in range(7):
	res_without = []
	for j in range(7):
		if i == j:
			continue
		res_without.append(res_list[j])
	res_fail = [all(r[i] for r in res_without) for i in range(255)]

	assert res_fail != res
```
`# check`에서, 앞 과정들 중 하나라도 빠질 경우 키 복구가 불가능함을 확인하였습니다.

```python
from Crypto.Cipher import AES

for front in range(2):
	key = 0
	keybits = [front] + res
	for i in range(256):
		key += keybits[i] << i

	key = int(key).to_bytes(32)

	flag = AES.new(key, AES.MODE_CTR, nonce=bytes(12)).decrypt(enc_flag)
	try:
		print(flag.decode())
	except:
		pass
```

## 플래그
`codegate2025{If_these_weils_could_talk_(I_can_feel_your_reign_when_it_cries_supersingular_curves_inside_of_you)}`