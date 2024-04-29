# f, l and ag
- 분야: Crypto
- 키워드: RSA, 다변수 상황에서의 Franklin-Reiter attack, LLL


## Introduction
이 문제는 드림핵 CTF에 출제되어, 현재는 워게임으로 익스포트되어 있는 [fl and ag](https://dreamhack.io/wargame/challenges/939) 문제의 revenge 버전입니다.

## 배경

### Franklin-Reiter related message attack

**Franklin-Reiter attack**은 어떤 두 메세지 $m_1$, $m_2$를 같은 RSA 공개키로 암호화한 값 $c_1$, $c_2$와, 두 원본 메세지의 차 $m_1 - m_2$의 값을 알고 있을 때 원래의 $m_1$, $m_2$를 빠르게 복구하는 공격 기법입니다. 대략적인 방법은 아래와 같습니다.

1. $<N, e>$를 RSA의 공개키라고 합시다. $m_2 - m_1 = r$이라고 하면, $(m_1)^e - c_1 \equiv 0 \pmod N$,  $(m_1+r)^e - c_2 \equiv 0 \pmod N$가 성립합니다. 이때 우리가 알고 있는 값은 $N, e, c_1, c_2, r$ 입니다.
2. 1의 식에서 $m_1$을 변수 $x$로 치환한 함수 $f_1(x) = x^e - c_1 \pmod N$, $f_2(x) = (x+r)^e - c_2 \pmod N$를 생각해봅시다. 이때 $m_1$은 $f_1$과 $f_2$의 해가 됨을 알 수 있습니다. 즉, $f_1$, $f_2$는 $x-m_1$을 공통 인수로 가집니다.
3. 그런데 $f_1$과 $f_2$의 GCD(Greatest Common Divisor) 함수는 Euclidean algorithm을 통해 다항시간 내에 구할 수 있습니다. $f_1$과 $f_2$의 GCD 값이 $x-m_1$이므로, 이는 다항시간 내에 $m_1$, 즉 원본의 메세지를 알 수 있다는 것을 의미합니다.

### LLL lattice basis reduction algorithm

**LLL 알고리즘**은 주어진 basis $B=\{ b_1, b_2, \ldots , b_n \}$로부터 LLL-reduced lattice basis를 빠르게 구하는 알고리즘으로, 주로 Shortest Vector Problem, Closest Vector Problem 등의 NP-Hard 문제의 근사해를 구하기 위해 사용됩니다. 더 나아가, 일부 어려운 정수 문제들을 푸는데도 유용하게 사용할 수 있습니다. LLL 알고리즘의 수학적인 디테일들을 다루기엔 그 내용이 너무 방대하기에 더 자세히 다루지는 않겠습니다. 아래의 참조 링크에서 더 많은 내용을 학습할 수 있습니다. (https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm)


## 분석
prob.py
```python
from Crypto.Util.number import getPrime, GCD, bytes_to_long

while True:
    p = getPrime(1024)
    q = getPrime(1024)
    e = 0x101
    if GCD((p - 1) * (q - 1), e) == 1:
        break
N = p * q

with open('flag', 'rb') as f:
    flag = f.read()
    assert len(flag) == 68

f, l, ag = flag[:17], flag[17:34], flag[34:]
f, l, ag, flag = map(bytes_to_long, (f, l, ag, flag))

f_enc = pow(f, e, N)
l_enc = pow(l, e, N)
ag_enc = pow(ag, e, N)
flag_enc = pow(flag, e, N)

print(f"{N = }")
print(f"{e = }")
print(f"{f_enc = }")
print(f"{l_enc = }")
print(f"{ag_enc = }")
print(f"{flag_enc = }")
```

기존 문제와의 유일한 차이점은 플래그가 두 조각이 아니라 세 조각으로 나뉘어 있다는 차이점을 가지고 있습니다. $N$의 비트 수, $e$ 등의 다른 parameter은 모두 기존과 동일합니다.

공개키의 크기는 2048비트, `f`, `l`, `ag`는 각각 17, 17, 34바이트이고, 이를 concatenate한 최종 플래그인 `flag`는 68바이트입니다. 

주어진 정보는 `f`, `l`, `ag`, `flag`를 각각 RSA 암호화한 4개의 암호문입니다. 

## 풀이
크게 세 단계에 거쳐서 풀이가 진행됩니다. 먼저 몇 가지 변수명들을 정의하도록 하겠습니다. 

$A$ = `f`, $B$ = `l`, $C$ = `ag`, $D$ = `flag`

$A_{e}$ = `f_enc`, $B_{e}$ = `l_enc`, $C_{e}$ = `ag_enc`, $D_{e}$ = `flag_enc`

또한 $a$ = $A / C$, $b$ = $B / C$

위 변수들에 대한 모든 연산이 `Zmod(N)`위에서 이루어짐에 유의합니다. 

1. $a$, $b$만으로 정의된 3개의 다항식에서 Franklin-Reiter attack을 모티브로 한 연산 과정을 통해 변수 하나를 소거한 새로운 다항식을 생성합니다. 
2. 기존의 변수 하나로만 정의되는 다항식과 새로 만든 다항식에서 Franklin-Reiter attack을 적용하여 $b$를 복원합니다. $b$를 대입하여 Franklin-Reiter attack을 한번 더 사용하여 $a$까지 복원합니다. 
3. $a$는 비트 수가 $N$에 비해 훨씬 작은 $A$와 $C$의 나눗셈으로 정의되었기 때문에 LLL 알고리즘을 이용해 $A$, $C$를 복원합니다. $b$를 알기 때문에 $B$까지 마저 복원하여 최종 플래그를 완성합니다.

### Step 1.
주어진 정보는 다음과 같습니다.
$$A^{257} = A_{e}, B^{257} = B_{e}, C^{257} = C_{e}, D^{257} = D_{e}$$

여기서 $D$는 $A$, $B$, $C$, 즉 `f`, `l`, `ag`를 이어붙인 결과이고, 각 17, 17, 34바이트의 크기를 가지고 있기 때문에 $D$, 즉 `flag`는 다음과 같이 표현할 수 있습니다.

$$D = 256^{51}A + 256^{34}B + C$$

[fl and ag](https://dreamhack.io/wargame/challenges/939)의 풀이와 같이 양변에서 $C$를 나누어주도록 하겠습니다.

$$D / C = 256^{51}a + 256^{34}b + 1$$
$$D_{e} / C_{e} = (256^{51}a + 256^{34}b + 1)^{257}$$
$$(256^{51}a + 256^{34}b + 1)^{257} = D_{e} / C_{e}$$

또한 $a$, $b$에 관한 다른 다항식들은 다음과 같습니다. 

$$a^{257} = A_{e} / C_{e}, b^{257} = B_{e} / C_{e}$$

이를 바탕으로 3개의 식을 생성합니다.

$$f_{1}(x, y) = (256^{51}x + 256^{34}y + 1)^{257} - D_{e} / C_{e}$$
$$f_{2}(x) = x^{257} - A_{e} / C_{e}$$
$$f_{3}(y) = y^{257} - B_{e} / C_{e}$$

$f_{1}(a, b), f_{2}(a), f_{3}(b)$ 은 모두 0의 값을 가집니다.

Franklin-Reiter attack의 방법과 동일하게 다항식의 GCD(Greatest Common Divisor)을 사용하는 아이디어는 같지만, 변수가 2개이기에 완전히 동일한 방법으로는 불가능합니다.

이 문제는 $y$를 상수 취급하고, $x$만을 변수로 취급하여 $x$를 소거함으로서 해결할 수 있습니다.


```python
Q.<y> = PolynomialRing(Zmod(N))
P.<x> = PolynomialRing(Q)

f1 = P((x * 256^51 + y * 256^34 + 1)^e - (flag_enc / ag_enc) % N)
f2 = P(x^e - (f_enc / ag_enc) % N)
f3 = Q(y^e - (f_enc / ag_enc) % N)
```

sagemath에서 PolyniomialRing을 이와 같이 설정하고 `f1`, `f2`의 최대공약수를 구하는 것과 동일한 방법으로 `x`의 차수를 줄여가면서 한 식에서 `x`의 지수항이 사라지고, 상수항(여기에는 `y`가 들어갈 수 있습니다.)만 남았을 경우를 생각해보겠습니다. 

`f1(a) == 0`과, `f2(a) == 0`을 만족하기 때문에 곱셈과 뺄셈만이 진행되는 GCD과정을 아무리 진행시켜도 항상 `f1(a) == 0`과 `f2(a) == 0`는 만족합니다. 

위에서 말한 것처럼 상수항이 남은 상태에서 그 상수항을 `g`라고 부르겠습니다. 
`g(a) == 0`을 만족하지만, 상수항이기 때문에 `x`의 값과 관계없이 `g`는 항상 0의 값을 가지는 것을 확인할 수 있습니다. 

이 상황에서의 `g`는 실제로는 상수항이 아닌 `y`로 표현된 다항식이기 때문에 `x`없이 `y`로만 구성된 다항식의 해에 `b`가 들어가는 식이 `g`와 `f3`으로 2개가 되어 일반 Franklin-Reiter attack으로 `b`를 복원할 수 있습니다.

<br>

여기서 유의할 점은 GCD과정에서 필요한 monic 과정이 이 상황에서는 불가능합니다. `y`의 다항식 꼴로 표현되는 계수의 역원을 찾을 수 없기 때문입니다. 

그래서 두 식의 `x`에 대한 최고차항 계수를 서로 반대로 곱하여 최고차항 계수가 같아지게 함으로서 `x`의 차수를 줄여나갈 수 있습니다.

하지만, 그 과정을 반복하면 `y`의 다항식 꼴로 표현되는 계수들의 차수가 기하급수적으로 커지기 때문에 미리 알고 있는 정보인 `f3`으로 나눈 나머지로 업데이트해주는 과정이 필수적입니다. 

이는 다음과 같이 구현됩니다. 

```python
while f2.degree() > 0:
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
```

### Step 2.
`g`와 `f3`에 대해 Franklin-Reiter attack을 이용해 `b`를 복구할 수 있습니다. 

두 식의 GCD를 구하는 것과 같이 차수를 하나씩 작게 만들면서 일차식이 나올 때까지 반복합니다. monic도 정의되어 있고, sagemath에서 다항식 사이의 % 연산도 정의되어 있어서 간편합니다. 

`b` 복구 이후에는 위에서 사용한 `f1`, `f2`에 `y = b`를 대입하여 같은 Franklin-Reiter attack을 이용해 `a`를 복구할 수 있습니다. 

### Step 3.

이제 구한 $(a = A/C)$로부터 $A$, $C$를 복원해야 합니다. $A$, $C$가 $N$에 비해 매우 작기 때문에, **LLL 알고리즘**을 사용하면 이를 복원할 수 있습니다.

아래의 basis matrix를 생각합시다.
$$
M =    \begin{bmatrix}    1 & a  \\   0 & N  \\ \end{bmatrix}
$$
또, 위 basis로 만들 수 있는 lattice 집합을 $L$이라고 합시다. 즉, $L = \{a_1v_1 +a_2v_2 \ |\ a_1,a_2 \in Z , v_1 = (1,a)  , v_2 = (0,N)\}$입니다. 또, $L$에서 가장 크기가 작은 벡터를 $\lambda(L)$이라고 합시다.

이때 $(C,A)$는 $L$의 원소가 되는데, 이유는 다음과 같습니다.

1. $(a \equiv A/C \pmod N)$이기 때문에 어떤 정수 $t$가 존재하여 $(aC - A)=Nt$가 성립합니다.
2. $a_1 = C, a_2 = -t$로 두면, $a_1v_1 + a_2v_2 = (C,aC)+(0,-Nt)=(C,A)$입니다. 따라서 $(C,A)\in L$이 성립합니다. 

그런데 $C$, $A$는 각각 34바이트(272비트), 17바이트(136비트) 수준의 크기인 반면, $a$와 $N$은 2048비트 정도의 크기로 $C$와 $A$에 비해 훨씬 큽니다. 이는 $(C,A)$는 $L$의 원소들 중에서도 특별히 크기가 작은 원소라는 것을 의미합니다. 따라서, $\lambda(L) = (C,A)$이거나, 적당히 작은 정수 $k$가 존재해 $k\lambda(L) = (C,A)$라고 기대해볼 수 있습니다. (후자의 경우는 $(C,A)$를 만들 때 사용한 $a_1, a_2$가 서로소가 아닐 때 발생합니다.) 

이제 $M$에 LLL 알고리즘을 적용해서 얻은 벡터 $b_1$을 생각해봅시다. LLL 알고리즘의 성질에 의해, $b_1$은 아래의 성질을 가집니다.
$$
||b_1|| \leq (2/\sqrt{4\delta-1} )^{n-1} ||\lambda(L)||
$$
이때 $\delta$는 LLL 알고리즘의 인자로 주로 ${3 \over 4}$를 택하고, $n$은 basis의 개수로, 이 문제에서는 $n=2$입니다. 즉, $||b_1|| <= \sqrt2 ||\lambda(L)||$입니다. 그런데 $\lambda(L)$은 $L$에서 가장 크기가 작은 벡터라고 정의를 했고, 따라서 $||\lambda(L)|| \leq ||(C,A)||$입니다. 즉, $||b_1|| \leq \sqrt2 ||(C,A)||$가 성립합니다. 그런데 $L$에서 $(C,A)$ 수준의 크기를 갖는 벡터는 사실상 $\lambda(L)$, 혹은 $\lambda(L)$의 상수배 정도 뿐이기에, $b_1$으로부터 $\lambda(L)$을 구할 수 있습니다. 그리고 위에서 언급했듯 적당한 $k$에 대해 $k\lambda(L) = (C,A)$일 가능성이 높고, 따라서 $b_1$으로부터 $(C,A)$를 구할 수 있습니다. 이때 $k$의 값에 따라 여러개의 $(C,A)$ 후보가 나올 수 있는데, $C$를 바이트 변환하였을 때 전부 printable, 또는 decodable임을 활용하면 어떤 $(C,A)$가 실제 플래그의 값인지 알 수 있습니다.

$C$, 즉 `ag`를 얻은 후에는 각각 `a`, `b`와 곱하여 `f`, `l`을 획득할 수 있습니다.



최종 솔브 코드는 다음과 같습니다.

### solve.sage
```python
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
```

## 레퍼런스

- https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm
- https://en.wikipedia.org/wiki/Coppersmith%27s_attack#Franklin%E2%80%93Reiter_related-message_attack