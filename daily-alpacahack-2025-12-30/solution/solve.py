from ast import literal_eval
from Crypto.Util.number import *

f = open("../distfiles/output.txt", "r")

N = int(literal_eval(f.readline().split(" = ")[1]))

cs = []

NDAT = 13

for i in range(NDAT):
    cs.append(int(f.readline()))

# lcg = lambda s: (s * 3 + 1337) % N

diffs = set()
for i in range(NDAT - 1):
    a, b = cs[i], cs[i + 1]
    diff = (b * pow(a, -3, N)) % N
    diffs.add(diff)

assert len(diffs) == 3
diffs = list(diffs)

for i in range(3):
    for j in range(3):
        if i == j:
            continue
        a, b = diffs[i], diffs[j]
        # a = m^1337
        # b = m^(1337 - N)
        t1 = pow(1337, -1, N - 1337)
        t2 = (t1 * 1337 - 1) // (N - 1337)
        # t1 * 1337 - 1 = t2 * (N - 1337)
        # t1 * 1337 + t2 * (1337 - N) = 1
        m = (pow(a, t1, N) * pow(b, t2, N)) % N
        flag = long_to_bytes(m)

        try:
            print(flag.decode())
            break
        except:
            continue
