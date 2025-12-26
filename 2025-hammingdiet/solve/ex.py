from gf2bv import LinearSystem
from gf2bv.crypto.mt import MT19937

from tqdm import trange, tqdm

lin = LinearSystem([32] * 624)
mt = lin.gens()
rng = MT19937(mt)
for _ in trange(500 * 624):
    rng.getrandbits(32)

mymt = [0] * 624

mymt[400] = 0x80000000 # 1599320
mymt[400] = 0x6422c37e # 1586822

zeros = [(rng.mt[0] ^ mymt[0]) >> 31] + [rng.mt[i] ^ mymt[i] for i in range(1, 624)]

print("solving...")
sol = lin.solve_one(zeros)
assert sol

rng = MT19937(sol)
pyrand = rng.to_python_random()

vals = [pyrand.getrandbits(32) for _ in range(624 * 1000)]
vals_cnt = [val.bit_count() for val in vals]

tot = sum(vals_cnt[:312500])
mini = tot
goodidx = 0

res = []

for ii in range(624 * 1000 - 312500):
    tot += vals_cnt[312500 + ii] - vals_cnt[ii]
    res.append([tot, ii])

res.sort(key = lambda x: x[0])


for tot, goodidx in res:

    goodvals = vals[goodidx + 1:goodidx + 1 + 312500]


    lin = LinearSystem([32] * 624)
    mt = lin.gens()

    rng = MT19937(mt)
    zeros = [rng.getrandbits(32) ^ goodvals[i] for i in range(624)]

    sol = lin.solve_one(zeros)
    assert sol

    rng = MT19937(sol)
    pyrand = rng.to_python_random()

    state = pyrand.getstate()
    suc = (state[1][0] != 0)
    tot = pyrand.getrandbits(10**7).bit_count()

    print(goodidx, tot, suc)

    if suc:
        break
    
from state2seed import state2seed
seed = state2seed(state)

import random
random.seed(seed)
assert random.getrandbits(10**7).bit_count() == tot

f = open("seed.txt", "w")
f.write(hex(seed))
f.close()