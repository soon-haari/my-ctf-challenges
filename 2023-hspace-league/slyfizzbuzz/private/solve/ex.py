import random
from pwn import *

class Twister:
    N = 624
    M = 397
    A = 0x9908b0df

    def __init__(self):
        self.state = [ [ (1 << (32 * i + (31 - j))) for j in range(32) ] for i in range(624)]
        self.index = 0
    
    @staticmethod
    def _xor(a, b):
        return [x ^ y for x, y in zip(a, b)]
    
    @staticmethod
    def _and(a, x):
        return [ v if (x >> (31 - i)) & 1 else 0 for i, v in enumerate(a) ]
    
    @staticmethod
    def _shiftr(a, x):
        return [0] * x + a[:-x]
    
    @staticmethod
    def _shiftl(a, x):
        return a[x:] + [0] * x

    def get32bits(self):
        if self.index >= self.N:
            for kk in range(self.N):
                y = self.state[kk][:1] + self.state[(kk + 1) % self.N][1:]
                z = [ y[-1] if (self.A >> (31 - i)) & 1 else 0 for i in range(32) ]
                self.state[kk] = self._xor(self.state[(kk + self.M) % self.N], self._shiftr(y, 1))
                self.state[kk] = self._xor(self.state[kk], z)
            self.index = 0

        y = self.state[self.index]
        y = self._xor(y, self._shiftr(y, 11))
        y = self._xor(y, self._and(self._shiftl(y, 7), 0x9d2c5680))
        y = self._xor(y, self._and(self._shiftl(y, 15), 0xefc60000))
        y = self._xor(y, self._shiftr(y, 18))
        self.index += 1

        return y
    
    def getrandbits(self, bit):
        return self.get32bits()[:bit]

    def randbytes(self, n):
        left = n

        res = []

        while left >= 4:
            left -= 4
            q = self.get32bits()

            for i in range(4):
                res.append(q[(3 - i) * 8:(4 - i) * 8][::-1])

        if left:
            q = self.get32bits()
            for i in range(left):
                res.append(q[(left - 1 - i) * 8:(left - i) * 8][::-1])

        assert len(res) == n

        return res

class Solver:
    def __init__(self):
        self.equations = []
        self.outputs = []
    
    def insert(self, equation, output):
        for eq, o in zip(self.equations, self.outputs):
            lsb = eq & -eq
            if equation & lsb:
                equation ^= eq
                output ^= o
        
        if equation == 0:
            if output == 0:
                return
            raise ValueError("Impossible generated bits.")

        lsb = equation & -equation
        for i in range(len(self.equations)):
            if self.equations[i] & lsb:
                self.equations[i] ^= equation
                self.outputs[i] ^= output
    
        self.equations.append(equation)
        self.outputs.append(output)
    
    def solve(self):
        num = 0
        for i, eq in enumerate(self.equations):
            if self.outputs[i]:
                # Assume every free variable is 0
                num |= eq & -eq

        
        state = [ (num >> (32 * i)) & 0xFFFFFFFF for i in range(624) ]
        return state

def fizzbuzz(n):
    fb = "sly"
    if n % 3 == 0:
        fb += "fizz"
    if n % 5 == 0:
        fb += "buzz"
    return fb

if __name__ == "__main__":

    # io = remote("localhost", 1013)
    io = remote("54.180.98.27", 1013)

    size = 5000

    twister = Twister()
    solver = Solver()

    twister.index = 624

    solver.insert(twister.state[0][0], 1)
    for i in range(1, 32):
        solver.insert(twister.state[0][i], 0)

    cnt = 0

    while True:
        print("Getting Data...")
        res = [0] * size

        for i in range(size):
            io.sendline(b"roll")
        for i in range(size):
            io.recvuntil(b"> ")
            if io.recvline()[:-1] == b"slyfizzbuzz":
                res[i] = 1

        cnt += size

        dats = [twister.getrandbits(8) for _ in range(size)]

        for i in range(size):
            dat = dats[i]
            if res[i] == 0:
                continue

            diff = Twister._xor(dat[:4], dat[4:])
            diff = Twister._xor(diff[:3], diff[1:])

            solver.insert(diff[0], 0)
            solver.insert(diff[1], 0)
            solver.insert(diff[2], 0)

            rank = len(solver.equations)

            print(f"{rank = }", end = "\r")

            if rank == 19968:
                break

        if rank == 19968:
            break

    state = solver.solve()

    random.setstate((3, tuple(state + [624]), None))

    for _ in range(cnt):
        random.getrandbits(8)

    io.sendlineafter(b"> ", b"asdf")

    for _ in range(100):
        io.sendlineafter(b"Guess> ", fizzbuzz(random.getrandbits(8)).encode())



    io.interactive()