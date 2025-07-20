from py_ecc import bn128
from pwn import *
from random import randrange

io = remote("localhost", 9997)

A = bn128.multiply(bn128.G1, randrange(bn128.curve_order))
B = bn128.multiply(bn128.G1, randrange(bn128.curve_order))

C = bn128.multiply(bn128.G2, randrange(bn128.curve_order))

assert (
    bn128.pairing(C, A) * bn128.pairing(C, B)
    ==
    bn128.pairing(C, bn128.add(A, B))
    )

io.sendlineafter(b"Input G1: ", str(A).encode())
io.sendlineafter(b"Input G1: ", str(B).encode())
io.sendlineafter(b"Input G2: ", str(C).encode())

assert io.recvline() == b"Looks like it's safe!\n"

io.close()