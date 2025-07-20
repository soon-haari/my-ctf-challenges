from pwn import *

io = remote("localhost", 9997)

q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
r = 21888242871839275222246405745257275088548364400416034343698204186575808495617

F = GF(q)
F2.<u> = GF(q^2, modulus=x^2 + 1)

E = EllipticCurve(F, [0, 3])
E2 = EllipticCurve(F2, [0, 3 / (u + 9)])

A, B = E.random_element(), E.random_element()
assert A * r == B * r == E(0)
C = E2.random_element()
assert C * r != E2(0)

io.sendlineafter(b"Input G1: ", str(A.xy()).encode())
io.sendlineafter(b"Input G1: ", str(B.xy()).encode())
io.sendlineafter(b"Input G2: ", str(tuple(tuple(val) for val in C.xy())).encode())


io.interactive()