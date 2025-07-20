FLAG = os.environ.get("FLAG", "Alpaca{********************************************}").encode()
pad = os.urandom(len(FLAG))
FLAG = [a ^^ b for a, b in zip(FLAG, pad)]

q = int(input("Missing order: "), 16)
assert not is_prime(q) and q.bit_length() == 256

F = GF(q)
A = random_matrix(F, len(FLAG))[:,:-2]
b = A * random_vector(F, A.ncols()) + vector(F, FLAG) * F.random_element()
print(dumps((A, b, pad)).hex())