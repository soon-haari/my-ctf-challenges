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