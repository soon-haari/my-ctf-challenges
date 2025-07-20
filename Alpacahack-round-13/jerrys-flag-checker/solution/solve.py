from pwn import *

io = remote("localhost", 9999)

flag = b""

base_len = 50

for i in range(base_len):
    msg = [127] * base_len

    for j in range(126):
        msg[base_len - i - 1] = j
        io.sendline(str(int.from_bytes(bytes(msg))).encode())

    idx = None
    for j in range(126):
        io.recvuntil(b"Guess the flag in integer: ")
        res = io.recvline()
        if idx == None:
            if b"Wrong" in res:
                idx = j
    
    flag = bytes([idx]) + flag
    print(flag.decode())

    if flag[:6] == b"Alpaca":
        break