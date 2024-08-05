from myAES import myAES as AES
from secret import flag
from os import urandom
import signal

signal.alarm(180)

sbox = AES.s_box[:]

ROUNDS = 3

for rnd in range(ROUNDS):
	print(f"--- ROUND {rnd + 1} ---")

	AES.blocksize = 24
	AES.n_rounds = 20
	AES.s_box = sbox[:]

	fish, bird = urandom(2)
	AES.s_box[fish], AES.s_box[bird] = AES.s_box[bird], AES.s_box[fish]

	key = urandom(AES.blocksize)
	encrypt = AES(key).encrypt
	decrypt = AES(key).decrypt

	while True:
		cmd = input("cmd> ")
		msg = bytes.fromhex(input("msg> "))

		if cmd == "e":
			result = encrypt(msg)
			print(f"result: {result.hex()}")

		elif cmd == "d":
			result = decrypt(msg)
			print(f"result: {result.hex()}")

		elif cmd == "v":
			assert msg == key
			break

print(flag)