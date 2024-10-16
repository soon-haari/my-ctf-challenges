import os
import random
import string
import hashlib
import time

colors = ["\033[0;32m", "\033[0;33m", "\033[0;34m", "\033[0;35m", "\033[0;36m", "\033[0;37m", "\033[0;31m", "\033[38;5;248m", "\033[0m"]
reset = '\033[0m'

banner = ""

for c in open("banner.txt", "r").read():
	banner += colors[random.randrange(0, 6)] + c
banner += reset

green, yellow, blue, purple, cyan, white, red, grey, reset = colors

flag = ""

for c in open("flag.txt", "r").read():
	flag += colors[random.randrange(0, 6)] + c
flag += reset


cur = int(time.time())
nonce = os.urandom(8).hex()

for filename in os.listdir("/tmp"):
	f_split = filename.split("_")
	if f_split[0] != "temp":
		continue

	t = int(f_split[1])
	if cur - t > 600: # 10 minutes
		try:
			os.remove(filename)
		except:
			pass

fname = f"/tmp/temp_{cur}_{nonce}"

print(banner)
