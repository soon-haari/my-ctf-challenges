import os
import random
import string
import hashlib

colors = ["\033[0;32m", "\033[0;33m", "\033[0;34m", "\033[0;35m", "\033[0;36m", "\033[0;37m", "\033[0;31m", "\033[38;5;248m", "\033[0m"]
green, yellow, blue, purple, cyan, white, red, grey, reset = colors

flag = ""

for c in open("flag.txt", "r").read():
	flag += colors[random.randrange(0, 6)] + c
flag += reset
