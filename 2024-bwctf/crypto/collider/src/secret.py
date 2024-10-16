import os
import random
import string
import hashlib

banner = """
  _, _, ,   ,  ___, ,_   _,,_   
 /  / \,|   | ' |   | \,/_,|_)  
'\_'\_/'|__'|___|_,_|_/'\_'| \  
   `'     '   '   '       `'  ` 
Have you solved y011d4 sama's unrandom DSA before? 😜
"""[1:]

colors = ['\033[94m', '\033[96m', '\033[95m']
reset = '\033[0m'

banner = ''.join(random.choice(colors) + char + reset if char != ' ' else char for char in banner)


colors = ["\033[0;32m", "\033[0;33m", "\033[0;34m", "\033[0;35m", "\033[0;36m", "\033[0;37m", "\033[0;31m", "\033[38;5;248m", "\033[0m"]
green, yellow, blue, purple, cyan, white, red, grey, reset = colors

flag = ""

for c in open("flag.txt", "r").read():
   flag += colors[random.randrange(0, 6)] + c
flag += reset

print(banner)