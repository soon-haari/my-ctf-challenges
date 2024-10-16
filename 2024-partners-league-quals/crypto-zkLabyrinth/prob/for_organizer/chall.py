from PIL import Image
from hashlib import sha256
from secret import flag

side_real = 100
side = side_real * 2 + 1

m = list(Image.open('maze.png').getdata())
m = [int(block == (0, 0, 0, 255)) for block in m]
assert len(m) == side**2
m = [m[side * i:side * (i + 1)] for i in range(side)]
assert m[1][0] == 0 and m[-2][-1] == 0

p = 2**255 - 19

def str2fp(msg):
	return int.from_bytes(sha256(msg.encode()).digest()) % p

name = input("Your name: ")
key = input("Your key: ")

state = str2fp(name)

x, y = 0, 1

while (x, y) != (side - 1, side - 2):
	cmd = input("> ")

	for c in cmd.lower():
		if c == "w":
			y -= 1
			state *= pow(1337, -1, p)
		elif c == "a":
			x -= 1
			state -= 1337
		elif c == "s":
			y += 1
			state *= 1337
		elif c == "d":
			x += 1
			state += 1337
		state %= p

		try:
			assert m[y][x] == 0			
		except:
			print("Invalid move!")
			exit()

if state == str2fp(key):
	print("Are you an alchemist?", flag)
else:
	print("You beat the maze, congrats!!! 🎉")

