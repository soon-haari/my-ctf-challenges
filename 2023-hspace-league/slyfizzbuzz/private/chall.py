import random
import os

FLAG = open("flag", "r").read()

def fizzbuzz(n):
    fb = "sly"
    if n % 3 == 0:
        fb += "fizz"
    if n % 5 == 0:
        fb += "buzz"
    return fb

for rounds in range(100000):
    cmd = input("> ")
    if cmd == "roll":
        dice = random.getrandbits(8)
        print(fizzbuzz(dice))

    else:
        for _ in range(100):
            assert fizzbuzz(random.getrandbits(8)) == input("Guess> ")
        break
else:
    exit()

print(f"Here is your flag: {FLAG}")