from Crypto.Util.number import *
import os

flag = bytes_to_long(os.environ.get("FLAG", "fakeflag").encode())

while True:
    try:
        if long_to_bytes(int(input("Guess the flag in integer: ")) - flag).decode():
            print("Wrong flag. :P")
        else:
            print("Yay, you found the flag! :3")
    except:
        print("Weird... :/") 
