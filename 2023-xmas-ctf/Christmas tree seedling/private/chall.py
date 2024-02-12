import sys; sys.set_int_max_str_digits(100000)
import random; getstate = lambda x: random.Random(x).getstate()
from secret import flag, banner

print(banner)

"The only supported seed types are: None, int, float, str, bytes, and bytearray."
"Let's try all of them!"

# s_None = None # Edit: Wait, this is used for initialization! This ain't a seed at all!
s_int1 = int(input("Int seed 1 please: ")); assert 2**40000 <= s_int1 < 2**80000
s_int2 = int(input("Int seed 2 please: ")); assert 2**20000 <= s_int2 < 2**40000
s_int3 = int(input("Int seed 3 please: ")); assert 2**2000  <= s_int3 < 2**20000
s_int4 = int(input("Int seed 4 please: ")); assert 0        <= s_int4 < 2**2000
s_int5 = int(input("Int seed 5 please: ")); assert             s_int5 < 0
# s_float = float(input("Float seed please: ")) # Edit: Nah, this is too useless.
s_str = input("String seed please: ")
s_bytes = bytes.fromhex(input("Bytes seed please: "))
# s_bytearray = bytearray.fromhex(input("Bytearray seed please: ")) # Edit: I think this one's same with bytes one.

assert len(set(map(getstate, [s_int1, s_int2, s_int3, s_int4, s_int5, s_str, s_bytes]))) == 1

"Oh right, almost forgot the most important one...."
the_most_important_one = "Merry Christmas! You are the True winner, regardless of the ranking, running nonstop towards your dreams! Thanks for playing, and have fun!!"

assert s_str == s_int1.to_bytes(10000, "big")[-len(s_str):].decode() == the_most_important_one

print(flag)