from pwn import *
from Crypto.Cipher import AES
import random
from tqdm import trange

# Helper

F.<a> = GF(2^128, modulus=x^128 + x^7 + x^2 + x + 1)

def bytes_to_n(b):
	v = int.from_bytes(nullpad(b), 'big')
	return int(f"{v:0128b}"[::-1], 2)

def bytes_to_poly(b):
	return F.from_integer(bytes_to_n(b))

def poly_to_n(p):
	v = p.to_integer()
	return int(f"{v:0128b}"[::-1], 2)
	
def poly_to_bytes(p):
	return poly_to_n(p).to_bytes(16, 'big')

def length_block(lad, lct):
	return int(lad * 8).to_bytes(8, 'big') + int(lct * 8).to_bytes(8, 'big')

def nullpad(msg):
	return bytes(msg) + b'\x00' * (-len(msg) % 16)

def calculate_tag(key, ct, nonce, ad=b""):
	y = AES.new(key, AES.MODE_ECB).encrypt(bytes(16))
	s = AES.new(key, AES.MODE_ECB).encrypt(nonce + b"\x00\x00\x00\x01")
	assert len(nonce) == 12

	y = bytes_to_poly(y)

	l = length_block(len(ad), len(ct))

	blocks = nullpad(ad) + nullpad(ct)
	bl = len(blocks) // 16

	blocks = [blocks[16 * i:16 * (i + 1)] for i in range(bl)]
	blocks.append(l)
	blocks.append(s)

	tag = F(0)
	
	for exp, block in enumerate(blocks[::-1]):
		tag += y^exp * bytes_to_poly(block)

	tag = poly_to_bytes(tag)

	return tag

def check():
	key = os.urandom(16)
	nonce = os.urandom(12)

	pt = os.urandom(os.urandom(1)[0])
	
	cipher = AES.new(key, AES.MODE_GCM, nonce)
	ct, tag = cipher.encrypt_and_digest(pt)

	assert tag == calculate_tag(key, ct, nonce)



if __name__ == "__main__":
	# 0. Check GCM helper, process start

	check()
	io = process(["python3", "chall.py"])
	# io = remote(?, ?)


	
	# 1. Collect until we have all candidates with length range(256, 1024)

	lb = 256
	ub = 512

	assert lb % 16 == 0 and ub % 16 == 0

	batch = 1500

	collect = [[] for _ in range(ub * 2)]

	collect_cnt = 0

	while True:
		for idx in range(lb, ub * 2):
			if len(collect[idx]) == 0:
				min_undone_idx = idx
				break
		else:
			break

		if min_undone_idx == None:
			break

		collect_cnt += 1

		print(f"Try {collect_cnt}, {min_undone_idx = }")
		
		if min_undone_idx < 512:
			cnt = 1
		elif min_undone_idx < 900:
			cnt = 2
		else:
			cnt = 3
		

		io.sendlines(([b"reset"] + [b"encrypt"] * cnt + [b"tag"]) * batch)

		for _ in range(batch):
			pt = b""

			for __ in range(cnt):
				io.recvuntil(b"pt: ")
				pt += bytes.fromhex(io.recvline().decode())
			io.recvuntil(b"tag: ")
			tag = bytes.fromhex(io.recvline().decode())

			if len(pt) >= 1024:
				continue

			collect[len(pt)].append([pt, tag])



	# 2. Recover H

	P.<x> = PolynomialRing(F)

	cands = None

	while True:
		idx = random.randrange(lb, ub * 2)
		if len(collect[idx]) < 2:
			continue

		(pt1, tag1), (pt2, tag2) = random.sample(collect[idx], 2)

		pt_xor = xor(pt1, pt2)
		tag_xor = xor(tag1, tag2)

		pt_xor = nullpad(pt_xor)
		blocks = [pt_xor[16 * i:16 * (i + 1)] for i in range(len(pt_xor) // 16)]

		poly = bytes_to_poly(tag_xor) # same with -bytes_to_poly(tag_xor)

		for i, block in enumerate(blocks[::-1]):
			poly += x^(i + 2) * bytes_to_poly(block)

		cur_cands = set([r[0] for r in poly.roots()])

		if cands == None:
			cands = cur_cands
		else:
			cands &= cur_cands

		if len(cands) == 1:
			for H in cands:
				break
			break



	# 3. Recover E(IV) to one of 256 elements

	pt1, tag1 = collect[lb][0]
	pt2, tag2 = collect[lb + 1][0]

	tag1 = bytes_to_poly(tag1)
	tag2 = bytes_to_poly(tag2)

	lblock1 = bytes_to_poly(length_block(0, len(pt1)))
	lblock2 = bytes_to_poly(length_block(0, len(pt2)))

	pt1 = nullpad(pt1)
	pt2 = nullpad(pt2)

	blocks1 = [pt1[16 * i:16 * (i + 1)] for i in range(len(pt1) // 16)]
	blocks2 = [pt2[16 * i:16 * (i + 1)] for i in range(len(pt2) // 16)]

	tag1_poly = x + H * lblock1
	tag2_poly = x + H * lblock2

	for i, block in enumerate(blocks1[::-1]):
		tag1_poly += H^(i + 2) * bytes_to_poly(block)
	for i, block in enumerate(blocks2[::-1]):
		tag2_poly += H^(i + 2) * bytes_to_poly(block)

	poly = (tag1_poly * H + tag2_poly) + (tag1 * H + tag2)

	cands = []

	for i in range(256):
		temp_poly = poly + bytes_to_poly(nullpad(bytes([i]))) * H^2

		cands.append(temp_poly.roots()[0][0])

	assert len(set(cands)) == 256



	# 4. Find stream[256:1024] for all 256 corresponding E(IV)

	stream_cands = [[] for _ in range(256)]

	for idx in trange(lb, ub * 2 - 1):
		pt1, tag1 = collect[idx][0]
		pt2, tag2 = collect[idx + 1][0]

		tag1 = bytes_to_poly(tag1)
		tag2 = bytes_to_poly(tag2)

		lblock1 = bytes_to_poly(length_block(0, len(pt1)))
		lblock2 = bytes_to_poly(length_block(0, len(pt2)))

		pt1 = nullpad(pt1)
		pt2 = nullpad(pt2)

		blocks1 = [pt1[16 * i:16 * (i + 1)] for i in range(len(pt1) // 16)]
		blocks2 = [pt2[16 * i:16 * (i + 1)] for i in range(len(pt2) // 16)]

		l = len(blocks1)


		if idx % 16 == 0:
			for si in range(256):
				s = cands[si]

				poly = H * (lblock1 * H + s + tag1) + (lblock2 * H + s + tag2)

				for i in range(l):
					poly += bytes_to_poly(xor(blocks1[l - 1 - i], blocks2[l - 1 - i])) * H^(3 + i)

				poly /= H^2

				res = poly_to_bytes(poly)[0] ^^ blocks2[-1][0]

				stream_cands[si].append(res)
				
		else:
			poly = ((lblock1 + lblock2) * H + (tag1 + tag2))

			for i in range(l):
				poly += bytes_to_poly(xor(blocks1[l - 1 - i], blocks2[l - 1 - i])) * H^(2 + i)

			poly /= H^2

			res = poly_to_bytes(poly)[idx % 16]

			for i in range(256):
				stream_cands[i].append(res)

	stream_cands = [bytes(stream) for stream in stream_cands]



	# 5. Try every 256 possibilities

	for si in trange(256):
		io.sendline(b"reset")
		io.sendline(b"encrypt")
		io.sendline(b"encrypt")
		io.sendline(b"verify")

		io.recvuntil(b"pt: ")
		pt1 = bytes.fromhex(io.recvline().decode())
		io.recvuntil(b"pt: ")
		pt2 = bytes.fromhex(io.recvline().decode())
		pt = pt1 + pt2

		l1 = len(pt1)
		l2 = len(pt2)

		ct = xor(pt2, stream_cands[si][l1 - 256:l1 + l2 - 256])

		pt0, tag0 = collect[len(pt)][0]

		tag = bytes_to_poly(tag0)

		pt0 = nullpad(pt0)
		pt = nullpad(pt)

		blocks0 = [pt0[16 * i:16 * (i + 1)] for i in range(len(pt0) // 16)]
		blocks = [pt[16 * i:16 * (i + 1)] for i in range(len(pt) // 16)]

		for i, block in enumerate(blocks0[::-1]):
			tag += H^(i + 2) * bytes_to_poly(block)
		for i, block in enumerate(blocks[::-1]):
			tag += H^(i + 2) * bytes_to_poly(block)

		tag = poly_to_bytes(tag)

		io.sendline(bytes.hex(ct).encode())
		io.sendline(bytes.hex(tag).encode())

		io.recvuntil(b"tag: ")

		res = io.recvn(1)
		if res != b">":
			res += io.recvline()
			break

	io.close()

	print(res.decode()[:-1])
