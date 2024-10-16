# 출제자

김민순

# Spec
- 1 core

# Concept
- Graph theory
- LLL

# 풀이

####  chall.py
```python
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
```

미로가 구현되어 있고, 상하좌우에 따라 $\mathbb{F}_p$ 위에서 1337에 대한 사칙연산을 수행합니다.

왼쪽-오른쪽이 서로 역연산, 위-아래가 서로 역연산 이기 때문에 미로가 일반적인 트리 자료구조라면 경로에 상관없이 도착점에서의 `state`는 온전히 시작점에서의 `state`에만 의존합니다. 그러나 시작과 최종 `state`는 sha256 해시값으로 결정되기 때문에 설정이 어렵습니다.

미로 `maze.png`를 분석해보면 실제로 트리 구조가 아님을 알 수 있습니다. 다시 말해, cycle이 존재합니다. Cycle이 존재한다면 cycle을 1회 돌 때마다 같은 위치로 다시 되돌아오더라도 state에 변화가 일어납니다. 
계산을 해보면 한 cycle을 순회하면 일정한 값이 `state`에 더해짐을 알 수 있습니다.

DFS로 그래프 분석을 진행하면 30개의 cycle이 존재함을 알 수 있고, LLL 알고리즘을 통해 각 사이클을 8비트 가량의 횟수만큼 반복해 돔으로서 최종 `state`를 원하는 값으로 바꿀 수 있습니다.

# 문제 세팅 방법

`docker-compose up -d`

# 출제 지문

![](https://media.discordapp.net/attachments/1279579536912285719/1284173405201109035/zk.jpeg?ex=66e5ab2e&is=66e459ae&hm=e9b5a99564aeafc325686145f8e09de6291c927fc2b2e52cdfbf08401f058d20&=&format=webp&width=878&height=700)

# 플래그

`hspace{LLL_for_a_maze_chall??_The_solution_is_actually_very_similar_to_exploiting_some_ZK_implementations_=)}`
