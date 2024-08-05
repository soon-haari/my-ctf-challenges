# Crypto - 🔀

### 출제자
- 김민순 (@soon_haari)

### 문제 세팅 방법


1. `for_organizer` 폴더로 이동
2. `Dockerfile`, `docker-compose.yml`의 port 세팅 상황에 맟게 변경
3. 아래 명령어 실행

```
$ docker-compose up -d
```

### 출제 지문
Something smells fishy, why all the birds are down here and fishes are flying?

### 문제 풀이(writeup)

AES가 구현되어 있고, 이는 실제 AES와 동일합니다. `myAES.py`의 `__main__`에서 확인 가능합니다. 허나, 블록사이즈를 늘리고 라운드 수를 늘려 사용합니다. 따라서 이는 알려진 취약점이 없을 것으로 생각 가능합니다. 

이 문제에서는 S-box 중에서 두 바이트를 서로 바꾼 상태에서 임의의 암복호화가 허용됩니다. 새로 생성된 S-box도 크게 취약점이 있다고 볼 수는 없지만, Inverse S-box는 그대로이기 때문에, 임의의 평문을 암호화하고 복호화한 결과가 동일하다면, 20라운드 중 단 한번도 뒤바뀐 바이트를 거치지 않았다는 사실을 이용하여 정보를 얻을 수 있습니다.

암호문과 평문을 모두 알고 있는 상태이기 때문에 첫 라운드와 마지막 라운드 모두에서 정보를 얻을 수 있고, 이를 조합하여 불가능한 바이트들을 제거해 나가면 최종적으로 S-box의 뒤바뀐 바이트를 알 수 있고, 또한 24바이트 키에 대한 정보를 추려낼 수 있습니다. 그러나 XOR된다는 특성 때문에 각 바이트당 2개의 후보를 남겨 놓는 수준까지밖에 추릴 수 없습니다. 따라서 $2^{24}$개의 후보가 존재합니다.

$2^{24}$전수 조사를 위해 빠른 C, Rust등의 빠른 언어를 사용해 전수 조사 과정을 시행해야 합니다.

### 플래그
cce2024{Fortunately_in_the_parellel_universe_fishes_were_swimming...phew!}