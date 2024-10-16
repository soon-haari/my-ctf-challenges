# Counter Strike

Simple GCM with some option is allowed:
- Encryption with length with `randrange(256, 512)`
- Digest and view the tag, however after digesting, verifying or additional encryption is impossible.

It can be easily concluded we can retreive the tag whenever plaintext's length is greater or equal to 256 bytes. It is impossible to calculate XOR stream's front 256 bytes, but we can make verifying not require front stream bytes by encrypting two times in a row. 

## Step 1.

By using encryption option 1 to 3 times, we can retreive some plaintext-tag pairs with 256 ~ 1023 bytes plaintexts.

512 byte plaintext is only generated when both two encryption's length is 256, which probability is $\frac{1}{65536}$. Using batch(sending multiple times and recieving multiple times to save a lot of time, especially on remote) is very important here.

## Step 2.

Calculating $H$ is very easy when we have 2 pairs of pt-tag with same length pt. Multiple candidates may exist when you find roots of a polynomial over $\mathbb{F}_{2^{128}}$. Reduce it until there exists a unique one.

## Step 3.

Calculating $s = \textnormal{E}(\textnormal{iv})$ is slightly trickier. We need two pair with plaintext length $l$ and $l + 1$ where $l$ is a multiple of blocksize which is 16.

Then, $(H \times tag_l) + tag_{l + 1}$ would make stream of $l$ bytes disappear, and only 1 byte remains unknown. By calculating the previous polynomial, $s \times (H + 1)$ term is remained, we can calculate $s$ from it.

256 possibilities exists since there is a unknown remaining 1 byte.

## Step 4.
Not much different from Step 3. With $l, l + 1$ length pairs, XOR stream's $l$'th byte can be calculated. (This time $l$ is every integer within `range(256, 1023)`.)

Since there exists 256 possibilities for $s$, stream also has 256 possibilities.

We now have 256 candidates for stream[256:1023].

## Step 5.
Using encryption oracle once, we cannot know the encrypted result because stream[:256] is still unknown. But using the second encryption, second plaintext is always inside the range 256:1023, which is why I set the range at the first place.

Brute force 256 times for each $s$'s candidates and the challenge is solved.
