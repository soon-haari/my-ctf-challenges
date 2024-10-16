# Collider

The challenge is to find two pairs of two irreducible polynomials over Finite Fields which multiplies to the same result, which is normally impossible. The only way to make this happen is to make the modulus composite for Phase 2. Phase 1 is passed automatically with any seed, but we have only 19937 bits to set for the Mersenne Twister, Phase 1 makes it much harder.

The irreducibility test was implemented from [Rabin's test of irreducibility](https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Rabin.27s_test_of_irreducibility). Sympy's irreducibility check for composite modulus ring isn't supposed to be used(irreducibility check for composite modulus ring isn't supposed to be used XD). It returns True way too easily, so I used Rabin's test so that random polynomials don't return True for the irreducibility test.

## Step 1.

Like the challenge unrandom DSA, we are given to set the `os.urandom` function as the `random.randbytes` function. However this time, the prime generation method is `getStrongPrime`, which is more complex. Reading the PyCryptodome implementation, the target prime number $p$ should be a prime, and $p - 1, p + 1$ both should have known 101-bit prime factor.

This piece of code will explain how I managed to find that kind of prime(which is composite).
```python
P.<m> = PolynomialRing(ZZ)

n = ((k - 1) * m + 1) * (k * (2 * k - 1) * m + 1)
assert n - 1 == m * (k * (k - 1) * (2 * k - 1) * m + (2 * k^2 - 1))
assert n + 1 == ((k^2 - k) * m + 1) * ((2 * k - 1) * m + 2)
```

With some CRT, prime selection is done.

## Step 2.

After making the modulus composite, it is difficult to make the 4 polynomials in total pass the irreducibility test on the weird (not)Field. We now have to seek a way to pass Rabin's test of irreducibility with a backdoor.

The first part of the test is easy to pass, it is coprime most of the time. However, making $f | x^{q^{n_i}} - x$ is difficult.

My solution was to find 1-degreed polynomials and multiply them to make full 4-degreed polynomials, then they are easy to pass the second part of the irreducibility test. Find 4 pairs of them, and swapping one can make different $p_1, q_1, p_2, q_2$ satisfying $p_1 * q_1 = p_2 * q_2$.

## Step 3.

The prime size is 1024 for the challenge, we need to set at least 1(Prime for Phase 1) + 1(Pseudo-Prime for Phase 2) + 10(10 random 1024-bit numbers that pass the Miller-Rabin test) + 8(Selected polynomial coefficients for Phase 2) = 20 1024-bit numbers, and they are over 19937 and there are more to set.

The prime number for Phase 1 must be set close to $2^{1024}$ to make `getRandomRange` not revert, and the pseudo-prime number for Phase 2 and polynomial coefficients MUST be fixed. Those 2 numbers should also be close to $2^{101}$. So my solution was to destroy *10 numbers that pass the Miller-Rabin test* a bit.

In summary, fix the important bits first, like:
- Phase 1: Modulus(Prime)
- Phase 1: 2 101-bit small prime numbers
- ~~Phase 1: 10 Miller-Rabin test numbers~~ (Doesn't need to be set because they will always pass because modulus is the actual prime)
- ~~Phase 1: Coefficients~~ (This gets automatically passed IF they are irreducible on the first try, so we have to brute force this until 2 selected random polynomials are irreducible on the first try. As an experimental result, I feel like at least 1 out of 5 random 4-degree polynomials is irreducible.)
- Phase 2: Modulus(Pseudo-Prime)
- Phase 2: 2 101-bit small prime numbers
- ~~Phase 2: 10 Miller-Rabin test numbers~~ (Need to be set, but later.)
- Phase 2: Coefficients

After that, we will have a lot of free bits left, because that will only use around 10000 bits. 10 Miller-Rabin test numbers for Phase 2's some bits must be fixed due to the previous fix, but all have free continuous chunks of bits. Making them pass the Miller-Rabin test afterward isn't so hard. However, one in 1600000 passes the Miller-Rabin test, so it will take some time to brute force. But with multi-core, it shouldn't be so hard, I assume it's doable in 10 minutes with 8-core.

Finally, brute-force with some bits left until Phase 1's selected polynomials are irreducible.

---

`solve.py` is just the final result of the difficult solution. I proved this is solvable, so I will leave the fun part to you. Maybe it will be nice to check what kind of numbers are appearing during the process after seeding the seed in `solve.py`.