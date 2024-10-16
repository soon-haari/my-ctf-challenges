# RSAjail-2

2-byte limit pretty much allowes everything from the solution for the previous challenge, except the function `pow`. So in this challenge, we have to implement `pow` function ourselves, specifically XGCD for inverse, and square-and-multiply method for $O(\log(N))$ exponentiation.

`:=` keyword is helpful to assign values.