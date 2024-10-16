# RSAjail-3

The fact Python language allows multiple lines for braces makes this challenge easy(a solution without braces might be possible using `_`, but it is used in the 1-byte version so we don't want to reveal that.).

The following is an actual working script for Python, and the solution to this challenge.
```python
(
q:=
N//
p,
phi
:=(
p-1
)*(
q-1
),
d:=
pow
(2
**
16+
1,
-1,
phi
),
m:=
pow
(c,
d,N
))
X(
m)
```