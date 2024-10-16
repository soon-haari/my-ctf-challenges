# RSAjail-1

1-byte limit bans two important things: `//` and `:=`. We have implement division ourselves, using `%, >` operators, or any other way. But more importantly without `:=`, we can't freely assign values into variables.

`_` is a key solution to this problem.

```python
>>> 1234
1234
>>> _
1234
>>> (1, 2, 3, 4)
(1, 2, 3, 4)
>>> _
(1, 2, 3, 4)
```

`_` saves the previous return value(if successful) and doesn't matter what type it is. So we can use `_` as a storage of multiple variables. It is a little bit painful to implement, but not *very* much different from 2-byte solution, except we have to implement division.