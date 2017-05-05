### aez - AEZ (Duh)
#### Yawning Angel (yawning at schwanenlied dot me)

This is an implementation of [AEZ](http://web.cs.ucdavis.edu/~rogaway/aez/),
primarily based on the reference code.  It appears to be correct and the
output matches [test vectors](https://github.com/nmathewson/aez_test_vectors).

Features:

 * Constant time, always.
 * Will use AES-NI if available on AMD64.
 * Unlike the `aesni` code, supports vectorized AD, nbytes > 16, and tau > 16.
