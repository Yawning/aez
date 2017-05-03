### aez - AEZ (Duh)
#### Yawning Angel (yawning at schwanenlied dot me)

This is an implementation of [AEZ](http://web.cs.ucdavis.edu/~rogaway/aez/),
primarily based on the reference code.  It appears to be correct and the
output matches [test vectors](https://github.com/nmathewson/aez_test_vectors).

**WARNING: This implementation is NOT ALWAYS CONSTANT TIME**

If you're on AMD64 with AES-NI, it is constant time, and the performance is
fairly good.  Otherwise, why are you looking at this, over alternatives that
don't use the AES round function?
