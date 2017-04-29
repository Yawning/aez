### aez - AEZ (Duh)
#### Yawning Angel (yawning at schwanenlied dot me)

This is an implementation of [AEZ](http://web.cs.ucdavis.edu/~rogaway/aez/),
primarily based on the reference code.  It appears to be correct and the
output matches [test vectors](https://github.com/nmathewson/aez_test_vectors).

**WARNING: This implementation is NOT ALWAYS CONSTANT TIME**

There have been some minor attempts at optimization, primarily for the lols,
and it actually is constant time on AMD64 assuming AES-NI is present.  To
showcase the true potential of the primitive, much more assembly is needed.
