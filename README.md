### aez - AEZ (Duh)
#### Yawning Angel (yawning at schwanenlied dot me)

This is an implementation of [AEZ](http://web.cs.ucdavis.edu/~rogaway/aez/),
primarily based on the reference code.  It appears to be correct and the
output matches [test vectors](https://github.com/nmathewson/aez_test_vectors)
derived with the reference code.

**WARNING: This implementation is NOT CONSTANT TIME**

There have been some minor attempts at optimization, primarily for the lols.
I may add AES-NI support, but the "correct" way to do that is AES-NI.  If Go
had intrinsics I'd jump all over that, but writing basically all of AEZ-Core
in the fucked up asembly dialect is not my idea of fun.
