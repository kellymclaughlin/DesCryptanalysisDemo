## Introduction
This project presents an implementation of a cryptanalytic attack against 
6-round DES. An attack on 6-round DES is a probabilistic attack. By
testing significantly many plaintext/ciphertext pairs, many of the key
bits become statistically apparent. This attack centers on the use of
characteristics. Please see [1] for a thorough discussion of characteristics
as they apply to differential cryptanalysis. Using the properties of the
characteristics and the known output from the last DES encryption round for
each pair of inputs, it is possible to work backwards to determine the key
bits that were XORed with the right-hand side of the output of the previous
round to form the SBox input. In this case, I use two characteristics that
allow the determination of 30 of the 56 key bits each (excluding parity bits).
This corresponds to the input to 5 different SBoxes. Unfortunately 3 of the
SBoxes (18 bits) for each characteristic overlap which leaves 42 bits that
are known and 14 bits yet to determine. From this point, however, it is very
simple to exhaustively search the remaining 2^14 possibilities and determine
the correct key.

In researching this project, most of the references contained a high level
description of the cryptanalysis on reduced round DES, but there were enough
details missing to make it unclear as to how the attack could actually be
implemented. This project is an attempt to show an implementation of the
attack that fills in some of the gaps left by other sources for anyone who
is new to this subject area.

To implement this attack, I first implemented the DES algorithm as described
in [1]. The implementation of the cryptanalysis followed after much studying
of [2] and [3].

## Building
The project can be built with ant using the provided build.xml file.
  `ant`

## Cleaning
  `ant clean`

## TODO
I'll soon have this code running somewhere publicly available.

## References

* [1] Eli Biham, Adi Shamir: Differential Cryptanalysis of DES-like Cryptosystems. CRYPTO 1990: 2-21
* [2] Eli Biham: Tutorial on Differenetial Cryptanalysis, 2005
* [3] Menezes, A. J., van Oorschot, P. C., and Vanstone, S. A. Handbook of Applied Cryptography. CRC Press, 1997