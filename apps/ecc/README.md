ECC-app
===========
This contains the Elliptic Curve Cryptography app and the Arbitrary Precision Arithmetics Library used. In the makefile using the compile flags it can be selected which coordinates for the ECC calculations are going to be used: 
CFLAGS += -DJACOBIAN_COORDINATES or AFFINE_COORDINATES or HOMOGENEOUS_COORDINATES
Also can be selected the use of SLIDING_WINDOW for the scalar multiplication operation #CFLAGS += -DSLIDING_WINDOW.
The size of the used words for the big integer library is also defined by the flags: WORDS_32_BITS or WORDS_16_BITS.
Finally the number of words used is defined with NUMWORDS=X. So, for example, with 32 bit words, for a 256 bits keys it should be set WORDS_32_BITS and NUMWORDS=8.