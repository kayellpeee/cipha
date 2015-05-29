##cipha

small ciphering library. encrypt & decrypt functions

###architecture
Block ciphers encrypt small parts of data using a different subkey for each
round of encryption. Fiestel cipher (network ?) splits the data in two and
encrypts half, which is then used with the other half in the next round of
encryption. Descryption simply requires flipping the order of subkeys (after
aligning halves).

You can make this more secure using pads on 1 half (or both) of the data.
(pad being random genrated junk data before encryption. Ignored when decrypted)
More goes into probilistic encryption (trapdoor fn) - useful when using public
key encryption

Symetric key encryption just means same key is used for encryption & decryption
Asymetric encrypts against a public key but private key is required for
decryption (relationship b/w both keys required?)

stream cipher can't use multiple rounds of encryption\*...do they "stack"
incoming data onto already encrypted data?? decryption?

\* not like Fiestel cipher at least

Currently won't actually encrypt anything because
 - overflowing utf8 (maybe?)
 - bit shifting overflow
 - direct add is xor —- will probably have to change this or overflow bit shift

bit shifting with overflow is suspect because it easily arrives at the starting
values (overflow left or right 3 places for 'size 3' bit remains unchanged)
...and then xor'ing with the same values doesn't do anything...

###planned features

Fiestel cipher
probabilistic encryption
trapdoor fn (for more secure probabilistic encryption) (primes)
symetric key encryption
asymetric key encryption (public key)
stream cipher (RIP block cipher - hopping on that codata)
