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

Currently encrypts to Vec<u32>
- xor is standard - ["⊕ denotes exclusive or (XOR)"](http://en.wikipedia.org/wiki/Hash-based_message_authentication_code#Definition_.28from_RFC_2104.29)
- xor allows same round function to be used in both decryption & encryption
- encryption logic now lies in round function & key generation
- round fn should change to be more hash-y (not just add)
- subkey & keys should be more secret-y (true hash not u32, u8)
  - larger and hex encoded

###tests

*no longer the case - fixed by [791914c5](https://github.com/kayellpeee/cipha/commit/791914c5e5b4c400587e384603e15d5b5e1e0aa7)*

for some reason it's failing on odd rounds with an odd length message
... must have something to do with the order or inputs/xor-ing (left/right)
hm, well if they're odd in length then there's one byte that floats on the end
and if they're encrypted for an odd amount of rounds then what was originally
left becomes right & vice versa...in order to have original left end up left it
must enter decryption as right (reverse order) and then exit flipped again
The fn already does that though.
```
 [L:a]  [R:b]                                       [L:b]   [R:a]
    \   /                                               \   /
      x                                                   x
    /   \                                               /   \
 [L:b]  [R:a]     <- an odd round encryption        [L:a]   [R:b]
    \   /            an odd round decryption ->         \   /
      x                                                   x
    /   \                                               /   \
 [L:a] [R:b]                                        [L:b]   [R:a]

  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *

 [L:a]  [R:b]                                       [L:b]   [R:a]
    \   /        <- an even round encryption            \   /
      x             an even round decryption ->           x
    /   \                                               /   \
 [L:b]  [R:a]                                       [L:a]   [R:b]
```
\* `A/a B/b` denotes original left and right respectively, obviously they will
mutate as they get passed around. Not intended to show same values.

So if a message is encrypted for an odd amount of rounds, it either needs to
*not* flip the order before decrypting, or it needs to flip before and after
decrypting i.e.:
```
  A       B  reverse input from encryption output ->    A   B
  |       |                                               x
 [L:a]  [R:b]                                       [L:b]   [R:a]
    \   /                                               \   /
      x                                                   x
    /   \                                               /   \
 [L:b]  [R:a]     <- an odd round encryption        [L:a]   [R:b]
    \   /            an odd round decryption ->         \   /
      x                                                   x
    /   \                                               /   \
 [L:a] [R:b]                                        [L:b]   [R:a]
  |      |                                                x
  A      B   reverse before reconstructing message ->   A   B

                            *or*

  A       B  same input from encryption output ->    A        B
  |       |                                          |        |
 [L:a]  [R:b]                                       [L:a]   [R:b]
    \   /                                               \   /
      x                                                   x 
    /   \                                               /   \
 [L:b]  [R:a]     <- an odd round encryption        [L:b]   [R:a]
    \   /            an odd round decryption ->         \   /
      x                                                   x 
    /   \                                               /   \
 [L:a] [R:b]                                        [L:a]   [R:b]
  |      |                                           |        |
  A      B   same before reconstructing message ->   A        B
```
Fn currently flips before & after but not sure why that works for even length
messages encrypted an odd amount of rounds but not for odd length messages an
odd amount of rounds...

AHHHHHHhhhhh so when message is odd in length, right contains 1 more byte than
left. And if fn reverses inputs to decrypt then the wrong side contains the
additional byte. So either change the index at which feistel_decrypt splits the
message at, or don't reverse the inputs before feeding it

... why did I do that in the first place?...
oh, I think it was because of [this picture](http://commons.wikimedia.org/wiki/File:Feistel_cipher_diagram_en.svg#/media/File:Feistel_cipher_diagram_en.svg)
which I definitely misinterpreted ["Commonly the two pieces R_n and L_n are not
switched after the last round."](http://simple.wikipedia.org/wiki/Feistel_cipher)

Dunno, I'll try both, see what works and try to rationalize it

*update*

Only fix was to change the index in which decryption function splits the
ciphertext. Simply not flipping the inputs didn't work (neither fliping before &
after decrypting, nor that in addition to after encrypting passed the tests).

Consider the order of subkeys:
```
                                                        A'''B'''
                                                          x
    A   B    <------- 1                 3  ------->     B'''A'''
    |   |                   subkeys:                   |     |
 [L:a]  [R:b]                                       [L:b]   [R:a]
    \   /                                               \   /
      x                                                   x
    /   \                                               /   \
   B'    A'  <------- 2                 2  ------->    A''   B''
   |     |                                             |     |
 [L:b]  [R:a]                                       [L:a]   [R:b]
    \   /                                               \   /
      x                                                   x
    /   \                                               /   \
   A''   B'' <------- 3                 1  ------->    B'    A'
   |     |                                             |     |
 [L:a] [R:b]                                        [L:b]   [R:a]
   |     |                                                x
   A'''  B'''                                           A   B
```
\* L[n] = R[n-2] i.e. A'' == B'
The only difference between encryption & decryption is the order of the subkeys.
This (poor) feistel_decrypt implementatino swaps before & after it runs because
it must ensure the same right sides are encrypted with the same subkeys


###planned features

- Fiestel cipher (currently implemented, just pretty poorly)
- probabilistic encryption
- trapdoor fn (for more secure probabilistic encryption) (primes)
- symetric key encryption
- asymetric key encryption (public key)
- stream cipher (RIP block cipher - hopping on that codata)
