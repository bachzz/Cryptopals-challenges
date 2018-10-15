### EXAPLAIN!
## Same as 29 with MD4 implementation

from random import randint
import sys


sys.path.insert(0, './lib')
from my_crypto_lib import *


class Oracle:

    def __init__(self):
        # Choose a random word from the dictionary to use as key
        with open("/usr/share/dict/words") as dictionary:
            candidates = dictionary.readlines()
            self._key = candidates[randint(0, len(candidates) - 1)].rstrip().encode()

    def validate(self, message, digest):
        """Checks if the given digest matches the keyed MD4-mac of the given message."""
        return MD4(self._key + message).hex_digest() == digest

    def generate_digest(self, message):
        """Generates a MD4 MAC digest using the secret key."""
        return MD4(self._key + message).hex_digest()


def md_pad(message):
    """Pads the given message the same way the pre-processing of the MD4 algorithm does."""
    ml = len(message) * 8

    message += b'\x80'
    message += bytes((56 - len(message) % 64) % 64)
    message += pack('<Q', ml)

    return message


def length_extension_attack(message, original_digest, oracle):
    """Performs a length extension attack on the MD4 keyed MAC, forging a variant of the given
    message that ends with ";admin=true". Returns the new message and its valid MAC digest.
    """
    extra_payload = b';admin=true'

    # Try multiple key lengths
    for key_length in range(100):

        # Get the forged message (original-message || glue-padding || new-message)
        # The bytes of the key are not relevant in getting the glue padding, since we only
        # care about its length. Therefore we can use any key for the padding purposes.
        forged_message = md_pad(b'A' * key_length + message)[key_length:] + extra_payload

        # Get the MD4 internal state (h1, h2, h3, h4) by reversing the last step of the hash
        h = unpack('<4I', unhexlify(original_digest))

        # Compute the MD4 hash of the extra payload, by setting the state of the MD4 function to the
        # cloned one that we deduced from the original digest.
        # We also set the message length ml to be the total length of the message.
        forged_digest = MD4(extra_payload, (key_length + len(forged_message)) * 8, h[0], h[1], h[2], h[3]).hex_digest()

        # If the forged digest is valid, return it together with the forged message
        if oracle.validate(forged_message, forged_digest):
            return forged_message, forged_digest

    # Otherwise it means that we didn't guess correctly the key length
    raise Exception("It was not possible to forge the message: maybe the key was longer than 100 characters.")


def main():
    oracle = Oracle()

    # Compute the original digest of the given message
    message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    message_digest = oracle.generate_digest(message)

    # Forge a variant of this message and get its valid MAC
    forged_message, forged_digest = length_extension_attack(message, message_digest, oracle)

    # Check if the attack works properly
    assert b';admin=true' in forged_message
    assert oracle.validate(forged_message, forged_digest)
    print "Original message:", message
    print "Forged message:", forged_message

if __name__ == '__main__':
	main()




# import struct
# import sys

# sys.path.insert(0, './lib')
# from my_crypto_lib import *
# from random import randint
# from struct import pack, unpack
# from binascii import unhexlify, hexlify

# def leftrotate(i, n):
#     return ((i << n) & 0xffffffff) | (i >> (32 - n))

# def F(x,y,z):
#     return (x & y) | (~x & z)

# def G(x,y,z):
#     return (x & y) | (x & z) | (y & z)

# def H(x,y,z):
#     return x ^ y ^ z

# class MD4():
#     #def __init__(self, data="", A=0x67452301, B=0xefcdab89, C=0x98badcfe, D=0x10325476):
#     def __init__(self, ml = None,A=0x67452301, B=0xefcdab89, C=0x98badcfe, D=0x10325476):
#     	if ml is None:
#     		self.ml = None
#     	else:
#     		self.ml = ml
#         self.remainder = ""
#         self.count = 0
#         self.h = [
#                 A,
#                 B,
#                 C,
#                 D
#                 ]

#     def _add_chunk(self, chunk):
#         self.count += 1
#         X = list( struct.unpack("<16I", chunk) + (None,) * (80-16) )
#         h = [x for x in self.h]
#         # Round 1
#         s = (3,7,11,19)
#         for r in xrange(16):
#             i = (16-r)%4
#             k = r
#             h[i] = leftrotate( (h[i] + F(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k]) % 2**32, s[r%4] )
#         # Round 2
#         s = (3,5,9,13)
#         for r in xrange(16):
#             i = (16-r)%4
#             k = 4*(r%4) + r//4
#             h[i] = leftrotate( (h[i] + G(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k] + 0x5a827999) % 2**32, s[r%4] )
#         # Round 3
#         s = (3,9,11,15)
#         k = (0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15) #wish I could function
#         for r in xrange(16):
#             i = (16-r)%4
#             h[i] = leftrotate( (h[i] + H(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k[r]] + 0x6ed9eba1) % 2**32, s[r%4] )

#         for i,v in enumerate(h):
#             self.h[i] = (v + self.h[i]) % 2**32

#     def add(self, data):
#         message = self.remainder + data
#         if self.ml is None:	
#         	#r = len(message) % 64
#         	r = len(message) * 8
#         else:
#         	r = self.ml
#         if r != 0:
#             self.remainder = message[-r:]
#         else:
#             self.remainder = ""
#         for chunk in xrange(0, len(message)-r, 64):
#             self._add_chunk( message[chunk:chunk+64] )
#         return self

#     def finish(self):
#         l = len(self.remainder) + 64 * self.count
#         self.add( "\x80" + "\x00" * ((55 - l) % 64) + struct.pack("<Q", l * 8) )
#         out = struct.pack("<4I", *self.h)
#         self.__init__()
#         return out


# message = "The quick brown fox jumps over the lazy dog"
# digest = MD4(message)
# #digest = MD4()
# #digest.add(message)
# print message
# #print ascii_to_hex(digest.finish())
# print digest.hex_digest()



# class Oracle:

#     def __init__(self):
#         # Choose a random word from the dictionary to use as key
#         with open("/usr/share/dict/words") as dictionary:
#             candidates = dictionary.readlines()
#             self._key = candidates[randint(0, len(candidates) - 1)].rstrip().encode()

#     def validate(self, message, digest):
#         """Checks if the given digest matches the keyed MD4-mac of the given message."""
#         #return MD4(self._key + message).hex_digest() == digest
#         st = ascii_to_hex(MD4().add(self._key + message).finish())
#         print st, digest
#         #print st
#         #return ascii_to_hex(MD4().add(self._key + message).finish()) == digest
#         return st == digest

#     def generate_digest(self, message):
#         """Generates a MD4 MAC digest using the secret key."""
#         #return MD4(self._key + message).hex_digest()
#         return ascii_to_hex(MD4().add(self._key + message).finish())


# def md_pad(message):
#     """Pads the given message the same way the pre-processing of the MD4 algorithm does."""
#     ml = len(message) * 8

#     message += b'\x80'
#     message += bytes((56 - len(message) % 64) % 64)
#     message += pack('<Q', ml)

#     return message


# def length_extension_attack(message, original_digest, oracle):
#     """Performs a length extension attack on the MD4 keyed MAC, forging a variant of the given
#     message that ends with ";admin=true". Returns the new message and its valid MAC digest.
#     """
#     extra_payload = b';admin=true'

#     # Try multiple key lengths
#     for key_length in range(100):

#         # Get the forged message (original-message || glue-padding || new-message)
#         # The bytes of the key are not relevant in getting the glue padding, since we only
#         # care about its length. Therefore we can use any key for the padding purposes.
#         forged_message = md_pad(b'A' * key_length + message)[key_length:] + extra_payload

#         # Get the MD4 internal state (h1, h2, h3, h4) by reversing the last step of the hash
#         h = unpack('<4I', unhexlify(original_digest))

#         # Compute the MD4 hash of the extra payload, by setting the state of the MD4 function to the
#         # cloned one that we deduced from the original digest.
#         # We also set the message length ml to be the total length of the message.
#         #forged_digest = MD4(extra_payload, (key_length + len(forged_message)) * 8, h[0], h[1], h[2], h[3]).hex_digest()
#         md4 = MD4((key_length + len(forged_message)) * 8, h[0], h[1], h[2], h[3])
#         forged_digest = ascii_to_hex(md4.add(extra_payload).finish())
#         # If the forged digest is valid, return it together with the forged message
#         if oracle.validate(forged_message, forged_digest):
#             return forged_message, forged_digest

#     # Otherwise it means that we didn't guess correctly the key length
#     raise Exception("It was not possible to forge the message: maybe the key was longer than 100 characters.")


# def main():
#     oracle = Oracle()

#     # Compute the original digest of the given message
#     message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
#     message_digest = oracle.generate_digest(message)

#     # Forge a variant of this message and get its valid MAC
#     forged_message, forged_digest = length_extension_attack(message, message_digest, oracle)

#     # Check if the attack works properly
#     assert b';admin=true' in forged_message
#     assert oracle.validate(forged_message, forged_digest)


# if __name__ == '__main__':
# 	main()