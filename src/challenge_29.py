### QUESTION ! Why not simply get the forged message's digest using the oracle?
### EXPLAIN!!
## WHAT WE HAVE?
    # An oracle - a service using SHA1-MAC to:
        # Generate a SHA1 MAC digest for a message using a secret key
        # Check the given digest matches the SHA1 MAC of a message
## GOAL?
    # Modify a message in-flight provided with its digest -> forge a new message containing extra payload (e.g: 'admin=true')
# HOW?
    # To break SHA1 MAC, we need to get its padding state (pre-processing state), after forged the new message, and the internal state (h0,h1,h2,h3,h4)  
    # Brute-force key-length until forged digest is the same as digest of forged message:
        # Get the forged message (original-message || glue-padding || new-message)
                                                    # glue-padding? Pads the given message the same way the pre-processing of the SHA1 algorithm does.
        # Get the SHA1 internal state (h1, h2, h3, h4, h5) by reversing the last step of the hash
        # Get SHA1 hash of the extra payload, by setting the state of the SHA1 function to the cloned one that we deduced from the original digest.
        # If the forged digest is valid, return it together with the forged message.
        # Else, keep brute-forcing

import struct
import sys


sys.path.insert(0, './lib')
from my_crypto_lib import *
from random import randint
from binascii import unhexlify

class Oracle:

    def __init__(self):
        # Choose a random word from the dictionary to use as key
        with open("/usr/share/dict/words") as dictionary:
            candidates = dictionary.readlines()
            self._key = candidates[randint(0, len(candidates) - 1)].rstrip().encode()

    def validate(self, message, digest):
        """Checks if the given digest matches the keyed SHA1-mac of the given message."""
        return sha1_mac(self._key, message) == digest

    def generate_digest(self, message):
        """Generates a SHA1 MAC digest using the secret key."""
        return sha1_mac(self._key, message)


def glue_padding(message):
    """Pads the given message the same way the pre-processing of the SHA1 algorithm does."""
    ml = len(message) * 8
    message += b'\x80'
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'

    message += struct.pack('>Q', ml)
    return message


def length_extension_attack(message, original_digest, oracle):
    """Performs a length extension attack on the SHA1 keyed MAC, forging a variant of the given
    message that ends with ";admin=true". Returns the new message and its valid MAC digest.
    """
    extra_payload = b';admin=true'
    for key_length in range(100):

        # Get the forged message (original-message || glue-padding || new-message)
        # We care only about key length -> Use any key for glue-padding purpose
        forged_message = glue_padding(b'A' * key_length + message)[key_length:] + extra_payload

        # Get the internal state (h1, h2, h3, h4, h5)
        h = struct.unpack('>5I', unhexlify(original_digest))
        
        # Get SHA1 hash of the extra payload, by setting the state of the SHA1 function to the
        # cloned one that we deduced from the original digest.
        forged_digest = sha1(extra_payload, (key_length + len(forged_message)) * 8, h[0], h[1], h[2], h[3], h[4])

        # If the forged digest is valid, return it together with the forged message
        if oracle.validate(forged_message, forged_digest):
            #print ord(unhexlify(original_digest)[5])
            result = {
                "message": forged_message,
                "digest": forged_digest
            }
            return result

    raise Exception("Unable to forge the message")


oracle = Oracle()

# Compute the original digest of the given message
message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
message_digest = oracle.generate_digest(message)

# Forge a variant of this message and get its valid MAC
result = length_extension_attack(message, message_digest, oracle)
forged_message = result["message"]
forged_digest = result["digest"]

# Check if the attack works properly
assert b';admin=true' in forged_message
assert oracle.validate(forged_message, forged_digest)
print "Original message:", message
print "Forged message:", forged_message
