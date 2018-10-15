### EXPLAIN!!!

## When signing a message using RSA:
##	 	- User generates signature using (n, d): sig = m ^ d mod n
##		- Server verifies signature using (n, e): (sig ^ e mod n) == m
## In this challenge, instead of signing message, m, we sign the PKCS1.5 encoding of message's hash:
##			00 01 FF FF ... FF 00 ASN.1 HASH
## How to exploit?
##		- A faulty PKCS1.5 verifier might not check all "FF" bytes in middle exist
## 		- We can generate "corrupted" PKCS1.5:
## 			00 01 FF 00 ASN.1 HASH GARBAGE
##		=> Correct signature will be the cube root of that 

import re
import sys


sys.path.insert(0, './lib')
from my_crypto_lib import *

ASN1_SHA1 = "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"

class Oracle(RSA):
    def sign(self, message):
        message_int = int(ascii_to_hex(message), 16)
        message_pkcs15 = "\x00\x01\xFF\xFF\xFF\xFF\xFF\xFF\x00" + message_int
        return self.decrypt(message_pkcs15)
    def verify(self, encrypted_signature, message):
        # Decrypt the given encrypted signature
        signature = "\x00" + hex_to_ascii("%x" % self.encrypt(encrypted_signature))
        # Verify that the signature contains a block in PKCS1.5 standard format (vulnerable implementation)
        r = re.compile("\x00\x01\xff+?\x00.{15}(.{20})", re.DOTALL)
        m = r.match(signature)
        if not m:
            return False
        # Take the hash part of the signature and compare with the server-computed hash
        hashed = m.group(1)
        return hashed == unhexlify(sha1(message))


def forge_signature(message, key_length):
    """Forges a valid RSA signature for the given message using the Bleichenbacher's e=3 RSA Attack."""

    # Prepare the block which will look like PKCS1.5 standard format to the vulnerable server
    block = "\x00\x01\xff\x00" + ASN1_SHA1 + unhexlify(sha1(message))
    garbage = "\x00" * (((key_length + 7) // 8) - len(block))
    block += garbage
    # Get the int version of the block and find its cube root (emulating the signing process)
    pre_encryption = int(ascii_to_hex(block), 16)#int.from_bytes(block, byteorder='big')
    forged_sig = find_cube_root(pre_encryption)
    forged_sig_hex = "%x" % forged_sig
    # Convert the signature to bytes and return it
    return hex_to_ascii(forged_sig_hex)#int_to_bytes(forged_sig)

oracle = Oracle(1024)
message = "hi mom"
forged_sig = forge_signature(message, 1024)

print "Message:", message
print "Forged sinature:", forged_sig
if oracle.verify(forged_sig, message):
	print "Correct signature! Welcome back."
else:
	print "Wrong signature! You'll be reported to an authority."

