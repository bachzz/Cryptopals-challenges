"""If the attacker has access to the edit() function to write on the ciphertext,
    then it is easy to decrypt the underlying plaintext:
    Since we know that the edit() function will encrypt the new_text that we give it
    with the same keystream used in the original ciphertext (shifted by offset), we can
    simply set the offset to zero and then overwrite the underlying plaintext of our ciphertext
    to be the ciphertext itself. Because by encrypting the ciphertext again we will basically
    decrypt it (that's how AES CTR works), the edit will return to us the original plaintext!
"""

import sys
import os
import struct

sys.path.insert(0, './lib')
from my_crypto_lib import *

class Oracle:

    def __init__(self):
        self.key = os.urandom(16)

    def edit(self, ciphertext, offset, new_text):
        """Changes the underlying plaintext of the given ciphertext at offset so that it
        contains new_text. Returns the new corresponding ciphertext.
        """
        pt = self.decrypt(ciphertext)
        pt = pt[: offset] + new_text + pt[offset + len(new_text) :]
        ct = self.encrypt(pt)
        return ct

    def decrypt(self, ciphertext):
        """Decrypts the given plaintext with AES-CTR with a nonce of 0."""
        return aes_ctr_dec(ciphertext, self.key, "\x00")

    def encrypt(self, plaintext):
        """Encrypts the given plaintext with AES-CTR with a nonce of 0."""
        return aes_ctr_enc(plaintext, self.key, "\x00")

def break_random_access_read_write_aes_ctr(ciphertext, encryption_oracle):
    # Assume random key is still unknown, the attacker can control only offset and new_text
    # (given the ciphertext).
    return encryption_oracle.edit(ciphertext, 0, ciphertext)


with open("./txt/25.txt") as f:
    b64 = f.read()

    # Decrypt ciphertext in ECB mode with key "YELLOW SUBMARINE" (from challenge 7)
b64_ascii = base64_to_ascii(b64)
plaintext = aes_ecb_dec(b64_ascii, "YELLOW SUBMARINE")

    # Oracle is a service with edit(ciphertext, offset, new_text) function that allows attacker to change the underlying plaintext of the given ciphertext at offset so that it
    # contains new_text. Returns the new corresponding ciphertext.
oracle = Oracle()

    # Get the ciphertext and give it to the attacker
ciphertext = oracle.encrypt(plaintext)
cracked_plaintext = break_random_access_read_write_aes_ctr(ciphertext, oracle)

    # Check if the attack worked
assert plaintext == cracked_plaintext
print cracked_plaintext