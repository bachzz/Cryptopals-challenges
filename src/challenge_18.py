### EXPLAIN! 
## pic 1 https://upload.wikimedia.org/wikipedia/commons/thumb/4/4d/CTR_encryption_2.svg/601px-CTR_encryption_2.svg.png
## pic 2 https://upload.wikimedia.org/wikipedia/commons/thumb/3/3c/CTR_decryption_2.svg/601px-CTR_decryption_2.svg.png
## CTR parameters: 
		#key=YELLOW SUBMARINE
      	#nonce=0
      	#format=64 bit unsigned little endian nonce,
        #     64 bit little endian block count (byte count / 16)

import sys
sys.path.insert(0, './lib')
from my_crypto_lib import *

key = "YELLOW SUBMARINE"
ct_b64 = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
ct_ascii = base64_to_ascii(ct_b64)

pt = aes_ctr_dec(ct_ascii,key,"\x00")
print "Original ciphertext base64:",ct_b64
print "AES in CTR mode decrypted:",pt
ct = aes_ctr_enc(pt,key,"\x00")
print "AES in CTR mode encrypted:",ct

#print len(b64_ascii)

