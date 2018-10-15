### EXPLAIN!
## WHAT WE HAVE?
    # A server: 
        # handles request: "http://localhost:8888/test?file=XXX&signature=XXX" || client inputs XXX
        # Validate the digest of filename with the signature (insecurely) by checking byte-by-byte with delay time and stops at incorrect byte
    # A client:
        # Recover the digest byte-by-byte with timing attack
## GOAL?
    # Recover the digest byte-by-byte with timing attack
## HOW?
    # Iterate through all possible bytes (0 - 15 <=> 0 - F), making a request with my known bytes + byte_guess + padding.
    # Take the maximum delay each time, which would occur when I've guessed the byte correctly, causing another sleep of 50ms, for an added delay of 100ms.
    # The byte with maximum delay each time is the correct byte for a position in digest
    # Append that byte to known bytes (found bytes) and brute-force next byte

import web
import time
import sys


sys.path.insert(0, './lib')
from my_crypto_lib import *


DELAY = 0.05
key = "YELLOW SUBMARINE"

# def hmac_sha1(key, message): 
# 	blockSize = 64  # the block size of the underlying hash function (e.g. 64 bytes for SHA-1)
# 	outputSize = 20	 # the output size of the underlying hash function (e.g. 20 bytes for SHA-1)

# 	# Keys longer than blockSize are shortened by hashing them
# 	if len(key) > blockSize:
# 		key = sha1(key)
# 	# Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
# 	if len(key) < blockSize:
# 		key += "\x00" * (blockSize - len(key))

# 	o_key_pad = xor(key, "\x5c" * blockSize)     # Outer padded key
#    	i_key_pad = xor(key, "\x36" * blockSize)    # Inner padded key

#    	return sha1(o_key_pad + sha1(i_key_pad + message))
def hmac_sha1(key, message):
    """Returns the HMAC-SHA1 for the given key and message. Written following Wikipedia pseudo-code."""

    if len(key) > 64:
        key = unhexlify(sha1(key))
    if len(key) < 64:
        key += b'\x00' * (64 - len(key))

    o_key_pad = xor(b'\x5c' * 64, key)
    i_key_pad = xor(b'\x36' * 64, key)

    return sha1(o_key_pad + unhexlify(sha1(i_key_pad + message)))

def insecure_validate(digest, sig):
	for i in range(len(digest)):
		if digest[i] != sig[i]:
			return False
		time.sleep(DELAY)
	return True

urls = (
    #'/', 'index',
    '/test', 'handle'
)


class handle:
    def GET(self):
    	data = web.input(file = "foo", signature = "46b4ec586117154dacd49d664e5d63fdc88efb51")
        filename = data.file # secret filename
        signature = data.signature # signature to verify with filename's digest
        digest = hmac_sha1(key, str(filename))
        print digest
        check = insecure_validate(digest, signature)
        message = "Filename's digest is: " + digest + "\nyour signature is: " + signature + "\n" + str(check)
        #return message
        if check:
        	return message
        else:
        	return web.internalerror("Nice try, kid.")

        

class MyApplication(web.application):
    def run(self, port=8080, *middleware):
        func = self.wsgifunc(*middleware)
        return web.httpserver.runsimple(func, ('0.0.0.0', port))

if __name__ == "__main__":
    app = MyApplication(urls, globals())
    app.run(port=8888)