### EXPLAIN!!!

## The server has services:
##		- Format request (along with default, hidden session id)
##		- Compress formatted request using "zlib"
##		- Encrypt compressed data using CTR or CBC mode => then return the final length
##
## Attacker will:
##		- Send any request (any content)
##		- Recover hidden session id (knowing only the length of encrypted, compressed, formatted request)
##
## How?
##		- Just know this: the more repeated strings in data, the better (return smaller length)
##		  				  zlib compresses data
##		- Using that fact, brute-force session-id byte-by-byte with alphabet characters (the correct byte will 
##		  reduce the most length of data)
##			+ In CTR mode, just like that.
##			+ In CBC mode, using the same fact to brute-force padding bytes with these characters
##			  '!@#$%^&*()-`~[]{}', and at the same time also brute-force session id


import string
import os
import zlib
import sys


sys.path.insert(0, './lib')
from my_crypto_lib import *

sessionid = 'TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE='
alphabet = string.ascii_letters + string.digits + '+/='
padding_alphabet = '!@#$%^&*()-`~[]{}'

def format_request(P):
    return "POST / HTTP/1.1\nHost: hapless.com\nCookie: sessionid={0}\nContent-Length: {1}\n{2}".format(sessionid, len(P), P)

def oracle_ctr(P):
	# Format request (P: any content)
    request = format_request(P)
    # Compress request
    compressed_request = zlib.compress(request.encode('ascii'))
    # Encrypt request in CTR mode
    key = os.urandom(16)
    encrypted_request = aes_ctr_enc(compressed_request, key, "\x00")
    return len(encrypted_request)


def oracle_cbc(P):
	# Format request (P: any content)
    request = format_request(P)
    # Compress request
    compressed_request = zlib.compress(request.encode('ascii'))
    # Encrypt request in CBC mode
    key = os.urandom(16)
    iv = os.urandom(16)
    aes_cbc_enc2(pkcs7_padding(compressed_request), key, iv)
    return len(encrypted_request)

def getPadding(oracle, s):
    l = oracle(s)
    padding = ''

    # brute-force "paddingAlphabet"
    for i in range(len(padding_alphabet)):
        padding += padding_alphabet[i]
        il = oracle(s+padding)# + s)
        if il > l:
            return padding

def guess_next_byte(oracle, knownStr):
    min_ch = ''
    min_ch_sz = 0

    # (for CBC mode) getPadding same as guess next character
    padding = getPadding(oracle, ('sessionid=' + knownStr + '~') * 8)
    
    # brute-force alphabet to get byte by byte (the character which is also in session key 
    #											will reduce compression length -> the character which returns
    #											smallest length will be the chosen one)
    for i in range(len(alphabet)):
        ch = alphabet[i]
        s = 'sessionid=' + knownStr + ch
        sz = oracle(padding + s* 8)
        if min_ch == '' or sz < min_ch_sz:
            min_ch = ch
            min_ch_sz = sz
    return min_ch

def recover_sessionid(oracle):
    knownStr = ''
    for i in range(0, 44):
        knownStr += guess_next_byte(oracle_ctr, knownStr)
    return knownStr

recovered_sessionid = recover_sessionid(oracle_ctr)
if recovered_sessionid != sessionid:
    raise Exception(recovered_sessionid + ' != ' + sessionid)
print "CTR mode: " + base64_to_ascii(recovered_sessionid)

recovered_sessionid = recover_sessionid(oracle_cbc)
if recovered_sessionid != sessionid:
    raise Exception(recovered_sessionid + ' != ' + sessionid)
print "CBC mode: " + base64_to_ascii(recovered_sessionid)

# message = "Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="
# message2 = "Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\nsessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="
# message3 = "sessionid"
# message_compressed = zlib.compress(message)
# message_compressed2 = zlib.compress(message2)
# message_compressed3 = zlib.compress(message3)
# print message_compressed, len(message_compressed)
# print message_compressed2, len(message_compressed2)
# print message_compressed3, len(message_compressed3)
