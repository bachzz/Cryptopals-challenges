import sys
sys.path.insert(0, '../')
from my_crypto_lib import *

message = "Burning 'em, if you ain't quick and nimble\x0aI go crazy when I hear a cymbal"
length_hex=len(message)*2
key = "ICE"
keyDup=key_dup(key,len(message))

message_hex=ascii_to_hex(message).zfill(length_hex)
key_hex=ascii_to_hex(keyDup).zfill(length_hex)

result=fixed_XOR(message_hex,key_hex).zfill(length_hex)
print "Message:",message
print "Key:",key
print "Encrypted (hex):",result
