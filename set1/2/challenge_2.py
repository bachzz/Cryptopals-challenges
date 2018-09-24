import sys
sys.path.insert(0, '../')

from my_crypto_lib import *
	
hex1="1c0111001f010100061a024b53535009181c"
hex2="686974207468652062756c6c277320657965"
result=fixed_XOR(hex1,hex2)
print "Hex1: ",hex1
print "Hex2: ",hex2
print "After XOR: ",result



