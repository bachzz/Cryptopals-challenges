'''def hex_to_binary(my_hex):
	num_of_bits = len(my_hex)*4
	hex_base = 16
	my_bin=bin(int(my_hex, hex_base))[2:].zfill(num_of_bits)
	return my_bin

def fixed_XOR(hex1,hex2): # len(hex1)=len(hex2)
	bin1=hex_to_binary(hex1)
	bin2=hex_to_binary(hex2)
	my_len=len(bin1)
	bin3=["" for i in range(my_len)]
	for i in range (my_len):
		if bin1[i]!=bin2[i]:
			bin3[i]='1'
		else:
			bin3[i]='0'
	bin3="".join(bin3)
	return "%x" % int(bin3,2)'''

import sys
sys.path.insert(0, '../')

from my_crypto_lib import *
	
hex1="1c0111001f010100061a024b53535009181c"
hex2="686974207468652062756c6c277320657965"
result=fixed_XOR(hex1,hex2)
print "Hex1: ",hex1
print "Hex2: ",hex2
print "After XOR: ",result



