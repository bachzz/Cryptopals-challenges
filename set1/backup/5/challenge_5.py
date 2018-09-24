def hex_to_binary(my_hex):
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
	return "%x" % int(bin3,2)

def ascii_to_hex(string):
	return string.encode("hex")

def hex_to_ascii(string):
	return string.decode("hex")

def key_dup(key,length): # fill a string repeatedly with key
	result=["" for i in range(length)]
	for i in range(0,length,len(key)):
		for j in range(0,len(key)):
			if i+j<length:
				result[i+j]=key[j]
	return "".join(result)			

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
