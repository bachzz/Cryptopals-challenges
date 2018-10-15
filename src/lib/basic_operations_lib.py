import base64

				### --- COMMON CONVERSIONS --- ###

def hex_to_binary(my_hex):
	num_of_bits = len(my_hex)*4
	hex_base = 16
	my_bin=bin(int(my_hex, hex_base))[2:].zfill(num_of_bits)
	return my_bin

def ascii_to_hex(string):
	return string.encode("hex")

def hex_to_ascii(string):
	if len(string) % 2 != 0:
		string = string.zfill(len(string)+1)
	return string.decode("hex")

def base64_to_hex(b64):
	text = base64.b64decode(b64)
	my_hex = ascii_to_hex(text)
	return my_hex

def hex_to_base64(my_hex):
	text=hex_to_ascii(my_hex)
	b64=base64.b64encode(text)
	return b64

def base64_to_ascii(b64):
	return base64.b64decode(b64)

				### --- KEY DUPLICATE --- ###
				
def key_dup(key,length): # fill a string repeatedly with key
	result=["" for i in range(length)]
	for i in range(0,length,len(key)):
		for j in range(0,len(key)):
			if i+j<length:
				result[i+j]=key[j]
	return "".join(result)


				### --- XOR OPERATIONS --- ###

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

# def xor(ascii1,ascii2): # return ascii
# 	hex1=ascii_to_hex(ascii1)
# 	hex2=ascii_to_hex(ascii2)
# 	return hex_to_ascii(fixed_XOR(hex1,hex2).zfill(len(hex1)))

def xor(a, b):
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

def xor2(binary_data_1, binary_data_2):
    """Returns the xor of the two binary arrays given."""
    return bytes([b1 ^ b2 for b1, b2 in zip(binary_data_1, binary_data_2)])

def single_byte_XOR(string,byte):	
	string2=key_dup(byte,len(string)) 
	return fixed_XOR(string,string2)
	
				### --- DETECT CIPHER --- ###

def get_block_size(enc_func,data):
	ct_length = len(enc_func(data))
	i = 1
	while True:
		data2 = data + "A"*i
		new_ct_length = len(enc_func(data2))
		block_size = new_ct_length - ct_length
		if block_size:
			return block_size
		i += 1
