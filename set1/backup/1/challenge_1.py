def hex_to_binary(my_hex):
	num_of_bits = len(my_hex)*4
	hex_base = 16
	my_bin=bin(int(my_hex, hex_base))[2:].zfill(num_of_bits)
	return my_bin

def base64_to_hex(base64):
		# BASE64 TABLE
	base64_table=["" for i in range(64)]
	base64_table[0]="A"
	for i in range(1,26):
		base64_table[i]=chr(ord(base64_table[i-1])+1)
	base64_table[26]="a"
	for i in range(27,52):
		base64_table[i]=chr(ord(base64_table[i-1])+1)
	base64_table[52]="0"
	for i in range(53,62):
		base64_table[i]=chr(ord(base64_table[i-1])+1)
	base64_table[62]="+"
	base64_table[63]="/"
		# Convert to hex
	my_bin=["" for i in range(len(base64)*6)]
	j=0
	for i in range(len(base64)):
		my_int=base64_table.index(base64[i])
		my_bin[j]=bin(my_int)[2:].zfill(6)
		j+=1
	my_bin="".join(my_bin)
	my_hex="%x" % int(my_bin,2)
	return my_hex

def hex_to_base64(my_hex):
	num_of_bits = len(my_hex)*4
	# BINARY
	my_bin=hex_to_binary(my_hex)
	# BASE64
		# BASE64 TABLE
	base64_table=["" for i in range(64)]
	base64_table[0]="A"
	for i in range(1,26):
		base64_table[i]=chr(ord(base64_table[i-1])+1)
	base64_table[26]="a"
	for i in range(27,52):
		base64_table[i]=chr(ord(base64_table[i-1])+1)
	base64_table[52]="0"
	for i in range(53,62):
		base64_table[i]=chr(ord(base64_table[i-1])+1)
	base64_table[62]="+"
	base64_table[63]="/"
		# CONVERT HEX TO BASE64
	base64=["" for i in range(num_of_bits/6)]
	j=0
	for i in range (0,num_of_bits,6):
		bits=my_bin[i:i+6]
		val=int(bits,2)
		base64[j]=base64_table[val]
		j+=1
	return base64

# HEX
my_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
# CONVERT
result=hex_to_base64(my_hex)
# DISPLAY
print "Hex: ", my_hex
print "Base64: ",
print "".join(result)
#print my_hex.decode("hex")
