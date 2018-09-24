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
	return string.decode("hex")

def base64_to_hex(b64):
	text = base64.b64decode(b64)
	my_hex = ascii_to_hex(text)
	return my_hex

def hex_to_base64(my_hex):
	text=hex_to_ascii(my_hex)
	b64=base64.b64encode(text)
	return b64

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

def single_byte_XOR(string,byte):
	string2=[byte for i in range(len(string)/2)] # duplicate bytes => 
	string2="".join(string2)					 # len(bytes)=len(string)	
	return fixed_XOR(string,string2)

					### --- BREAK SINGLE-BYTE KEY XOR --- ###	
	
# chatacters frequency
letter_scores = {
    'e': 27,
    't': 26,
    ' ': 25,
    'a': 24,
    'o': 23,
    'i': 22,
    'n': 21,
    's': 20,
    'h': 19,
    'r': 18,
    'd': 17,
    'l': 16,
    'u': 15,
    'c': 14,
    'm': 13,
    'f': 12,
    'g': 11,
    'y': 10,
    'p': 9,
    'b': 8,
    'v': 6,
    'k': 5,
    'j': 4,
    'x': 3,
    'q': 2,
    'z': 1,
}

def englishness(str):
    score = 0
    for i in range(0, len(str), 1):
        c = str[i].lower()
        if c in letter_scores:
            score += letter_scores[c]
    return score

def break_single_byte_xor(encoded,dec_start,dec_end): # dec_start: decimal value of first char
	max_score=0										  # dec_end: decimal value of final char
	true_key=0
	message=0

	for i in range(dec_start,dec_end): # Brute-force key from ascii(dec_start)->ascii(dec_end)
		key=hex(i)[2:]
		result=single_byte_XOR(encoded,key).zfill(len(encoded)).decode("hex")
		if englishness(result)>max_score:
			max_score=englishness(result)
			true_key=key
			message=result
	result={
		'key':true_key.decode("hex"),
		'message':message
	}
	return result

				### --- IMPLEMENT / BREAK REPEATING-KEY XOR (VIGENER's cipher) --- ###

def key_dup(key,length): # fill a string repeatedly with key
	result=["" for i in range(length)]
	for i in range(0,length,len(key)):
		for j in range(0,len(key)):
			if i+j<length:
				result[i+j]=key[j]
	return "".join(result)

