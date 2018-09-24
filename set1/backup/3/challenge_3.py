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

def single_byte_XOR(string,byte):
	string2=[byte for i in range(len(string)/2)] # duplicate bytes => 
	string2="".join(string2)					 # len(bytes)=len(string)	
	return fixed_XOR(string,string2)

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
	
encoded="1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"


print "Encrypted hex:",encoded
result=break_single_byte_xor(encoded,65,122) # Brute-force key from A -> z
print "Single-byte key:",result['key']
print "Decrypted message: ",result['message']
