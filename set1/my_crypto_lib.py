from Crypto.Cipher import AES
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

def base64_to_ascii(b64):
	return base64.b64decode(b64)

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
	string2=key_dup(byte,len(string)) 
	return fixed_XOR(string,string2)

					### --- BREAK SINGLE-BYTE KEY XOR (Substitution's cipher) --- ###	
	
# chatacters frequency
letter_scores = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
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

def hamming_distance(hex1,hex2):
	xor=fixed_XOR(hex1,hex2)
	xor_bin=hex_to_binary(xor)
	count=0
	for i in range(len(xor_bin)):
		if xor_bin[i]=="1":
			count+=1
	return count

def find_possible_keysize(encrypted_ascii,min_byte_size,max_byte_size): 
	key_avg_dists=[]
	for keysize in range(min_byte_size,max_byte_size):
		chunks=[encrypted_ascii[i:i+keysize] for i in range(0,len(encrypted_ascii),keysize)]
		norm_dists=[]
		while True:
			try:
				chunk0=chunks[0]
				chunk1=chunks[1]
				if len(chunk0)==len(chunk1):
					# calculate Hamming distance
					chunk0_hex=ascii_to_hex(chunk0)
					chunk1_hex=ascii_to_hex(chunk1)
					dist=hamming_distance(chunk0_hex,chunk1_hex)
					# normalize the distance
					norm=dist/float(keysize)
					norm_dists.append(norm)
				del chunks[0]
				del chunks[0]
			except Exception as e:
				break
		result = {
			'key':keysize,
			'avg distance':sum(norm_dists)/len(norm_dists)
		}
		key_avg_dists.append(result)

	possible_keysize = sorted(key_avg_dists, key=lambda x: x['avg distance'])	
	return possible_keysize[0]['key']

def break_repeating_key_xor(encrypted_ascii,keysize):
	# GET THE KEY!
	key=[]
	for i in range(keysize):
		block=[]
		for j in range(i,len(encrypted_ascii),keysize):
			block.append(encrypted_ascii[j])
		block="".join(block)
		block_hex=ascii_to_hex(block)
		key_char=break_single_byte_xor(block_hex,32,256)['key'] # brute-force from 'SPACE' to ...
		key.append(key_char)
	key="".join(key)
	# GET THE MESSAGE!
	keys=key_dup(key,len(encrypted_ascii)) # duplicate key -> len(keys)=len(ciphertext)
	keys_hex=ascii_to_hex(keys)
	encrypted_hex=ascii_to_hex(encrypted_ascii)
	message_hex=fixed_XOR(encrypted_hex,keys_hex).zfill(len(encrypted_hex))
	message=hex_to_ascii(message_hex)
	result = {
		'key':key,
		'message':message
	}
	return result
				
				### --- AES ENCRYPTION / DECRYPTION --- ###
				
def aes_ecb_enc(message,key):
	cipher=AES.new(key,AES.MODE_ECB)
	return cipher.encrypt(message)

def aes_ecb_dec(ciphertext,key):
	cipher=AES.new(key,AES.MODE_ECB)
	return cipher.decrypt(ciphertext)
	
def detect_aes_ecb(ct_ascii,aes_type):
	byte_size=aes_type/8
	for i in range(0,len(ct_ascii),byte_size):
		if ct_ascii[i:(i+byte_size)] in ct_ascii[(i+byte_size):]:
			return True
	return False
