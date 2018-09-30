import sys
sys.path.insert(0, './lib')
from my_crypto_lib import *

ct_arr=[]

with open("./txt/8.txt") as f:
	b64=f.read()
for i in range(0,len(b64),320):
	b64_i=b64[i:(i+320)]
	b64_i_ascii=base64_to_ascii(b64_i)
	if detect_aes_ecb(b64_i_ascii,128):
		ct_arr.append(b64_i)

print ct_arr
