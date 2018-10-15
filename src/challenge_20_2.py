import base64
import random
import itertools
import operator
import sys

# Cryptohelper from https://github.com/apuigsech/cryptohelper
from cryptohelper import *


key = ''.join([chr(random.randint(0,255)) for i in range(16)])



def main(argv):
	with open('./txt/20.txt') as f:
		ct_list = [base64.b64decode(line.rstrip()) for line in f]


	ks = keystream_from_many_time_pad(ct_list, dict(freq_eng, **{' ':15, ':':2, ';':2}))

	for i in range(len(ct_list)):
		print strxor(ct_list[i], ks)


if __name__ == "__main__":
	main(sys.argv)