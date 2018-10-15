import sys


sys.path.insert(0, './lib')
from my_crypto_lib import *



class DSA():
	# Key generation
	def __init__(self, p = 0, q = 0, g = 0):
		if p == 0 and q == 0 and g == 0:
			self.p = int('800000000000000089e1855218a0e7dac38136ffafa72eda7'
	     				'859f2171e25e65eac698c1702578b07dc2a1076da241c76c6'
	     				'2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe'
	     				'ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2'
	     				'b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87'
	     				'1a584471bb1', 16)
			self.q = int('f4f47f05794b256174bba6e9b396a7707e563c5b', 16)
			self.g = int('5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119'
	     				'458fef538b8fa4046c8db53039db620c094c9fa077ef389b5'
	     				'322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047'
	     				'0f5b64c36b625a097f1651fe775323556fe00b3608c887892'
	     				'878480e99041be601a62166ca6894bdd41a7054ec89f756ba'
	     				'9fc95302291', 16)
		else:
			self.p = p
			self.q = q
			self.g = g
		self.x = randint(1, self.q - 1) # private key
		self.y = pow(self.g, self.x, self.p) # public key
	
	def h_sha1(self, message):
		return int(sha1(message), 16)
	
	def sign(self, message):
		while True:
			k = randint(2, self.q - 1)
			r = pow(self.g, k, self.p) % self.q
			if r == 0:
				continue
			s = (inv_mod(k, self.q) * (self.h_sha1(message) + self.x * r)) % self.q
			if s != 0:
				break
		return r, s

	def verify(self, message, r, s):
		if not (0 < r < self.q) or not (0 < s < self.q):
			return False
		w = inv_mod(s, self.q)
		u1 = (self.h_sha1(message) * w) % self.q
		u2 = (r * w) % self.q
		v1 = pow(self.g, u1, self.p)
		v2 = pow(self.y, u2, self.p)
		v = ((v1*v2) % self.p) % self.q

		return v == r
