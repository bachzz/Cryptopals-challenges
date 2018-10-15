### NOTE!!! RUN challenge_36_server first

### Break SRP with a zero key
## Server produces K by: S = (A * v^u)^b mod N, K_server = H(S)
## => A = 0 or A = N or A = N^2 => S = 0 
## => we can authenticate simply by sending K_client = H(0) without knowing the password!

import web
import sys
import requests
import thread
import time


sys.path.insert(0, './lib')
from my_crypto_lib import *
from random import randint
from hashlib import sha256

N = int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
            "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
            "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
            "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
            "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
            "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
            "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
            "fffffffffffff",16) # taken from Diffie-Helman's p
g = 2
k = 3
I = "ngb1998@gmail.com"
a = randint(0,N - 1)

### CHANGE "A" HERE ####
					   #
A =  N				   #
					   #
########################

password = "p4$$vv0rd"

# Retrieve from server
salt = ""
B = 0

# WEB CLIENT

urls = (
    '/', 'handle'
)


class handle():
	def POST(self):
		data = web.input(salt = "", B = "", message = "")
		if len(data.salt) != 0 and len(data.B) != 0:
			salt = data.salt
			B = int(data.B)
			# Compute string uH = SHA256(A|B), u = integer of uH
			uH = sha256(str(A)+str(B)).digest()
			u = int(ascii_to_hex(uH), 16)
			# Generate string xH=SHA256(salt|password)
			xH = sha256(salt + password).digest()
			x = int(ascii_to_hex(xH), 16)		
			# Generate S = (B - k * g**x)**(a + u * x) % N
			
			############### CHANGE "S" HERE ######################
																 #
			S = 0#modexp(B - k * modexp(g, x, N), a + u * x, N)	 #
																 #
			######################################################

			# Generate K = SHA256(S)
			K = sha256(str(S)).digest()
			# C->S || Send HMAC-SHA256(K, salt)
			hm = hmac_sha256(K, salt)
			print hm
			queries = "?hmac=" + str(hm)
			request = requests.post("http://localhost:8888/" + queries)
		if len(data.message) != 0:
			print data.message
			

class MyApplication(web.application):
    def run(self, port = 8080, *middleware):
        func = self.wsgifunc(*middleware)
        return web.httpserver.runsimple(func, ('0.0.0.0', port))

def run_client():
	app = MyApplication(urls, globals())
	app.run(port = 8080)

if __name__ == "__main__":
	thread.start_new_thread(run_client, ())
	time.sleep(2)
	# C->S || Send I, A=g**a % N (a la Diffie Hellman)	
	queries = "?email=" + I + "&A=" + str(A)
	request = requests.post("http://localhost:8888/" + queries)
	time.sleep(20)
	thread.exit()