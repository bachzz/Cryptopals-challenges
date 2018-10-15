### EXPLAIN!
### MAN IN THE MIDDLE (MITM) key-fixing attack for Diffie-Helman

##		   A 			 p
## Alice -----> Hacker -----> Bob
##		 <-----		   <-----	
##		    p             B

## kAB = (p^a) mod p = (p^b) mod p = 0
## -> Secret key of Alice & Bob becomes 0!
## -> Hacker uses the key to decrypt messages

import os
import sys


sys.path.insert(0, './lib')
from my_crypto_lib import *


class User:
	def __init__(self, usrname):
		# user's params
		self.usrname = usrname 
		self.dh = diffie_helman()
		self.p = self.dh.p
		self.g = self.dh.g
		self.public_key = self.dh.public_key()
		self.secret_key = ""
		self.iv = os.urandom(16)
		self.received_message = ""
		self.package = { # package to send
			"p": 0,
			"g": 0,
			"public_key": 0,
			"message_enc": "",
			"iv": "",
			"usrname": ""
		}

	def encrypt_message(self, message):
		return aes_cbc_enc(128, message, sha1(str(self.secret_key))[0:16], self.iv)
	def send(self):
		#self.package["public_key"] = self.public_key
		self.package["message_enc"] = ""
		return self.package
	def send_message(self, message):
		self.package["message_enc"] = self.encrypt_message(message)
		return self.package
	def receive(self, other_package):
		p = other_package["p"]
		g = other_package["g"]
		other_public_key = other_package["public_key"]
		self.dh.p = p
		self.dh.g = g
		message_enc = other_package["message_enc"]
		iv = other_package["iv"]
		usrname = other_package["usrname"]
		if other_public_key != 0:
			self.secret_key = self.dh.secret_key(other_public_key)
		if len(message_enc) != 0 and len(iv) != 0: #and self.secret_key != 0:
			self.received_message = aes_cbc_dec(128, hex_to_ascii(message_enc), sha1(str(self.secret_key))[0:16], iv)
			print usrname + ": " + self.received_message

# Initialize users
Alice = User("Alice")
Bob = User("Bob")

Alice.package["p"] = Alice.p
Alice.package["g"] = Alice.g
Alice.package["public_key"] = Alice.public_key
Alice.package["usrname"] = Alice.usrname
Alice.package["iv"] = Alice.iv

Bob.package["p"] = Bob.p
Bob.package["g"] = Bob.g
Bob.package["public_key"] = Bob.public_key
Bob.package["usrname"] = Bob.usrname
Bob.package["iv"] = Bob.iv

Bob.receive(Alice.send())
Alice.receive(Bob.send())

Bob.receive(Alice.send_message("Hi Bob!"))
Alice.receive(Bob.send_message("Hi Alice!"))

	### 	ManInTheMiddle key-fixing attack (MITM)		###
class MITM(User):
	def receive(self, other_package):
		p = other_package["p"]
		g = other_package["g"]
		other_public_key = other_package["public_key"]
		self.package["p"] = p
		self.package["g"] = g
		self.package["public_key"] = p
		# receive message
		message_enc = other_package["message_enc"]
		iv = other_package["iv"]
		self.package["iv"] = iv
		self.iv = iv
		usrname = other_package["usrname"]
		self.package["usrname"] = "*Relaying...* " + usrname

		if len(message_enc) != 0 and len(iv) != 0:# and self.secret_key != 0:
			self.secret_key = self.dh.secret_key(p)
			self.received_message = aes_cbc_dec(128, hex_to_ascii(message_enc), sha1(str(self.secret_key))[0:16], iv)
			print "*Listening to...* " + usrname + ": " + self.received_message

Hacker = MITM("Anonymous")

# A->M || Send "p", "g", "A"
Hacker.receive(Alice.send())
# M->B || Send "p", "g", "p"
Bob.receive(Hacker.send())
# B->M || Send "B"
Hacker.receive(Bob.send())
# M->A || Send "p"
Alice.receive(Hacker.send())
# A->M || Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
Hacker.receive(Alice.send_message("Whaddup!"))
# Hacker relays that message to Bob
Bob.receive(Hacker.send_message(Hacker.received_message))
# B->M || Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
Hacker.receive(Bob.send_message("Supppp!"))
# Hacker relays that message to Alice
Alice.receive(Hacker.send_message(Hacker.received_message))

