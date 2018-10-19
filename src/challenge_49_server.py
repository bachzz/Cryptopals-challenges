import thread
import time
import web
import urlparse
import sys


sys.path.insert(0, './lib')
from my_crypto_lib import *

#### SHARED-SECRET-KEY #####
key = "YELLOW SUBMARINE"   #
############################

urls = (
	'/', 'handle'
)

def cbc_mac(message, key, iv):
	ct = aes_cbc_enc2(message, key, iv)
	return ct[-16:] # mac is last block C[n]

class handle:
	def POST(self):
		data = web.input(_from = "", to = "", amount = "", tx_list = "", iv_hex = "", mac_hex = "")
		if len(data.tx_list) != 0:
			# parse message
			id1 = data._from
			id2 = data.to
			amount = data.amount
			# Generate mac for given message & iv
			message = "_from=" + id1 + "&to=" + id2 + "&amount=" + amount
			mac = cbc_mac(message, key, hex_to_ascii(data.iv_hex))
			# Compare mac with client's mac 
			if ascii_to_hex(mac) == data.mac_hex:
				print "from: " + id1 + "   to: " + id2 + "   Amount: " + amount 
				return "OK!"
			else:
				return web.internalerror("Nice try, kid.")
		else:
			return 200

class MyApplication(web.application):
    def run(self, port = 8080, *middleware):
        func = self.wsgifunc(*middleware)
        return web.httpserver.runsimple(func, ('0.0.0.0', port))

def run_server():
	app = MyApplication(urls, globals())
	app.run(port = 8888)
	print "Exit thread!"

if __name__ == "__main__":
	thread.start_new_thread(run_server, ())
	time.sleep(20)
	thread.exit()