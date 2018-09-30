import sys
sys.path.insert(0, './lib')
from my_crypto_lib import *

# HEX
my_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
# CONVERT
result=hex_to_base64(my_hex)
# DISPLAY
print "Hex: ", my_hex
print "Base64: ",
print "".join(result)
#print my_hex.decode("hex")
