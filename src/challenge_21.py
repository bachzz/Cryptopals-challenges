import sys


sys.path.insert(0, './lib')
from my_crypto_lib import *

seed = 23
rng = MT19937RNG(seed)
#rng = MT19937(seed)
#rng = MT19937RNG
#rng = rng.random(seed)
print rng.extract_number()
#print rng