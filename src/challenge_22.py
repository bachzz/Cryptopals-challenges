### EXPLAIN
## Just brute-force the seed (timestamp) backward in time (seed_trial -= 1) until it has the same PRNG with the original seed

import sys
import time
import random


sys.path.insert(0, './lib')
from my_crypto_lib import *

def routine():
	s = random.randint(40, 1000)
	time.sleep(s/10)
	#time.sleep(random.randint(40, 1000))
	seed = int(time.time())
	print "Original seed:",seed
	rng = MT19937RNG(seed)
	s = random.randint(40, 1000)
	time.sleep(s/10)
	return rng.extract_number()

rng = routine()

seed_trial = int(time.time())
while MT19937RNG(seed_trial).extract_number() != rng:
	seed_trial -= 1
print "Cracked seed:",seed_trial