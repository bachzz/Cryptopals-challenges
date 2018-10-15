# class MT19937RNG:
#     # Initialize the generator from a seed
#     def __init__(self, seed):
#         self.MT = [0] * 624
#         self.index = 0        
#         self.MT[0] = seed & 0xffffffff     # We just play with lowest 32 bits of each element
#         for i in range(1, 623+1): # loop over each element
#             self.MT[i] = ((0x6c078965 * (self.MT[i-1] ^ (self.MT[i-1] >> 30))) + i) & 0xffffffff # We use "& 0xffffffff" to get lowest 32 bits of each element
        

#     # Extract a tempered pseudorandom number based on the index-th value,
#     # calling generate_numbers() every 624 numbers
#     def extract_number(self):
#         if self.index == 0:
#             self.generate_numbers()
#         y = self.MT[self.index]
#         y = y ^ (y >> 11)
#         y = y ^ ((y << 7) & (0x9d2c5680))
#         y = y ^ ((y << 15) & (0xefc60000))
#         y = y ^ (y >> 18)

#         self.index = (self.index + 1) #% 624
#         return y


#     # Generate an array of 624 untempered numbers
#     def generate_numbers(self):
#         for i in range(0, 623+1):
#             y = (self.MT[i] & 0x80000000) + (self.MT[(i+1) % 624] & 0x7fffffff)  
#             self.MT[i] = self.MT[(i + 397) % 624] ^ (y >> 1)
#             if (y % 2) != 0: # y is odd
# 				self.MT[i] = self.MT[i] ^ (2567483615) # 0x9908b0df

def get_lowest_bits(n, number_of_bits):
    """Returns the lowest "number_of_bits" bits of n."""
    mask = (1 << number_of_bits) - 1
    return n & mask

class MT19937RNG:
    """This implementation resembles the one of the Wikipedia pseudo-code."""
    W, N, M, R = 32, 624, 397, 31
    A = 0x9908B0DF
    U, D = 11, 0xFFFFFFFF
    S, B = 7, 0x9D2C5680
    T, C = 15, 0xEFC60000
    L = 18
    F = 1812433253
    LOWER_MASK = (1 << R) - 1
    UPPER_MASK = get_lowest_bits(not LOWER_MASK, W)

    def __init__(self, seed):
        self.mt = []

        self.index = self.N
        self.mt.append(seed)
        for i in range(1, self.index):
            self.mt.append(get_lowest_bits(self.F * (self.mt[i - 1] ^ (self.mt[i - 1] >> (self.W - 2))) + i, self.W))

    def extract_number(self):
        if self.index >= self.N:
            self.twist()

        y = self.mt[self.index]
        y ^= (y >> self.U) & self.D
        y ^= (y << self.S) & self.B
        y ^= (y << self.T) & self.C
        y ^= (y >> self.L)

        self.index += 1 
        return get_lowest_bits(y, self.W)

    def twist(self):
        for i in range(self.N):
            x = (self.mt[i] & self.UPPER_MASK) + (self.mt[(i + 1) % self.N] & self.LOWER_MASK)
            x_a = x >> 1
            if x % 2 != 0:
                x_a ^= self.A

            self.mt[i] = self.mt[(i + self.M) % self.N] ^ x_a

        self.index = 0
