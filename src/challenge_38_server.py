############# NOTE #############

# Use Python3 for challenge_38_server.py and challenge_38_client.py
# Due to issues of sha256 in python 2 (e.g: "utf-8" encoding issue: UnicodeDecodeError: 'ascii' codec can't decode byte...)
# Python3 doesn't have web.py yet so I had to use "flask" for server-client protocols

###############################

### Explain:
## Same as challenges 36,37 but now Server "leaks" some parameters like b, B, u, salt
## From those params, MITM hacker can compute session key K and brute-force K until get common dictionary word for password


from flask import Flask, request, jsonify
from hashlib import sha256
from random import randint
import sys

sys.path.insert(0, './lib')
from my_crypto_lib import *



def hmac_sha256_2(key, message):
    """Returns the HMAC-SHA256 for the given key and message. Written following Wikipedia pseudo-code."""

    if len(key) > 64:
        key = sha256(key).digest()
    if len(key) < 64:
        key += b'\x00' * (64 - len(key))

    o_key_pad = xor2(b'\x5c' * 64, key)
    i_key_pad = xor2(b'\x36' * 64, key)

    return sha256(o_key_pad + sha256(i_key_pad + message).digest()).hexdigest()


def h(data):
    """Computes the sha1 hash of the input string and returns the integer corresponding to the output."""
    return int(sha256(data.encode()).hexdigest(), 16)


# N = int("008c5f8a80af99a7db03599f8dae8fb2f75b52501ef54a827b8a1a586f14dfb20d6b5e2ff878b9ad6bca0bb9"
#         "18d30431fca1770760aa48be455cf5b949f3b86aa85a2573769e6c598f8d902cc1a0971a92e55b6e04c4d07e"
#         "01ac1fa9bdefd1f04f95f197b000486c43917568ff58fafbffe12bde0c7e8f019fa1cb2b8e1bcb1f33", 16)
N = int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
            "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
            "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
            "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
            "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
            "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
            "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
            "fffffffffffff",16) # taken from Diffie-Helman's p

# Client and server agree on these values beforehand
g = 2
k = 3

# Server computes these values on his own
b = randint(0, N - 1)
B = modexp(g, b, N)
salt = str(randint(0, 2**32 - 1))

# Values to update later
v = None
A = None
S, K = None, None

app = Flask(__name__)


@app.route('/', methods=['POST'])
def mitm_attack():
    """This is a MITM attack to SRP."""
    global v, A, B, S, K

    # This example server supports only HTTP POST requests
    if request.method == 'POST':

        # Get the data sent by the client as json
        post_data = request.get_json()

        # First (C->S) post
        if 'I' in post_data and 'A' in post_data:

            # Get the I and A sent by the client
            I = post_data.get('I')
            A = post_data.get('A')

            # Send the user the salt and B (first S->C)
            return jsonify(salt=salt, B=B)

        # Second (C->S) post
        elif 'hm' in post_data:

            # Get the client HMAC
            client_hm = post_data.get('hm')

            with open("/usr/share/dict/words") as dictionary:
                candidates = dictionary.readlines()

            # Try several possible password candidates
            for candidate in candidates:

                # Strip the word
                candidate = candidate.rstrip()

                # Compute u
                u = h(str(A) + str(B))
                v = modexp(g, h(salt + candidate), N)

                # Compute S and K
                S = modexp(A * modexp(v, u, N), b, N)
                K = sha256(str(S).encode()).digest()

                # Compute HMAC
                candidate_hm = hmac_sha256_2(K, salt.encode())

                if candidate_hm == client_hm:
                    print("The password is:", candidate)
                    return "OK", 200

            return "BAD", 500


def main():
    app.run()


if __name__ == '__main__':
	main()