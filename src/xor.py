
from Crypto.Util.number import getPrime, getRandomInteger, GCD, long_to_bytes, bytes_to_long
import os
import math

class XOR:
    """XOR crypto implementation in python."""
    def __init__(self):
        self.session_key = None

    def generate_session_key(self):
        self.session_key = os.urandom(16).hex()

    def xor(self, message):
        # Repeat the key if the message is longer than the key
        mult = math.ceil(len(message) / len(self.session_key))
        key = (self.session_key * mult).encode()

        c = "".join(chr(ord(a) ^ b) for a, b in zip(message.decode(), key)).encode()
        return c
        
