from Crypto.Util.number import getPrime, getRandomInteger, GCD, long_to_bytes, bytes_to_long

class RSA:
    """RSA implementation in python."""
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def create_keys(self):
        e = 65537
        gcd = -1

        # Run untill GCD(e, phi(n)) = 1
        while gcd != 1:
            p = getPrime(1024)
            q = getPrime(1024)

            n = p*q
            phi_n = (p-1)*(q-1)

            gcd = GCD(e, phi_n)

        d = pow(e, -1, phi_n)

        self.private_key = {
            "p": p,    
            "q": q,    
            "phi_n": phi_n,    
            "n": n,
            "d": d,    
        }
        self.public_key = {
            "n": n,
            "e": e,
        }

    def encrypt(self, message):
        message_bytes = bytes_to_long(message.encode())
        chipertext = pow(message_bytes, self.public_key["e"], self.public_key["n"])
        return chipertext

    def decrypt(self, chipertext):
        message_bytes = pow(chipertext, self.private_key["d"], self.private_key["n"])
        message = long_to_bytes(message_bytes).decode()
        return message
        
