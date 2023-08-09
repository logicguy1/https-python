import time
from sty import fg, bg, ef, rs

from rsa import RSA
from xor import XOR

class Server():
    """Server side crypto manager"""
    def __init__(self):
        self.RSA = RSA()
        self.RSA.create_keys()
        self.log("Created Private Key:", self.RSA.private_key)
        self.log("Created Public Key:", self.RSA.public_key)

        self.XOR = XOR()

        self.destination_send = None
        self.state = "Awaiting connection"

    def log(self, *args, **kwargs):
        args = list(args)
        args.insert(1, fg.grey)
        args.append(fg.rs)
        print(f"[{fg.red}SERVER{fg.rs}]", *args, **kwargs)

    def send(self, msg):
        time.sleep(0.1)
        self.log("Recived message ", msg)

        if msg["msg"] == "client hello":
            self.destination_send = msg["source"]
            self.destination_send({"msg": "server hello"})
            self.destination_send({"msg": "certificate", "cert": self.RSA.public_key})
            self.destination_send({"msg": "server hello done"})
            self.state = "Pending key exchange"

        if msg["msg"] == "client key exchange":
            self.XOR.session_key = self.RSA.decrypt(msg["key"])
            self.log("Decrypted XOR key", self.XOR.session_key)

            self.log("XOR session key setup, datasteam has been opened")
            c = self.XOR.xor("You can now send information securely between server and client!".encode())
            self.destination_send({"msg": "data steam", "c": c})

        if msg["msg"] == "data steam":
            m = self.XOR.xor(msg["c"])
            self.log("Decrypted message", m.decode())
            self.log("Send message to server > ", end="", flush=True)

            m = input()
            c = self.XOR.xor(m.encode())
            self.destination_send({"msg": "data steam", "c": c})


class Client():
    """Client side crypto manager"""
    def __init__(self):
        # Rsa client without keys (yet)
        self.RSA = RSA()
        self.XOR = XOR()

        self.destination_send = None

        self.state = "Awaiting connection"

    def log(self, *args, **kwargs):
        args = list(args)
        args.insert(1, fg.grey)
        args.append(fg.rs)
        print(f"[{fg.green}CLIENT{fg.rs}]", *args, **kwargs)

    def connect(self, destination_send):
        # Send the server a hello packet, with the adress where it can reply
        self.destination_send = destination_send
        self.state = "Awaiting server hello"
        self.destination_send({"msg": "client hello", "source": self.send})

    def send(self, msg):
        time.sleep(0.1)
        self.log("Recived message ", msg)

        if msg["msg"] == "server hello":
            self.state = "Pending certificate"

        if msg["msg"] == "certificate":
            self.RSA.public_key = msg["cert"]
        
        if msg["msg"] == "server hello done":
            self.state = "Generating session key"
            self.XOR.generate_session_key()
            self.log("Created XOR key", self.XOR.session_key, "encrypting...")
            key = self.RSA.encrypt(self.XOR.session_key)
            self.destination_send({"msg": "client key exchange", "key": key})

        if msg["msg"] == "data steam":
            m = self.XOR.xor(msg["c"])
            self.log("Decrypted message", m.decode())
            self.log("Send message to server > ", end="", flush=True)

            m = input()
            c = self.XOR.xor(m.encode())
            self.destination_send({"msg": "data steam", "c": c})

class CommManager:
    def __init__(self):
        self.server = Server()
        self.client = Client()


if __name__ == "__main__":
    mgr = CommManager()
    mgr.client.connect(mgr.server.send)
    #m = mgr.server.encrypt("Hello world!")
    #mgr.server.decrypt(m)
