import rsa
def open_public_key(path):
	with open(path,"r") as f:
		return rsa.PublicKey.load_pkcs1(f.read().encode())

def open_private_key(path):
	with open(path,"r") as f:
		return rsa.PrivateKey.load_pkcs1(f.read().encode())
