from Crypto.PublicKey import ECC
from hashlib import sha256
from base64 import b64decode, b64encode
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from time import sleep
import pwn
import string
import json

def send_receive(msg):
	sleep(.1)
	msgb = json.dumps(message).encode()
	conn = pwn.remote('localhost', 1234)
	conn.recv()
	conn.send(msgb + b'\n')
	res = conn.recv()
	rr = res.decode().split('\n')[1]
	return rr

with open('message.txt', 'r') as f:
	data = f.read()
	message = json.loads(data)

aeskeyb = b64decode(message["aeskey"])
nonceb = b64decode(message["nonce"])
enc_message = b64decode(message["message"])

ecckey = ECC.generate(curve='NIST P-256')
signer = DSS.new(ecckey, 'fips-186-3')
message["eccpubkey"] = b64encode(ecckey.public_key().export_key(format='DER')).decode()

flag = ''
for i in range(len(enc_message)):
	messageb = enc_message[0:i+1]
	message["message"] = b64encode(messageb).decode()
	h = SHA256.new(aeskeyb + nonceb + messageb)
	signatureb = signer.sign(h)
	message["signature"] = b64encode(signatureb).decode()
	res = send_receive(message)
	for c in string.printable:
		h = sha256((flag + c).encode()).hexdigest()
		if h == res:
			flag += c
print(flag)