#!/usr/bin/env python3
from Crypto.PublicKey import RSA, ECC
import json
from hashlib import sha256
from Crypto.Cipher import AES, PKCS1_OAEP
from base64 import b64decode,b64encode
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from pwn import * 



def verify_message(message):
	eccpubkey = ECC.import_key(message["eccpubkey"])
	h = SHA256.new(message["aeskey"] + message["nonce"] + message["message"])
	verifier = DSS.new(eccpubkey, 'fips-186-3')
	
	try:
		verifier.verify(h, message["signature"])
		return True
	except ValueError:
		return False

def sign_message(message,text):
	message["message"] = text
	ecckey = ECC.generate(curve='P-256')
	signer = DSS.new(ecckey, 'fips-186-3')
	
	message["eccpubkey"] = b64encode(ecckey.public_key().export_key(format='DER'))
	h = SHA256.new(message["aeskey"] + message["nonce"] + message["message"])
	
	message["signature"] = b64encode(signer.sign(h))
	message["message"] = b64encode(text)
	message["aeskey"] = b64encode(message["aeskey"])
	message["nonce"] = b64encode(message["nonce"])
	
	return message

def decrypt_message(message):
	aeskey = rsacipher.decrypt(message["aeskey"])
	ctr = AES.new(aeskey, AES.MODE_CTR, nonce=message["nonce"])
	return ctr.decrypt(message["message"])

def main():
	
	# message = input("Enter message in json format: ")
	# message = json.loads(message)

	with open('message.txt', 'r') as f:
		data = f.read()
		message = json.loads(data)

	message["nonce"] = b64decode(message["nonce"])
	message["message"] = b64decode(message["message"])
	message["aeskey"] = b64decode(message["aeskey"])
	message["signature"] = b64decode(message["signature"])
	message["eccpubkey"] = b64decode(message["eccpubkey"])
	
	for i in range(len(message["message"])) : 
		p = remote("crypto1.ctf.nullcon.net",5001)
		
		sendmsg = message["message"][0:1+i]
		message = sign_message(message,sendmsg)
		
		p.sendlineafter("format: ",message)
		p.recvuntil("receipt:")
	    hm = p.recvline.decode()
	    
	    for ch in printable:
	        ch = ch.encode()
	        if hm == SHA256.new(flag + ch).hexdigest():
	            flag += ch
	            continue
	            
	print(flag)
	
if __name__ == '__main__':
	main()