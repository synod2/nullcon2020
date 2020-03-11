ayyMessage
==============================
crypto , 410 pt

desc 
------------------------------
```
We have captured a message from Bob to Alice. 
We believe it contains sensitive information. 
Alice's message server runs at: server.py. 
Can you find the contents of the message?
```

files 
-------------------------------
-server.py
-rsapubkey.pem
-messsage.txt


solution
-------------------------------
server.py 의 동작 구조부터 분석해보자.
main() 함수에선 JSON형식으로 입력된 데이터를 파싱하여 base64로 디코딩하고, 
verify_message 함수를 통과시켜 해당 메시지가 유효한지를 판별, 
유효하다면 decrypt_message 함수를 통해 복호화 하고 
복호화 한 내용의 해쉬값을 출력해준다. 

verify_message  함수는 인자로 들어온 메시지가 유효한지를 체크하는 함수인데,
메시지에 포함되어있던 eccpubkey를 ECC 암호화의 키로 만들고
aeskey, nonce, message 문자열을 합친것을 해쉬화 하여 문자열 h를 만든다.
그다음 아까 가져온 eccpubkey를 인자로 fips-186-3 방식으로 DSS서명을 만든다.
이후 아까 만든 서명에서 message에 들어있던 signature로 h 가 유효한지 체크한다.  

decrypt_message함수는 서버에 있는 rsa private key를 가져와서 복호화 키로 사용한다.
이때에 복호화 할 내용은 메시지의 message 부분으로, 이 부분이 복호화 되어 평문이 된다음
hash로 출력된다.

즉, 이 서버코드는 전송해준 message의 내용을 가지고서 서명을 만들고 인증을 한다는 뜻이 된다.
그렇다는건 사용자가 보내는 내용대로 인증이 된다는 이야기니까 message가 어떤 내용이건 무관하게
인증이 가능하고 복호화가 된다. 

이를 이용하여 지금 가지고 있는 암호화된 메시지를 한글자씩 잘라서 전송하면 
서버는 한글자씩 해쉬 결과를 보내준다.
아스키 코드 범위내에서 문자열 해쉬를 돌려 어떤 문자열이 결과완 일치하는지를 찾으면
첫글자를 찾을 수 있게 된다 . 
첫글자를 찾은 이후에는 동일하게 한글자씩 더해서 날리고 비교하다보면
결국은 전체 문자열을 얻을수 있게 된다. 

문제 서버가 닫힌 이후라 실제 풀이는 불가하지만, 다른 풀이를 참고해 코드를 작성해봤다.
새로 메시지를 보낼 떄 바꿔야 할 내용은 message 오브젝트로, 해당 내용이 바뀌면
signature도 거기에 맞게 변경되어야 verify를 통과시킬 수 있다.
이떄 signature를 만들기 위해선 sign 함수를 실행시켜야하는데, 이를 위해 ECC키를 새로생성해야한다.
새로 생성한 ECC 키로 dss signer를 새로 만들고, signer를 통해 새로 만든 시그너쳐와 
새로만든 ECC키의 public key도 함께 전송한다.
즉, 메시지를 바꾸어 보낼때는 수정한 message에 맞춰 signature와 eccpubkey를 새로 생성해 전송해야한다. 


사용된 ECC 함수 정보 
``` 
export_key()
- format = ""
'DER'. The key will be encoded in ASN.1 DER format (binary). For a public key, the ASN.1 subjectPublicKeyInfo structure defined in RFC5480 will be used. For a private key, the ASN.1 ECPrivateKey structure defined in RFC5915 is used instead (possibly within a PKCS#8 envelope, see the use_pkcs8 flag below).
'PEM'. The key will be encoded in a PEM envelope (ASCII).
'OpenSSH'. The key will be encoded in the OpenSSH format (ASCII, public keys only).
키 생성시 어떤 형식으로 만들것인지 결정. 수신한 ecc pubkey가 DER 형식이었으므로 동일하게 맞춰주자.

generate() 
- curve = "" 
Curve	Possible identifiers
NIST P-256	'NIST P-256', 'p256', 'P-256', 'prime256v1', 'secp256r1'
NIST P-384	'NIST P-384', 'p384', 'P-384', 'prime384v1', 'secp384r1'
NIST P-521	'NIST P-521', 'p521', 'P-521', 'prime521v1', 'secp521r1'
256, 384, 521 방식중에 하나를 선택하여 적용할 수있다. 
fips-186-3방식으로 DSS 서명을 하려면 p-256만 사용이 가능한걸로 보인다. 
```
이러한 방법으로 signature와 eccpubkey를 생생하여 verify함수를 통과시키면
정상적으로 통과 되는것을 볼 수 있다. 

```
def sign_message(message,text):
	message["message"] = text
	ecckey = ECC.generate(curve='P-256')
	signer = DSS.new(ecckey, 'fips-186-3')
	
	message["eccpubkey"] = ecckey.public_key().export_key(format='DER')
	h = SHA256.new(message["aeskey"] + message["nonce"] + message["message"])
	
	message["signature"] = signer.sign(h)
	return message
```
최종적으로, 기존에 만들어져 있던 message 문자열을 하나식 잘라 보내고
잘라 보낸 message의 복호화-해쉬 결과가 아스키 범위 내에서 어떤 문자열의 해쉬와 일치하는지를 비교하여
평문을 하나씩 찾아내면 된다. 
```
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
```