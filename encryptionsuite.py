#pip3 install pycryptodomex

import json
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome import Random
from Cryptodome.Hash import SHA256, SHA
from Cryptodome.Cipher import PKCS1_OAEP, PKCS1_v1_5
from base64 import b64encode, b64decode

ENCODING = 'utf-8'

def verifysha256(hash,string):
    salt = hash.split("$")[1]
    hash = hash.split("$")[0]
    string = str(string)
    string += str(salt)
    string = tobytes(string)
    h = SHA256.new()
    h.update(string)
    stringhash = str(h.hexdigest())
    if stringhash == str(hash):
        return True
    else:
        return False

def sha256(string):
    string = tobytes(string)
    h = SHA256.new()
    h.update(string)
    hash = h.hexdigest()
    return tostring(hash)

def sha256withsalt(string):
    salt = Random.get_random_bytes(6)
    string = str(string)+str(salt)
    string = tobytes(string)
    h = SHA256.new()
    h.update(string)
    hash = str(h.hexdigest())
    hash += "$"
    hash += str(salt)
    return hash

def tobytes(string):
    if isinstance(string,bytes):
        return string 
    else:
        return string.encode(ENCODING)

def tostring(bytes):
    if isinstance(bytes,str):
        return bytes 
    else:
        return str(bytes.decode(ENCODING))

def encrypt_aes(msg,key):
    #TAKES STR, RETURNS B64d-BYTES
    msg = tobytes(msg)
    cipher = AES.new(key,AES.MODE_CTR)
    ct_bytes = cipher.encrypt(msg)
    nonce = b64encode(cipher.nonce).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'nonce':nonce,'ciphertext':ct})
    result = tobytes(result)
    result = b64encode(result)
    return result

def decrypt_aes(jsondata,key):
    #TAKES B64d-BYTES, RETURNS STR
    jsondata = b64decode(jsondata)
    jsondata = tostring(jsondata)
    b64 = json.loads(jsondata)
    nonce = b64decode(b64['nonce'])
    ct = b64decode(b64['ciphertext'])
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    pt = cipher.decrypt(ct)
    pt = tostring(pt)
    return pt

def encrypt_rsa(msg,pubkey):
    #TAKES BYTES, RETURNS BYTES
    message = tobytes(msg)
    pubkey = tostring(pubkey)
    h = SHA.new(message)
    key = RSA.importKey(pubkey)
    cipher = PKCS1_v1_5.new(key)
    ciphertext = cipher.encrypt(message+h.digest())
    return ciphertext

def decrypt_rsa(message,key,keypass):
    #TAKES BYTES, RETURNS BYTES
    key = tostring(key)
    key = RSA.import_key(key,passphrase=keypass)
    dsize = SHA.digest_size
    sentinel = Random.new().read(15+dsize)

    cipher = PKCS1_v1_5.new(key)
    message = cipher.decrypt(message,sentinel)
    digest = SHA.new(message[:-dsize]).digest()
    if digest==message[-dsize:]:
        message = message[:-dsize]
        return message
    else:
        raise RuntimeError("RSA failed checksum - message deemed corrupt. Cannot continue.")

def gen_key_rsa(password,size=2048):
    secret_code = password
    key = RSA.generate(size)
    encrypted_key = key.export_key(passphrase=secret_code,pkcs=8,protection="scryptAndAES256-CBC")
    return key.publickey().export_key(),encrypted_key

def gen_key_aes(size=32):
    return Random.get_random_bytes(size)

#CHEATSHEETS
#AES
#key = getn_key_aes()
#enc = encrypt_aes("Hello, world!",key)
#decrypt_aes(enc,key)

#RSA
#pub,priv = gen_key_rsa('Test')
#enc = encrypt_rsa("Hello, world!",pub)
#print(type(pub))
#print(type(priv))
#enc = encrypt_rsa("Hello, world!",pub)
#print(decrypt_rsa(enc,priv,"Test"))
