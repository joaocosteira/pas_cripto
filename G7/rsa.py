from cryptography.hazmat.backends   import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import * 
from cryptography.hazmat.primitives.asymmetric.padding import * 


def genSKey_RSA():
	return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )


def save_private_key(pk, filename):
    pem = pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)


def save_public_key(pk, filename):
    pem = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)


def getPublicKey(ficheiro):
    with open(ficheiro, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key


def getPrivateKey(ficheiro):
    with open(ficheiro, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key


def signRSA(sKey,msg):
    # if(type(msg)==str):
    #   msg=msg.encode()
    return sKey.sign(
        msg,
        PSS(
            mgf=MGF1(hashes.SHA256()),
            salt_length=PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verifyRSA(pKey,msg,sig):
    try:
        pKey.verify(
        sig,
        msg,
        PSS(
            mgf=MGF1(hashes.SHA256()),
            salt_length=PSS.MAX_LENGTH
        ),
        hashes.SHA256())
        return True
    except:
        return False


def encryptRSA(pKey,msg):
  return pKey.encrypt(
      msg,
      OAEP(
          mgf=MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None
      )
  )


def decryptRSA(sKey,msg):
  return sKey.decrypt(
      msg,
      OAEP(
          mgf=MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None
      )
  )


# def Skey2bytes(key):
#     return key.private_bytes(
# 	   encoding=serialization.Encoding.PEM,
# 	   format=serialization.PrivateFormat.PKCS8,
# 	   encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
# 	)

# def bytes2Skey(bts):
#     return serialization.load_pem_private_key(
#         bts,
#         backend=default_backend()
#     )
