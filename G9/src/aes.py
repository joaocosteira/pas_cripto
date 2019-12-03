from cryptography.hazmat.backends   import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers    import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf   import HKDF
from cryptography.hazmat.primitives.asymmetric import dh

P = 99494096650139337106186933977618513974146274831566768179581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382445323499931625451272600173180136123245441204133515800495917242011863558721723303661523372572477211620144038809673692512025566673746993593384600667047373692203583
G = 44157404837960328768872680677686802650999163226766694797650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974314935015501571333024773172440352475358750668213444607353872754650805031912866692119819377041901642732455911509867728218394542745330014071040326856846990119719675

pn = dh.DHParameterNumbers(P, G)
parameters = pn.parameters(default_backend())


def key2bytes(key):
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def bytes2key(bts):
    return serialization.load_pem_public_key(
        bts,
        backend=default_backend()
    )


def genSharedSecret(skey,pkey):
    return skey.exchange(pkey)


def genSKey():
    return parameters.generate_private_key()


def genPKey(skey):
    return skey.public_key()


def cipher(k,v):
    return Cipher(
        algorithms.AES(k),
        modes.CBC(v),
        backend=default_backend()
    )


def encrypt(m,k):
    tiny_key = hashKey(k,32)
    init_vector = hashKey(k,16)
    encryptor = cipher(tiny_key,init_vector).encryptor()
    ct = encryptor.update(pad(m).encode()) + encryptor.finalize()
    return ct 


def decrypt(ct,k):
    tiny_key = hashKey(k,32)
    init_vector = hashKey(k,16)
    decryptor = cipher(tiny_key,init_vector).decryptor()
    pt_padded=decryptor.update(ct) + decryptor.finalize()
    pt=pt_padded.decode('utf-8') #bytes to str

    #unpad
    l=pt.count('{')
    return pt[:len(pt)-l]

#Pad: Adiciona uma sequencia de { no fim da string para fazer pacotes de tamanho 16, e assim de tamanho divisivel
def pad(s):
    return s + ((16-len(s)%16)* '{')


def hashKey(shared_key,size):
    return HKDF(
            algorithm=hashes.SHA256(),
            length=size,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)

# def int_to_bytes(x: int) -> bytes:
#     return x.to_bytes((x.bit_length() + 7) // 8, 'big')

# def int_from_bytes(xbytes: bytes) -> int:
#     return int.from_bytes(xbytes, 'big')
