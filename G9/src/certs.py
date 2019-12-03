from OpenSSL import crypto

def unpack(name):
    name_p12  = crypto.load_pkcs12(
        open("certs/"+name+".p12", 'rb').read(),
        b'1234'
    )

    name_cert = crypto.dump_certificate(
        crypto.FILETYPE_PEM,
        name_p12.get_certificate()
    )  

    name_priv = crypto.dump_privatekey(
        crypto.FILETYPE_PEM,
        name_p12.get_privatekey(),
        None,
        b'1234'
    )
    return bytes2cert(name_cert),bytes2skey(name_priv)


def unpackCA():
    cert_cer = crypto.load_certificate(
        crypto.FILETYPE_ASN1,
        open("certs/CA.cer", 'rb').read()
    )
    
    cert_pem = crypto.dump_certificate(
        crypto.FILETYPE_PEM,
        cert_cer
    )
    return bytes2cert(cert_pem)


def sign(skey,msg):
    msg = msg.encode() if(type(msg)==str) else msg
    return crypto.sign(skey,msg,digest="md5")


def verify(cert,sig,msg):
    try:        
        if(verify_cert(cert)):
            crypto.verify(cert,sig,msg,digest="md5")
            return True
    except Exception as e:
        print(e)
    return False


def verify_cert(cert):
# inspirado em:
#   (http://www.yothenberg.com/validate-x509-certificate-in-python/)
#   (http://aviadas.com/blog/2015/06/18/verifying-x509-certificate-chain-of-trust-in-python/)
    # Create and fill a X509Sore with trusted certs
    store = crypto.X509Store()
    store.add_cert(unpackCA())

    # Create a X590StoreContext with the cert and trusted certs
    store_ctx = crypto.X509StoreContext(store, cert)
    # and verify the the chain of trust
    result = store_ctx.verify_certificate()

    # Returns None if certificate can be validated
    if result is None:
        return True
    else:
        return False


def bytes2skey(bts):
    return crypto.load_privatekey(
        crypto.FILETYPE_PEM,
        bts,
        b'1234'
    ) 


def bytes2cert(bts):
    return crypto.load_certificate(
        crypto.FILETYPE_PEM,
        bts
    )


def cert2bytes(cert):
    return crypto.dump_certificate(
        crypto.FILETYPE_PEM,
        cert
    )
