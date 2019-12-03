from aes import *
from rsa import *
import sys


def main():
    try:
        n=int(sys.argv[1])
    except:
        n=int(input("Numero de Clientes: "))
    sKey = genSKey_RSA()
    save_private_key(sKey,"keys/privateServidor.txt")
    save_public_key(genPKey(sKey),"keys/publicServidor.txt")        

    for i in range (n):
        sKey = genSKey_RSA()
        save_private_key(sKey,"keys/private"+str(i)+".txt")
        save_public_key(genPKey(sKey),"keys/public"+str(i)+".txt")


if __name__ == "__main__":
    main()    