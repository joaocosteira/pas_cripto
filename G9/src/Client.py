# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio,socket,os,sys
from aes import *
import certs as c

conn_port = 8888
max_msg_size = 9999


class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, sckt=None):
        """ Construtor da classe. """
        #id
        self.id = sys.argv[1]
        cert,key=c.unpack("Cliente"+self.id)
        #client private key AES
        self.key = genSKey()
        #client public key AES
        self.pkey=key2bytes(genPKey(self.key))
        #client certificate private key
        self.privateKey = key
        #client certificate
        self.cert = c.cert2bytes(cert)

        self.msg_cnt = 0


    def process(self, msg=b""):
        """ Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """

        if(self.msg_cnt==0):
            self.msg_cnt+=1
            return self.pkey

        if(self.msg_cnt==1):
            self.msg_cnt+=1
            server_pkey,sig,cert = msg[:625],msg[625:625+256],c.bytes2cert(msg[625+256:])
            
            v = c.verify(cert,sig,self.pkey+server_pkey)
            if v:
                self.key=genSharedSecret(self.key,bytes2key(server_pkey))
                # print(self.key)
            else:
                print("Erro na verificação!")
                return None
            return c.sign(self.privateKey,self.pkey+server_pkey)+self.cert

        if(self.msg_cnt>=2):
            if(len(msg)>0 and self.msg_cnt>2):
                print('Received (%d): %r' % (self.msg_cnt -2 , decrypt(msg,self.key)))

            self.msg_cnt +=1
            print('Input message to send (empty to finish)')
            new_msg = str(input())
            ct = encrypt(new_msg,self.key)
            return ct if len(new_msg)>0 else None

#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#

@asyncio.coroutine
def tcp_echo_client(loop=None):
    if loop is None:
        loop = asyncio.get_event_loop()

    reader, writer = yield from asyncio.open_connection(
        '127.0.0.1',conn_port, loop=loop)

    addr = writer.get_extra_info('peername')
    client = Client(addr)
    msg = client.process()
    while msg:
        writer.write(msg)
        msg = yield from reader.read(max_msg_size)
        if msg :
            msg = client.process(msg)
        else:
            break
    writer.write(b'\n')
    print('Socket closed!')
    writer.close()


def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())


run_client()
