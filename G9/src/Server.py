# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
from aes import *
import certs as c

conn_cnt = 0
conn_port = 8888
max_msg_size = 9999


class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, addr=None):
        """ Construtor da classe. """
        c.unpackCA()
        cert,key = c.unpack("Servidor")
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        #server certificate private key
        self.privateKey = key
        #server certificate
        self.cert = c.cert2bytes(cert)
        self.clientes={}


    def process(self, msg):
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """

        if(self.msg_cnt==0):
            self.msg_cnt += 1
            skey=genSKey()
            pKey=key2bytes(genPKey(skey))
            self.clientes[self.id]= msg, pKey,skey
            return pKey+c.sign(self.privateKey,msg+pKey)+self.cert

        if(self.msg_cnt==1):
            self.msg_cnt += 1
            sig,cert = msg[:256],c.bytes2cert(msg[256:])

            p,k,s = self.clientes[self.id]
            v = c.verify(cert,sig,p+k)
            if v:
                self.clientes[self.id]=genSharedSecret(s,bytes2key(p))
                # print(self.clientes[self.id])
            else:
                print("Erro na verificação!")

            return b'OK!'

        if(self.msg_cnt>1):
            self.msg_cnt += 1
            
            #Para a terminação
            if(len(msg)==0):
                print("["+self.id+"]")
            else:
                print('%d : %r' % (self.id,msg))
                # print('Msg Content: ',decrypt(msg,self.clientes[self.id]))
                old_msg = decrypt(msg,self.clientes[self.id])
                new_msg = encrypt(old_msg+' [R]',self.clientes[self.id])
            return new_msg if len(msg)>0 else None


#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#

@asyncio.coroutine
def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt +=1
    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(conn_cnt, addr)
    data = yield from reader.read(max_msg_size)
    while True:
        if not data: continue
        if data[:1]==b'\n': break
        data = srvwrk.process(data)
        if not data: break
        writer.write(data)
        yield from writer.drain()
        data = yield from reader.read(max_msg_size)
    print("[%d]" % srvwrk.id)
    writer.close()


def run_server():
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(
        handle_echo, '127.0.0.1', conn_port, loop=loop)
    server = loop.run_until_complete(coro)
    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    print('  (type ^C to finish)\n')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('\nFINISHED!')


run_server()
