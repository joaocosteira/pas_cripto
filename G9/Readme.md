
# Guião 9
O programa encontra-se separado em quatro ficheiros, ***Server.py*** que responde aos pedidos dos clientes, ***Client.py*** que envia pedidos ao servidor, o ficheiro ***aes.py*** que contém todos os métodos necessários à implementação do algoritmo de Diffie-Hellman, assim como do algoritmo simetrico AES, e o ficheiro ***certs.py*** que implementa as funcionalidades que tratam dos certificados, como carregar os certificados e chaves privadas, assinar e verificar as assinaturas, assim como a validade dos certificados.

# Funcionamento
Quando um cliente se conecta ao servidor, envia a sua chave pública do AES (g<sup>x</sup>). O servidor responde com a sua chave pública, uma mensagem assinada contendo as chaves públicas do Cliente e Servidor, e o seu Certificado (g<sup>y</sup>, Sig<sub>S</sub>(g<sup>x</sup>, Cert<sub>S</sub>). O cliente efetua a verificação da assinatura da mensagem, assim como da validade do certificado enviado pelo Servidor, de seguida calcula a chave partilhada (k=g<sup>xy</sup>) e envia as duas chaves públicas assinadas e o seu Certificado (Sig<sub>C</sub>(g<sup>x</sup>, Cert<sub>C</sub>). Ao receber esta mensagem, o Servidor verifica a assinatura e o Certificado do Cliente e calcula a chave partilhada. A partir deste ponto todas as mensagens seguintes são encriptadas usando ***k***.

![diagram](https://github.com/uminho-miei-crypto/1920-G7/blob/master/Guioes/G9/Certs.png)

## Servidor
O servidor recebe e redireciona os pedidos recebidos, acrescentando no fim da mensagem '***[R]***', de modo a simular uma resposta ao pedido do Cliente.

## Makefile
De modo a facilitar a verificação do funcionamento do programa, ao executar o comando ***make*** são criados dois novos terminais, em que o primeiro é o Servidor e o restante é o Cliente. 

## Ficheiros .p12 e .cer
Para o bom funcionamento deste programa é necessario que sejam fornecidos na pasta certs um ficheiro CA.cer, um ficheiro Servidor.p12 para o Servidor e um ficheiro Cliente***X***.p12 para cada Cliente, onde ***X*** será o Identificador do mesmo.
