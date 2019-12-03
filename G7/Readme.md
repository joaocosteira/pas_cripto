
# Guião 7
O programa encontra-se separado em quatro ficheiros, ***Server.py*** que responde aos pedidos dos clientes, ***Client.py*** que envia pedidos ao servidor, o ficheiro ***aes.py*** que contém todos os métodos necessários à implementação do algoritmo de Diffie-Hellman, assim como do algoritmo simetrico AES, e o ficheiro ***rsa.py*** que implementa as funcionalidades que tratam das chaves públicas e privadas, como guardar e carregar as chaves em ficheiros, assinar e verificar as assinaturas.

# Funcionamento
Quando um cliente se conecta ao servidor, envia o seu id na primeira mensagem. O servidor responde com uma chave g^y (chave pública, AES) gerada por si. O cliente envia então a sua chave g^x. A partir deste ponto são enviados novamente as chaves, mas assinadas. Depois, a chave final K é calculada (g^xy), e todas as comunicações seguintes são encriptadas usando esta chave.
![diagram](https://github.com/uminho-miei-crypto/1920-G7/blob/master/Guioes/G9/diagram.png)

## Servidor
O servidor recebe e redireciona os pedidos recebidos, acrescentando no fim da mensagem '***[R]***', de modo a simular uma resposta ao pedido do Cliente.

## Key Generator
Recebe o número de clientes (N), como argumento ou input, e gera N +1 pares de chaves (N clientes + 1 Servidor)

## Makefile
De modo a facilitar a verificação do funcionamento do programa, ao executar o comando ***make*** são criados três pares de chaves e três novos terminais, em que o primeiro é o Servidor e os restantes são Clientes. 

## Todo
1. Usar a função de padding em vez de usar chavetas
2. Gerar um vetor de inicialização e enviá-lo para o servidor, em vez de usar uma parte da chave como IV
