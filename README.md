# Trabalho Prático 2 - Geração deterministica de chaves RSA

## Autores
- Ana Raquel Neves Vidal
- Simão Augusto Ferreira Andrade

## Linguagens de programação utilizadas
- C;
- Java;

## Objetivos
- Implementar um **gerador de bytes pseudo-aleatórios**, com uma *seed* com N bytes. A inicialização deste gerador será importante para contribuir para a geração do par de chaves RSA;
- Implementar um **gerador de chaves RSA**, que gere um par de chaves (pública e privada) com base num número primo de N bits, e que guarde as chaves em ficheiros de texto;

## Bibliotecas
- [OpenSSL](https://www.openssl.org/)
- [BigInteger](https://docs.oracle.com/javase/7/docs/api/java/math/BigInteger.html)

## Parâmetros de entrada
- Palavra-passe com N bytes;
- Uma *confusion string* (seja lá o que isso for);
- Contador de iterações;

## Gerador de bytes pseudo-aleatórios (*randgen*)
Criação de um PRBG a partir da palavra-passe, da *confusion string* e do contador de iterações.

1. Computar uma *seed* para a palavra-passe, a *confusion string* e o contador de iterações, usando o método PBKDF2;
2. Transformar a *confusion string* numa sequência de bytes do mesmo tamanho da palavra-passe HMAC (*confusion pattern*);
3. Inicializar o gerador com a *seed*;
4. Começar um ciclo com 'contador de iterações' iterações;
    1. Usar o PRNG para gerar um conjunto de bytes pseudo-aleatórios, até que o padrão da *confusion string* seja encontrado;
    2. Usar o PRNG para produzir a nova *seed* e usar essa *seed* para gerar os bytes pseudo-aleatórios.

Para o PRNG utilizado foi o **SHA-256**, onde é dada uma *seed* e é gerado o hash dessa *seed*, a cada iteração é gerado um novo hash usando o hash anterior como *seed*.

## Gerador de chaves RSA (*rsagen*)

O par de chaves RSA será gerado através do gerador de bytes pseudo-aleatórios, da seguinte forma:

1. Gerar um conjunto de bytes pseudo-aleatórios com o tamanho da chave RSA (em bytes);
2. Será dividido o conjunto de bytes em dois conjuntos de bytes, sendo que o primeiro conjunto irá representar o nosso *p* e o segundo conjunto irá representar o nosso *q*, ambos em formato BIGNUMBER/BigInteger;
3. Será verificado se os dois conjuntos de bytes são primos, caso não sejam, o seu valor será incrementado até que sejam primos;
4. Será calculado o valor de *n* através da multiplicação de *p* e *q*;
5. O valor de *e* é fixo, sendo que o seu valor é 65537 (2^16 + 1);
6. Será calculado o valor de *d* através da função *modular inverse* de *e* e *phi(n)*, sendo que *phi(n)* é calculado através da multiplicação de *(p-1)* e *(q-1)*;

Após isso, será guardado o par de chaves RSA em dois ficheiros de texto, sendo que um deles irá conter a chave pública (n,e) e o outro irá conter a chave privada (n,d).