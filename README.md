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
- ...

## Parâmetros de entrada
- Palavra-passe com N bytes;
- Uma *confusion string* (seja lá o que isso for);
- Contador de iterações;

## Gerador de bytes pseudo-aleatórios (randgen)
Gerar uma *key* de 256 bits a partir da palavra-passe, da *confusion string* e do contador de iterações.

1. Computar uma *seed* para a palavra-passe, a *confusion string* e o contador de iterações, usando o método PBKDF2;
2. Transformar a *confusion string* numa sequência de bytes do mesmo tamanho da palavra-passe HMAC (*confusion pattern*);
3. Inicializar o gerador com a *seed*;
4. Começar um ciclo com 'contador de iterações' iterações;
    1. Usar o PRNG para gerar um conjunto de bytes pseudo-aleatórios, até que o padrão da *confusion string* seja encontrado;
    2. Usar o PRNG para produzir a nova *seed* e usar essa *seed* para gerar os bytes pseudo-aleatórios.


## Gerador de chaves RSA (rsagen)
Por escrever...