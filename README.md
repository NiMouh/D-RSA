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
Usando o método PBKDF2, gerar uma *key* de 256 bits a partir da palavra-passe, da *confusion string* e do contador de iterações.

1. Transformar a *confusion string* numa sequência de bytes do mesmo tamanho da palavra-passe (HMAC?);
2. Inicializar a gerador com a *seed*;
3. Usar o gerador para gerar os bytes pseudo-aleatórios, até que o padrão da *confusion string* seja encontrado;
4. Usar o gerador para produzir a nova *seed* e usar essa *seed* para gerar os bytes pseudo-aleatórios.
5. Repetir os passos 3 e 4 n vezes (n = contador de iterações).


## Gerador de chaves RSA (rsagen)
Por escrever...