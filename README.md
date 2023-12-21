# Trabalho Prático 2 - Geração deterministica de chaves RSA

## Autores
- Ana Raquel Neves Vidal
- Simão Augusto Ferreira Andrade

## Linguagens de programação utilizadas
- C;
- Java;

## Objetivos
1. Implementar um **gerador de bytes pseudo-aleatórios**, com uma *seed* com N bytes. A inicialização deste gerador será importante para contribuir para a geração do par de chaves RSA;
2. Implementar um **gerador de chaves RSA**, que gere um par de chaves (pública e privada) com base num número primo de N bits, e que guarde as chaves em ficheiros de texto;
3. Testar a performance do gerador de bytes pseudo-aleatórios, em termos de tempo de execução.

## Bibliotecas
- [OpenSSL](https://www.openssl.org/)
- [BigInteger](https://docs.oracle.com/javase/7/docs/api/java/math/BigInteger.html)

## Gerador de bytes pseudo-aleatórios (*randgen*)
Criação de um PRBG (*Pseudo-Random Bit Generator*) que irá gerar um conjunto de bytes pseudo-aleatórios.

### Parâmetros de entrada 
- Palavra-passe;
- *Confusion string*;
- Contador de iterações;

### Pseudo-código
1. Computar uma *seed* para a palavra-passe, a *confusion string* e o contador de iterações, usando o método PBKDF2;
2. Computar uma *confusion pattern*, neste caso vamos usar o mesmo método que foi usado para computar a *seed*, pois a *confusion string* é dada no algortimo PBKDF2 como o *salt*;
3. Inicializar o gerador com a *seed*;
4. Começar um ciclo com 'contador de iterações' iterações;
    1. Usar o PRNG para gerar um conjunto de bytes pseudo-aleatórios, até que o padrão da *confusion pattern* seja encontrado;
    2. Usar o PRNG para produzir a nova *seed* e usar essa *seed* para gerar os bytes pseudo-aleatórios.

Para o PRNG utilizado foi o **SHA-256**, onde é dada uma *seed* e é gerado o hash dessa *seed*, a cada iteração é gerado um novo hash usando o hash anterior como *seed*.

## Gerador de chaves RSA (*rsagen*)
O par de chaves RSA será gerado através do gerador de bytes pseudo-aleatórios, da seguinte forma:

### Pseudo-código
1. Gerar um conjunto de bytes pseudo-aleatórios com o tamanho da chave RSA (em bytes);
2. Será dividido o conjunto de bytes em dois conjuntos de bytes, sendo que o primeiro conjunto irá representar o nosso *p* e o segundo conjunto irá representar o nosso *q*, ambos em formato BIGNUMBER/BigInteger;
3. Será verificado se os dois conjuntos de bytes são primos, caso não sejam, o seu valor será incrementado até que sejam primos;
4. Será calculado o valor de *n* através da multiplicação `p * q`;
5. O valor de *e* é fixo, sendo que o seu valor é 65537 (2^16 + 1);
6. Será calculado o valor de *d* através da função *modular inverse* de *e* e *phi(n)*, sendo que *phi(n)* é calculado através da multiplicação `(p-1) * (q-1)`;


## Armazenamento das chaves RSA (*storekeys*)
Será guardado o par de chaves RSA em dois ficheiros de texto, sendo que um deles irá conter a chave pública `(n,e)` e o outro irá conter a chave privada `(n,d)`, ambos em codificados base64.


## Execução do programa

### Em C

Para compilar o programa em C, basta executar o makefile, através do comando `make`, e será criado um executável chamado *randgen*, outro chamado *rsagen* e outro chamado *performance*.

Para executar o programa *randgen* basta executar o seguinte comando:
```bash
simao@root$ ./randgen <password> <confusion string> <iterations>
```

Nota: Sendo que o resultado será retornado para o *stdout*.

Para executar o programa *rsagen* basta executar o seguinte comando:
```bash
simao@root$ ./rsagen
```

Para executar o programa *performance* basta executar o seguinte comando:
```bash
simao@root$ ./performance
```

Nota: Sendo que a entrada do programa será feita através do *stdin*.

De modo a executar ambos utilizando o *pipe*, basta executar o seguinte comando:
```bash
simao@root$ ./randgen <password> <confusion string> <iterations> | ./rsagen
```

### Em Java

Para compilar o programa em Java, basta executar o seguinte comando:
```bash
ana@root$ javac *.java
```

Para executar o programa *randgen* basta executar o seguinte comando:
```bash
ana@root$ java randgen <password> <confusion string> <iterations>
```

Nota: Sendo que o resultado será retornado para o *stdout*.

Para executar o programa *rsagen* basta executar o seguinte comando:
```bash
ana@root$ java rsagen
```

Nota: Sendo que a entrada do programa será feita através do *stdin*.

De modo a executar ambos utilizando o *pipe*, basta executar o seguinte comando:
```bash
ana@root$ java randgen <password> <confusion string> <iterations> | java rsagen
```


## Testes de performance

Devido á grande computação que é feita pela aplicação *randgen*, apenas foi testado a performance do *setup* do gerador de bytes pseudo-aleatórios.

### C
Por fazer...

### Java
Por fazer...