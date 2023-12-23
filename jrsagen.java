import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Base64;

/**
 * @file: jrsagen.java
 * @author:Ana Raquel Neves Vidal 
 * @student number: 118408
 * @author:Simão Augusto Ferreira Andrade
 * @student number: 118345
 * @brief: Geração de chaves RSA
 * @date: 2021/04/25
 */
public class jrsagen {
    public static final int PRIME_SIZE = 256; // Tamanho dos primos p e q em bits
    public static final BigInteger e = BigInteger.valueOf(65537); // Valor de e

    /** 
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {

        // Obter os bytes do stdin
        byte[] random_stream_bytes = System.in.readAllBytes();

        byte[] firstBytes = Arrays.copyOfRange(random_stream_bytes, 0, PRIME_SIZE);
        
        // Generate the key pair
        BigInteger[][] keyPair = rsagen(firstBytes);

        // Store the key pair in files
        storeKeyPair(keyPair);
    }

    /**
     * @brief: Geração de chaves RSA
     * @param: random_stream_bytes - Bytes aleatórios gerados
     * 
     * @return: keyPair - Chave pública e privada
     */

    public static BigInteger[][] rsagen(byte[] random_stream_bytes) throws Exception {

        // Dividir o stream aleatório em duas partes p e q
        byte[] p_bytes = Arrays.copyOfRange(random_stream_bytes, 0, random_stream_bytes.length / 2);
        byte[] q_bytes = Arrays.copyOfRange(random_stream_bytes, random_stream_bytes.length / 2, random_stream_bytes.length);

        //tornar o p e q como bignumbers
        BigInteger p = new BigInteger(1, p_bytes);
        BigInteger q = new BigInteger(1, q_bytes);
       
        // Verifica se p não é primo
        while (!p.isProbablePrime(100)) {
            p = p.nextProbablePrime();
            
        }

        // Verifica se q não é primo
        while (!q.isProbablePrime(100)) {
            q = q.nextProbablePrime();
        }
        

        // Calcular o n
        BigInteger n = p.multiply(q);

        // Calcular o phi
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // Calcular o d
        BigInteger d = e.modInverse(phi);

        // criar a chave publica pub=(n,e)
        BigInteger[] public_key = {n, e};

        // criar a minha chave privada priv=(n,d)
        BigInteger[] private_key = {n, d};

        //colocar num array o pub e priv
        BigInteger[][] keyPair = {public_key, private_key};

        return keyPair;
    }

    /**
     * @brief: Codificar um array de bytes para base64
     * @param: bytes - Array de bytes a codificar
     * 
     * @return: base64 - Array de bytes codificado em base64
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    /**
     * @brief: Geração de DER encoding para a chave pública
     * @param: N - n
     * @param: e - e
     * 
     * @return: derEncoding - DER encoding para a chave pública
     */
    public static byte[] generateDEREncodingPublic(BigInteger N, BigInteger e) {
        byte[] NBytes = removeSignByte(N.toByteArray()); // Remove byte de sinal se existir
        byte[] eBytes = removeSignByte(e.toByteArray()); // Remove byte de sinal se existir

        // Montando a estrutura DER
        int totalLength = 4 + NBytes.length + 2 + eBytes.length; // 4 bytes para cabeçalho + tamanho n + tamanho e
        byte[] derEncoding = new byte[totalLength];

        derEncoding[0] = 0x30; // Byte de início da sequência
        derEncoding[1] = (byte) (totalLength - 6); // Tamanho total do bloco n + e

        int index = 2;
        derEncoding[index++] = 0x02; // Byte de separação para n
        derEncoding[index++] = (byte) NBytes.length; // Tamanho de n

        // Copiar os bytes de n para a representação DER
        System.arraycopy(NBytes, 0, derEncoding, index, NBytes.length);
        index += NBytes.length;

        derEncoding[index++] = 0x02; // Byte de separação para e
        derEncoding[index++] = (byte) eBytes.length; // Tamanho de e

        // Copiar os bytes de e para a representação DER
        System.arraycopy(eBytes, 0, derEncoding, index, eBytes.length);

        return derEncoding;
    }

    /**
     * @brief: Geração de DER encoding para a chave privada
     * @param: N = p*q - n
     * @param: d e.modInverse(phi) - d
     * 
     * @return: derEncoding - DER encoding para a chave privada
     */
    public static byte[] generateDEREncodingPrivate(BigInteger n, BigInteger d) {
        byte[] NBytes = removeSignByte(n.toByteArray()); // Remove byte de sinal se existir
        byte[] dBytes = removeSignByte(d.toByteArray());

        // Calculate total length for the DER encoding
        int totalLength = 6 + NBytes.length + dBytes.length;
        int index = 0;
        byte[] derEncoding = new byte[totalLength];

        derEncoding[index++] = 0x30; // Byte of sequence start
        derEncoding[index++] = (byte) (totalLength - 6); // Total block length

        derEncoding[index++] = 0x02; // Byte for p
        derEncoding[index++] = (byte) NBytes.length; // p size
        System.arraycopy(NBytes, 0, derEncoding, index, NBytes.length);
        index += NBytes.length;

        derEncoding[index++] = 0x02; // Byte for d
        derEncoding[index++] = (byte) dBytes.length; // d size
        System.arraycopy(dBytes, 0, derEncoding, index, dBytes.length);

        return derEncoding;
    }

    /**
     * @brief: Codificar um array de bytes para base64
     * @param: bytes - Array de bytes a codificar
     * 
     * @return: base64 - Array de bytes codificado em base64
     */
    public static byte[] removeSignByte(byte[] bytes) {
        if (bytes[0] == 0) {
            byte[] result = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, result, 0, result.length);
            return result;
        }
        return bytes;
    }
    
    /**
     * @brief: Codificar um array de bytes para base64
     * @param: bytes - Array de bytes a codificar
     * 
     * @return: base64 - Array de bytes codificado em base64
     */
    public static void storeKeyPair(BigInteger[][] keyPair) throws IOException {
        // Get the public key
        BigInteger[] public_key = keyPair[0];

        // juntar o n e o e num array de bytes
        byte[] public_key_bytes = generateDEREncodingPublic(public_key[0], public_key[1]);

        // codificar o array de bytes para base64
        String public_key_base64 = "------BEGIN PUBLIC KEY------\n" + encodeToBase64(public_key_bytes) + "\n------END PUBLIC KEY------\n";

        // Save Public Key in PEM format
        try (FileOutputStream outputStream = new FileOutputStream("public_key.pem")) {
            outputStream.write(public_key_base64.getBytes());
        }catch(Exception e){
            System.out.println("Erro ao escrever no ficheiro");
        }

        // Get the private key
        BigInteger[] private_key = keyPair[1];

        // juntar o n e o e num array de bytes
        byte[] private_key_bytes = generateDEREncodingPrivate(private_key[0], private_key[1]);

        // codificar o array de bytes para base64
        String private_key_base64 = "------BEGIN PRIVATE KEY------\n" +  encodeToBase64(private_key_bytes) + "\n------END PRIVATE KEY------\n";

        // Store the private key in a file
        try (FileOutputStream outputStream = new FileOutputStream("private_key.pem")) {
            outputStream.write(private_key_base64.getBytes());
        }catch(Exception e){
            System.out.println("Erro ao escrever no ficheiro");
        }
    }

    /**
     * @brief: Codificar um array de bytes para base64
     * @param: data - Array de bytes a codificar
     * 
     * @return: base64 - Array de bytes codificado em base64
     */
    public static String encodeToBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
}
