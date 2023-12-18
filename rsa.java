import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import java.io.*;

/**
 * This file contains the implementation of the D-RSA algorithm in Java.
 *
 * @author Ana Raquel Neves Vidal (118408)
 * @author Simão Augusto Ferreira Andrade (118345)
 *
 */
public class RSA {
    public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    public static final int SIZE_STREAM = 2048; // Tamanho da chave RSA
    public static final int ITERATIONS = 10; // Número máximo de iterações
    public static final String PASSWORD = "password";
    public static final String CONFUSION_STRING = "abc";
    public static final int SEED =  32; // Tamanho da seed em bytes
    public static final int SHA256_DIGEST_LENGTH = 32; // Tamanho do output do SHA-256 em bytes
    public static final BigInteger e = BigInteger.valueOf(65537); // Valor de e
    
    public static void main(String[] args) throws Exception {
        
        // Generate random stream of bytes
        byte[] random_stream_bytes = randgen(PASSWORD, CONFUSION_STRING, ITERATIONS, SIZE_STREAM / 8);

        // Generate the key pair
        BigInteger[][] keyPair = generateKeyPair(random_stream_bytes);

        // Store the key pair in files
        storeKeyPair(keyPair);
    }

    /**
     * Generates a random stream of bytes
     * 
     * @param streamSize The size of the stream
     * @param seed The seed
     * 
     * @return The random stream of bytes
    */
    public static byte[] generateRandomBytes(int streamSize, byte[] seed) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] stream = new byte[streamSize];

            for (int index = 0; index < streamSize; index += SHA256_DIGEST_LENGTH) {
                // Use SHA-256 to hash the seed
                byte[] hashOutput = sha256.digest(seed);

                // Copy the hash output to the stream
                int bytesToCopy = (index + SHA256_DIGEST_LENGTH > streamSize) ? streamSize - index : SHA256_DIGEST_LENGTH;
                
                // Copy the hash output to the stream
                System.arraycopy(hashOutput, 0, stream, index, bytesToCopy);

                // Update the seed with the hash output for the next iteration
                System.arraycopy(hashOutput, 0, seed, 0, SHA256_DIGEST_LENGTH);

            }
            
            return stream;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace(); // Handle the exception appropriately
            return null;
        }
    }

    public static String encodeToBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static boolean verificarPadrao(byte[] A, byte[] B) {

        if(A.length > B.length){
            System.out.println("A is bigger than B");
            return false;
        }

        for (int i = 0; i <= B.length - A.length; i++) {
            int j;
            for (j = 0; j < A.length; j++) {
                if (B[i + j] != A[j]) {
                    break;
                }
            }
            if(j == A.length){
                return true;
            }
        }   
        return false;
    }
    
    public static byte[] randgen(String password, String confusionString, int iterations, int size)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        // Derivar a chave usando PBKDF2 com a senha, o salt que é numa maneira inicial, a confusion string e o número de iterações
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), confusionString.getBytes(), iterations, (SEED + confusionString.length()) * 8); //256 bits para a chave
        SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        byte[] key_derivator = skf.generateSecret(spec).getEncoded();

        byte[] bootstrapSeed = new byte[SEED];
        bootstrapSeed = Arrays.copyOfRange(key_derivator, 0, SEED);

        byte[] confusionPattern = new byte[confusionString.length()];
        confusionPattern = Arrays.copyOfRange(key_derivator, SEED, SEED + confusionString.length());

        byte[] stream = new byte[size];
        for(int iteration = 0; iteration < iterations; iteration++){
           while(true){
                stream = generateRandomBytes(size, bootstrapSeed);

                if(verificarPadrao(confusionPattern, stream)){
                    break;
                }
           }
           
           bootstrapSeed = Arrays.copyOfRange(stream, stream.length - SEED, stream.length); // pass the stream to the bootstrap seed
        }
        return stream;
    }

    /**
     * Generates a key pair
     * 
     * @param random_stream_bytes The random stream of bytes
     * 
     * @return The key pair
    */
    public static BigInteger[][] generateKeyPair(byte[] random_stream_bytes) throws Exception {
        // Dividir o stream aleatório em duas partes p e q
        byte[] p_bytes = Arrays.copyOfRange(random_stream_bytes, 0, random_stream_bytes.length / 2);
        byte[] q_bytes = Arrays.copyOfRange(random_stream_bytes, random_stream_bytes.length / 2, random_stream_bytes.length);

        // tornar o p e q como bignumbers e certificar que são primos
        BigInteger p = new BigInteger(1, p_bytes).nextProbablePrime();
        BigInteger q = new BigInteger(1, q_bytes).nextProbablePrime();

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
     * Stores the public key in a file
     * 
     * @param keyPair The key pair to store
    */
    public static void storeKeyPair(BigInteger[][] keyPair) throws IOException {
        // Get the public key
        BigInteger[] public_key = keyPair[0];

        // passar o n e o e para um array de bytes
        byte[] n_bytes = public_key[0].toByteArray();
        byte[] e_bytes = public_key[1].toByteArray();

        // juntar o n e o e num array de bytes
        byte[] public_key_bytes = new byte[n_bytes.length + e_bytes.length];
        System.arraycopy(n_bytes, 0, public_key_bytes, 0, n_bytes.length);
        System.arraycopy(e_bytes, 0, public_key_bytes, n_bytes.length, e_bytes.length);

        // codificar o array de bytes para base64
        String public_key_base64 = encodeToBase64(public_key_bytes);

        // imprimir a chave publica
        System.out.println("------BEGIN PUBLIC KEY------\n" + public_key_base64 + "\n------END PUBLIC KEY------\n");

        // Get the private key
        BigInteger[] private_key = keyPair[1];

        // passar o n e o d para um array de bytes
        byte[] n_bytes_priv = private_key[0].toByteArray();
        byte[] d_bytes_priv = private_key[1].toByteArray();

        // juntar o n e o d num array de bytes
        byte[] private_key_bytes = new byte[n_bytes_priv.length + d_bytes_priv.length];
        System.arraycopy(n_bytes_priv, 0, private_key_bytes, 0, n_bytes_priv.length);
        System.arraycopy(d_bytes_priv, 0, private_key_bytes, n_bytes_priv.length, d_bytes_priv.length);

        // codificar o array de bytes para base64
        String private_key_base64 = encodeToBase64(private_key_bytes);

        // imprimir a chave privada
        System.out.println("------BEGIN PRIVATE KEY------\n" + private_key_base64 + "\n------END PRIVATE KEY------\n");

        // Store the public key in a file
        try (FileOutputStream outputStream = new FileOutputStream("public_key.pem")) {
            outputStream.write(public_key_base64.getBytes());
        }catch(Exception e){
            System.out.println("Erro ao escrever no ficheiro");
        }

        // Store the private key in a file
        try (FileOutputStream outputStream = new FileOutputStream("private_key.pem")) {
            outputStream.write(private_key_base64.getBytes());
        }catch(Exception e){
            System.out.println("Erro ao escrever no ficheiro");
        }
    }
}
