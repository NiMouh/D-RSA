import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.util.Random;
import java.io.FileOutputStream;

/**
 * @file: jrandgen.java
 * @author:Ana Raquel Neves Vidal
 * @student number: 118408
 * @author:Simão Augusto Ferreira Andrade
 * @student number: 118345
 * @brief: Geração de bytes aleatórios usando PBKDF2 e SHA-256
 * @date: 2021/04/25
 * 
 * @copyright Copyright (c) 2023
 */

public class jrandgen {

    public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    public static final int SIZE_STREAM = 4096; // Tamanho da chave RSA
    public static final int SEED = 32; // Tamanho da seed em bytes
    public static final int SHA256_DIGEST_LENGTH = 32; // Tamanho do output do SHA-256 em bytes

    public static void main(String[] args) throws Exception {

        if (args.length < 1) {
            System.out.println("Insufficient arguments, insert a mode");
        }

        String MODE = args[0];

        if (MODE.equals("generate")) { // Gerar bytes aleatórios

            if (args.length != 4) {
                System.out.println("Usage: ./jrandgen <mode> <password> <confusion string> <iterations>");
                System.exit(1);
            }

            String PASSWORD = args[1];
            String CONFUSION_STRING = args[2];
            int ITERATIONS = Integer.parseInt(args[3]);

            byte[] pseudoRandomBytes = randgen(PASSWORD, CONFUSION_STRING, ITERATIONS, SIZE_STREAM);

            System.out.write(pseudoRandomBytes);
            System.out.flush();

        } else if (MODE.equals("test")) { // Testar a velocidade do setup do PBKDF2

            int[] password_sizes = { 10000, 100000, 200000 };
            int[] salt_sizes = { 5000, 50000, 100000 };
            int[] iteration_counts = { 1000, 10000, 100000 };

            setupPerformance(password_sizes, salt_sizes, iteration_counts);
        }
    }

    /**
     * @brief: Geração de bytes aleatórios usando PBKDF2 e SHA-256
     * @param: password        - Senha para gerar a chave
     * @param: confusionString - String de confusão para gerar a chave
     * @param: iterations      - Número de iterações para gerar a chave
     * @param: size            - Tamanho do output em bytes
     * 
     * @return: stream - Bytes aleatórios gerados
     */
    public static byte[] randgen(String password, String confusionString, int iterations, int size)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        char[] passwordChar = password.toCharArray();
        byte[] confusionStringBytes = confusionString.getBytes();

        // Derivar a chave usando o algoritmo PBKDF2
        PBEKeySpec spec = new PBEKeySpec(passwordChar, confusionStringBytes, iterations,
                (SEED + confusionString.length()) * 8); // 256 bits para a chave
        SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        byte[] key_derivator = skf.generateSecret(spec).getEncoded();

        // Cortar a chave derivada para obter a seed
        byte[] bootstrapSeed = new byte[SEED];
        for (int i = 0; i < SEED; i++) {
            bootstrapSeed[i] = key_derivator[i];
        }

        // Cortar a chave derivada para obter o padrão de confusão
        byte[] confusionPattern = new byte[confusionString.length()];
        for (int i = 0; i < confusionString.length(); i++) {
            confusionPattern[i] = key_derivator[SEED + i];
        }

        byte[] stream = new byte[size];
        for (int iteration = 0; iteration < iterations; iteration++) {
            while (true) {
                stream = generateRandomBytes(size, bootstrapSeed);

                if (verificarPadrao(confusionPattern, stream)) {
                    break;
                }
            }
            // Obter os ultimos bytes da stream para a bootstrap seed
            for (int i = 0; i < SEED; i++) {
                bootstrapSeed[i] = stream[stream.length - SEED + i];
            }
        }
        return stream;
    }

    /**
     * @brief: Geração de bytes aleatórios usando SHA-256
     * @param: streamSize - Tamanho do output em bytes
     * @param: seed       - Seed para gerar a stream
     * 
     * @return: stream - Bytes aleatórios gerados
     */
    public static byte[] generateRandomBytes(int streamSize, byte[] seed) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] stream = new byte[streamSize];

            for (int index = 0; index < streamSize; index += SHA256_DIGEST_LENGTH) {
                // Usar o SHA-256 para fazer o hash da seed
                byte[] hashOutput = sha256.digest(seed);

                // Copiar o hash do output para a stream
                int bytesToCopy = (index + SHA256_DIGEST_LENGTH > streamSize) ? streamSize - index
                        : SHA256_DIGEST_LENGTH;
                System.arraycopy(hashOutput, 0, stream, index, bytesToCopy);

                // Atualizar o tamanho da seed com o hash do output para a proxima iteração
                System.arraycopy(hashOutput, 0, seed, 0, SHA256_DIGEST_LENGTH);

            }
            return stream;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace(); // Handle the exception appropriately
            return null;
        }
    }

    /**
     * @brief: Verificar se um array de bytes contém um padrão
     * @param: A - Array de bytes a verificar
     * @param: B - Array de bytes que contém o padrão
     * 
     * @return: true - Se o array de bytes contém o padrão
     * @return: false - Se o array de bytes não contém o padrão
     */

    public static boolean verificarPadrao(byte[] A, byte[] B) {

        if (A.length > B.length) {
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
            if (j == A.length) {
                return true;
            }
        }
        return false;
    }

    /**
     * @brief: Remover o byte de sinal de um array de bytes
     * @param data - Array de bytes a remover o byte de sinal
     * @return data - Array de bytes sem o byte de sinal
     */
    public static String encodeToBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    /**
     * @brief Remover o byte de sinal de um array de bytes
     * @param password_sizes   Tamanhos das passwords a testar
     * @param salt_sizes       Tamanhos dos salts a testar
     * @param iteration_counts Número de iterações a testar
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static void setupPerformance(int[] password_sizes, int[] salt_sizes, int[] iteration_counts)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        Random random = new Random();
        String results = "password_size,salt_size,iterations,time_seconds\n";

        for (int password_size : password_sizes) {
            for (int salt_size : salt_sizes) {
                for (int iteration_count : iteration_counts) {

                    // Generate a random password using /dev/urandom
                    String password = "";
                    for (int i = 0; i < password_size; i++) {
                        password += (char) (random.nextInt(26) + 'a');
                    }

                    // Generate a random salt using /dev/urandom
                    String salt = "";
                    for (int i = 0; i < salt_size; i++) {
                        salt += (char) (random.nextInt(26) + 'a');
                    }

                    long startTime = System.currentTimeMillis();

                    char[] passwordChar = password.toCharArray();
                    byte[] saltBytes = salt.getBytes();

                    PBEKeySpec spec = new PBEKeySpec(passwordChar, saltBytes, iteration_count,
                            (SEED + salt.length()) * 8); // 256 bits para a chave
                    SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
                    skf.generateSecret(spec).getEncoded();

                    long endTime = System.currentTimeMillis();

                    long totalTime = endTime - startTime; // time in milliseconds

                    System.out.println("Interações: " + iteration_count + " Tempo: " + totalTime);

                    results += password_size + "," + salt_size + "," + iteration_count + "," + totalTime / 1000.0
                            + "\n";
                }
            }
        }

        try (FileOutputStream output = new FileOutputStream("performance_java.csv")) {
            output.write(results.getBytes());
        } catch (Exception e) {
            System.out.println("Erro ao escrever no ficheiro");
        }
    }
}
