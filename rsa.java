import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.security.MessageDigest;


 public class SecondProject {
    public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    public static final int SIZE_STREAM = 2048; // Tamanho da chave RSA
    public static final int ITERATIONS = 10; // Número máximo de iterações
    public static final String PASSWORD = "password";
    public static final String CONFUSION_STRING = "abc";
    public static final int SEED =  32; // Tamanho da seed em bytes
    public static final int SHA256_DIGEST_LENGTH = 32; // Tamanho do output do SHA-256 em bytes
    public static void main(String[] args) throws Exception {
        try {
            byte[] random_stream_bytes = randgen(PASSWORD, CONFUSION_STRING, ITERATIONS, SIZE_STREAM / 8);
            
            for(int i = 0; i < random_stream_bytes.length; i++){
                System.out.printf("%02x", random_stream_bytes[i]);
            }
            System.out.println();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

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

    public static boolean verificarPadrao1(byte[] mainArray, byte[] subArray) {
        int mainLength = mainArray.length;
        int subLength = subArray.length;
    
        int mainIndex = 0, subIndex = 0;
    
        while (mainIndex < mainLength && subIndex < subLength) {
            if (mainArray[mainIndex] == subArray[subIndex]) {
                mainIndex++;
                subIndex++;
            } else {
                mainIndex = mainIndex - subIndex + 1; // Restart from the next index in mainArray
                subIndex = 0; // Reset subIndex to start from the beginning of subArray
            }
        }
    
        return (subIndex == subLength); // Check if the entire subArray is traversed
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
        // Converter a string de confusão e a senha em arrays de bytes e arrays de char respetivamente
        char[] passwordChar = password.toCharArray();

        // Derivar a chave usando PBKDF2 com a senha, o salt que é numa maneira inicial, a confusion string e o número de iterações
        PBEKeySpec spec = new PBEKeySpec(passwordChar, confusionString.getBytes(), iterations, (SEED + confusionString.length()) * 8); //256 bits para a chave
        SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        byte[] key_derivator = skf.generateSecret(spec).getEncoded();

        // Cortar a chave derivada para obter a seed
        byte[] bootstrapSeed = new byte[SEED];
        for(int i = 0; i < SEED; i++){
            bootstrapSeed[i] = key_derivator[i];
        }

        // Cortar a chave derivada para obter o padrão de confusão
        byte[] confusionPattern = new byte[confusionString.length()];
        for(int i = 0; i < confusionString.length(); i++){
            confusionPattern[i] = key_derivator[SEED + i];
        }

        byte[] stream = new byte[size];
        for(int iteration = 0; iteration < iterations; iteration++){
           while(true){
                stream = generateRandomBytes(size, bootstrapSeed);

                if(verificarPadrao(confusionPattern, stream)){
                    System.out.println("Found confusion string in generated bytes!");
                    break;
                }
           }
           // Get the last bytes of the stream for the bootstrap seed
            for(int i = 0; i < SEED; i++){
                bootstrapSeed[i] = stream[stream.length - SEED + i];
            }
        }
        return stream;
    }
}
