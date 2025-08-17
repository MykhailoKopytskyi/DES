import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.FileReader;
import java.io.FileWriter;


public class Main {
    /**
     * Provides simple CLI tools for interaction with the DES encryption/decryption algorithm
     * @param args an array of arguments
     */
    public static void main(String[] args) {
        if(args.length < 2) {
            System.out.println("Not enough arguments. Need " + (4-args.length) + " more argument(s).");
            return;
        }

        String action = args[0]; // -e or -d or -g
        if(action.equals("-e")) {
            if(args.length < 4) {
                System.out.println("Not enough arguments. Need " + (4-args.length) + " more argument(s)." );
                return;
            }
            BufferedReader plaintextReader = null;
            BufferedWriter ciphertextWriter = null;
            BufferedReader keyReader = null;

            String plaintextFilePath = args[1];
            String ciphertextFilePath = args[2];
            String keyFilePath = args[3];
            try {
                plaintextReader = new BufferedReader(new FileReader(plaintextFilePath));
                ciphertextWriter = new BufferedWriter(new FileWriter(ciphertextFilePath));
                keyReader = new BufferedReader(new FileReader(keyFilePath));
                String plaintext = "";
                String plaintextLine;

                // Take plaintext from a file
                while((plaintextLine = plaintextReader.readLine()) != null) {
                    plaintext += plaintextLine;
                }

                // Take a key from a file
                long key = Long.parseLong(keyReader.readLine()); 

                // Encrypt the contents of the file
                String ciphertext = DES.encrypt(plaintext, key);

                // Save the ciphertext inside the ciphertext file
                ciphertextWriter.write(ciphertext); 

                plaintextReader.close();
                ciphertextWriter.close();
                keyReader.close();
            }
            catch (IOException e) {
                e.printStackTrace();
            }
        }
        else if (action.equals("-d")) {
           if(args.length < 4) {
                System.out.println("Not enough arguments. Need " + (4-args.length) + " argument(s)." );
                return;
            }
            BufferedReader ciphertextReader = null;
            BufferedWriter plaintextWriter = null;
            BufferedReader keyReader = null;

            String ciphertextFilePath = args[1];
            String plaintextFilePath = args[2];
            String keyFilePath = args[3];
            try {
                ciphertextReader = new BufferedReader(new FileReader(ciphertextFilePath));
                plaintextWriter = new BufferedWriter(new FileWriter(plaintextFilePath));
                keyReader = new BufferedReader(new FileReader(keyFilePath));

                String ciphertext = "";
                String ciphertextLine;

                // Take ciphertext from a file
                while((ciphertextLine = ciphertextReader.readLine()) != null) {
                    ciphertext += ciphertextLine;
                }

                // Take a key from a file
                long key = Long.parseLong(keyReader.readLine()); 

                // Decrypt the contents of the file
                String plaintext = DES.decrypt(ciphertext, key); 

                // Save the plaintext inside the plaintext file
                plaintextWriter.write(plaintext); 

                ciphertextReader.close();
                plaintextWriter.close();
                keyReader.close();
            }
            catch (IOException e) {
                e.printStackTrace();
            }
        }
        else if(action.equals("-g")) {
            String keyFilePath = args[1];
            BufferedWriter keyWriter;
            try {
                keyWriter = new BufferedWriter(new FileWriter(keyFilePath));
                long randomKey = (long) (Math.random() * Long.MAX_VALUE); // Generate random 64 bit key
                keyWriter.write(Long.toString(randomKey)); // Save the generated key in the file
                keyWriter.close();
            }
            catch(IOException e) {
                e.printStackTrace();
            }
        }
        else {
            System.out.println("Must be either -e, -d or -g");
            return;
        }
    }
}
