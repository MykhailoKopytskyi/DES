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
        // If there are not enough arguments, then we terminate early
        // We expect format of input like this: --encrypt/decrypt --plaintext/filename "..." --key "..."
        if(args.length < 5) {
            System.out.println("Not enough arguments");
            return;
        }

        String operation = args[0]; // --encrypt or --decrypt
        String inputType = args[1]; // --plaintext or --filename
        long key = Long.parseLong(args[4]); // Parse the key into a long value

        if(operation.equals("--encrypt")) {
            if(inputType.equals("--plaintext")) {
                String plaintext = args[2]; // Plaintext to be encrypted
            }
            else if(inputType.equals("--filename")) {
                BufferedReader br = null;
                BufferedWriter bw = null;
                String fileName = args[2];
                try {
                    br = new BufferedReader(new FileReader(fileName));
                    bw = new BufferedWriter(new FileWriter("ciphertext.txt"));
                    String accLine = "";
                    String line;
                    // Read the contents of a file into a single variable
                    while((line = br.readLine()) != null) {
                        accLine += line;
                    }
                    String ciphertext = DES.encrypt(accLine, key); // Encrypt the contents of the file
                    bw.write(ciphertext); // Save the ciphertext inside ciphertext.txt file
                    br.close();
                    bw.close();
                }
               
                catch (IOException e) {
                    e.printStackTrace();
                }
            }
            else {
                System.out.println("Must be either --plaintext OR --filename");
                return;
            }
        }
        else if (operation.equals("--decrypt")) {
            if(inputType.equals("--ciphertext")) {
                String ciphertext = args[2];
            }
            else if(inputType.equals("--filename")) {
                BufferedReader br = null;
                BufferedWriter bw = null;
                String fileName = args[2];
                try {
                    br = new BufferedReader(new FileReader(fileName));
                    bw = new BufferedWriter(new FileWriter("plaintext.txt"));
                    String accLine = "";
                    String line;
                    // Read the contents of a file into a single variable
                    while((line = br.readLine()) != null) {
                        accLine += line;
                    }
                    String plaintext = DES.decrypt(accLine, key); // Decrypt the contents of the file
                    bw.write(plaintext); // Save the plaintext inside ciphertext.txt file
                    br.close();
                    bw.close();
                }
               
                catch (IOException e) {
                    e.printStackTrace();
                }
            }
            else {
                System.out.println("Must be either --ciphertext OR --filename");
                return;
            }
        }
        else {
            System.out.println("Must be either --encrypt or --decrypt");
            return;
        }
    }
}
