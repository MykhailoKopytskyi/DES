public class Main {
    public static void main(String[] args) {
        long key = 0b0001001100110100010101110111100110011011101111001101111111110001L;

        long[] arrOfBlocks = {20334, 123, 7836, 99, 23, 0, -21, -45};
        for(long block : arrOfBlocks) {
            long encryptedBlock = DES.encryptBlock(block, key);
            long decryptedBlock = DES.decryptBlock(encryptedBlock, key);
            System.out.println("Block to encrypt: " + block);
            System.out.println("Decrypted block: " + decryptedBlock + "\n");
        }
    }
}
