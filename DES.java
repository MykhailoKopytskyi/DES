public class DES {

    // Extracts the parity bits from 64 bit key. The resulting key is 56 bits, which is also permuted. Done BEFORE we begin the 1st round of encryption
    private static final int[] PC1 = {
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    };


    // Tells how to perform initial permutation of the block BEFORE we begin the 1st round of encryption
    private static final int[] IP = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };


    // Selects 48 bits from the round key of 56 bits. Also permutes the round key
    private static final int[] PC2 = {
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    };

    
    // Expansion table used for expanding the subblock from 32 bits to 48 bits in order to XOR it with the round key
    private static final int[] E = {
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    };


    private static final int[][][] S_BOXES = {
        // S1
        {
            {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
            {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
            {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
            {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
        },
        // S2
        {
            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
            {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
            {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
            {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
        },
        // S3
        {
            {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
            {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
            {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
            {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
        },
        // S4
        {
            {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
            {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
            {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
            {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
        },
        // S5
        {
            {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
            {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
            {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
            {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
        },
        // S6
        {
            {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
            {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
            {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
            {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
        },
        // S7
        {
            {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
            {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
            {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
            {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
        },
        // S8
        {
            {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
            {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
            {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
            {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
        }
    };


    // Permutes the output of the S-box, i.e. the 32 bit block 
    private static final int[] P = {
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25
    };


    // Final permutation on 64 bit block, which is performed AFTER the 16th encryption round. It is the inverse of initial permutation IP
    private static final int[] FP = {
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    };


    private static final int[] numberOfCircularShifts = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};


    /**
     * Performs DES encryption or decryption based on the value of @param reverse
     * @param block 64 bit block of data to be encrypted
     * @param key 64 bit key
     * @param reverse false if encryption should be performed and true otherwise
     * @return encrypted/decrypted block of 64 bits
     */
    private static long processCipher(long block, long key, boolean reverse) {
        block = DES.permuteIP(block); // Permutes the block. Length stays the same - 64 bits
        key = DES.permutePC1(key); // Extracts 8 parity bits and permutes the key. Length is 56 bits

        // Extract left and right subblocks to prepare them for 16 round encryption/decryption
        long leftSubBlock = (block & 0xFFFFFFFF00000000L) >>> 32;
        long rightSubBlock = block & 0x00000000FFFFFFFFL;

        long[] subKeys = DES.generateSubkeys(key); // Generate subkeys for all 16 rounds

        // If reverse is true, then we are in decryption mode and thus, we apply the subkeys in reverse order
        if(reverse) {
            subKeys = DES.reverseArray(subKeys);
        }

        // Perform 16 rounds of encryption/decryption
        for(int i = 0; i < 16; i++) {
            long roundKey = subKeys[i]; // Get the round key
            long tempRightSubBlock = rightSubBlock;

            rightSubBlock = leftSubBlock ^ DES.fiestelRoundFunction(rightSubBlock, roundKey); // Apply Fiestel round function and XOR with left subblock
            leftSubBlock = tempRightSubBlock;
        }
        block = DES.permuteFP((rightSubBlock << 32) | leftSubBlock); // Reverse LR -> RL and perform reverse permutation (with respect to initial one) of the 64 bit block 
        return block;
    }


    /**
     * Performs encryption
     * @param block 64 bit block of data to be encrypted
     * @param key 64 bit key
     * @return encrypted block of 64 bits
     */
    public static long encryptBlock(long block, long key) {
        return DES.processCipher(block, key, false);
    }


    /**
     * Performs decryption
     * @param block 64 bit block of data to be decrypted
     * @param key 64 bit key
     * @return decrypted block of 64 bits
     */
    public static long decryptBlock(long block, long key) {
        return DES.processCipher(block, key, true);
    }


    /**
     * Reverses the array
     * @param arr array to be reversed
     * @return array with the same elements but in reverse order
     */
    private static long[] reverseArray(long[] arr) {
        int i = 0; 
        int j = arr.length - 1;

        while(i < j) {
            long tempEl = arr[i];
            arr[i] = arr[j];
            arr[j] = tempEl;
            i++;
            j--;
        }
        return arr;
    }


    /**
     * The Fiestel round function. It expands the block from 32 to 48 bits and does XOR with the 48 bit key. It then performs S-box substitution and permutation
     * @param block 32 bit block of data to be processed by Fiestel round function
     * @param subkey 48 bit subkey for this round of encryption/decryption
     * @return 32 bit block of processed data, ready for next round of encryption/decryption
     */
    private static long fiestelRoundFunction(long block, long subkey) {
        block = DES.expandBlock(block); // Expand the block
        block = block^subkey; // Encrypt the block
        block = DES.performSubstitution(block);
        block = DES.permuteP(block);
        return block;
    }


    /**
     * BEFORE starting the 1st round of encryption/decryption removes 8 parity bits from the key and permutes the rest
     * @param key 64 bit key to be processed
     * @return 56 bit permuted key
     */
    private static long permutePC1(long key) {
        return permute(key, DES.PC1, 64);
    }


    /**
     * BEFORE starting the 1st round of encryption/decryption performs initial permutation of the 64 bit block of data 
     * @param block 64 bit block of data
     * @return permuted 64 bit block of data
     */
    private static long permuteIP(long block) {
        return permute(block, DES.IP, 64);
    } 


    /**
     * On every round of encryption/decryption selects 48 bits from 56 bit key and permutes them
     * @param key 56 bit key
     * @return 48 bit permuted key
     */
    private static long permutePC2(long key) {
        return permute(key, DES.PC2, 56);
    }


    /**
     * On every round of encryption/decryption expands the 32 bit block of data to 48 bit block
     * @param block 32 bit block of data to be expanded
     * @return expanded 48 bit block of data
     */
    private static long expandBlock(long block) {
        return permute(block, DES.E, 32);
    }


    /**
     * On every round of encryption/decryption permutes the 32 bit block of data (straight after S-box)
     * @param block 32 bit block of data
     * @return permuted 32 bit block of data
     */
    private static long permuteP(long block) {
        return permute(block, DES.P, 32);
    }


    /**
     * AFTER the last round of encryption/decryption permutes the 64 bit block of data (inverse of the permuteIP)
     * @param block 64 bit block of data
     * @return 64 bit permuted block of data
     */
    private static long permuteFP(long block) {
        return permute(block, DES.FP, 64);
    }


    /**
     * On every round of encryption/decryption performs S-box substitution of the 48 bit block of data for 32 bit block
     * @param block 48 bit block of data
     * @return 32 bit block of data 
     */
    private static long performSubstitution(long block) {
        long tempBlock = 0;
        long mask = 0x3FL << 42;
        // For each S-box 
        for(int i = 0; i < DES.S_BOXES.length; i++) {
            tempBlock = tempBlock << 4;
            int sixBitBlock = (int) ((block & mask) >>> (6 * (7-i))); // Extract six bit subblock from the block

            int row = ((0b100000 & sixBitBlock) >>> 4) | (0b000001 & sixBitBlock); // Extract row coordinates for S-box from the six bit subblock
            int column = (0b011110 & sixBitBlock) >>> 1; // Extract column coordinates for S-box from the six bit subblock
            long fourBitBlock = DES.S_BOXES[i][row][column]; // Get the four bit block from the S-box

            tempBlock = tempBlock | fourBitBlock;
            mask = mask >>> 6;
        }
        return tempBlock;
    }


    /**
     * Performs permutation of the component , be it a key or a block of data
     * @param component key or a block of data to be permuted
     * @param table permutation table which defines how to permute the component
     * @param componentLength the number of bits in the component
     * @return permuted component
     */
    private static long permute(long component, int[] table, int componentLength) {
        long temp = 0;
        for(int i = 0; i < table.length; i++) {
            temp = temp << 1;
            int bitPos = componentLength - table[i]; // Calculate which bit to extract
            long mask = 0b1L << bitPos; 

            if((component & mask) != 0) {
                temp = temp | 0b1L;
            }
        }
        return temp;
    }


    /**
     * Performs a circular left shift by 1 bit of the 28 bit @param key
     * @param key 28 bit part of the key
     * @return @param key value shifted left circularly by 1 bit
     */
    private static long circularLeftShiftSubkey28(long subkey) {
        long mask = 0xFFFFFFFL; // Mask to disregard any bit after the 28th bit
        return ((subkey << 1) | (subkey >>> 27)) & mask; 
    }


    /**
     * Performs a separate circular left shift of each of the 2 halves of the 56 bit key
     * @param key 56 bit key to be shifted
     * @return shifted 56 bit key
     */
    private static long circularLeftShiftKey56(long key) {
        long leftSubkey = (key & 0xFFFFFFF0000000L) >>> 28; // Extract the upper 28 bits of the key and shift them right
        long rightSubkey = key & 0x0000000FFFFFFFL; // Extract the lower 28 bits of the key

        // Perform a circular left shift of each of the 28 bit parts of the key
        long leftSubkeyShifted = DES.circularLeftShiftSubkey28(leftSubkey);
        long rightSubkeyShifted = DES.circularLeftShiftSubkey28(rightSubkey);

        return (leftSubkeyShifted << 28) | (rightSubkeyShifted);
    }


    /**
     * Generates an array of subkeys for each each round of encryption/decryption and performs PC2 selection and permutation on each
     * @param key a primary key based on which we generate the subkeys
     * @return an array of subkeys for each round of encryption/decryption
     */
    private static long[] generateSubkeys(long key) {
        long[] subKeys = new long[DES.numberOfCircularShifts.length];
        for(int i = 0; i < DES.numberOfCircularShifts.length; i++) {
            // For each round of encryption/decryption perform 1 or 2 circular left shifts
            for(int j = 0; j < DES.numberOfCircularShifts[i]; j++) {
                key = DES.circularLeftShiftKey56(key);
            }
            subKeys[i] = DES.permutePC2(key); // Select 48 bits from the 56 bit key and permute them
        }
        return subKeys;
    }
}

