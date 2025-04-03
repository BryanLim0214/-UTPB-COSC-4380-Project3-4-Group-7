import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Implementation of the AES (Advanced Encryption Standard) algorithm
 * in both ECB and CBC modes with debugging capabilities.
 */
public class AES {
    // Debug flag to control output
    private static boolean DEBUG = false;

    // AES constants
    private static final int BLOCK_SIZE = 16; // 128 bits = 16 bytes
    private static final int ROUNDS = 10;     // 10 rounds for AES-128

    // S-box for SubBytes operation
    private static final byte[] S_BOX = {
            (byte)0x63, (byte)0x7c, (byte)0x77, (byte)0x7b, (byte)0xf2, (byte)0x6b, (byte)0x6f, (byte)0xc5,
            (byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2b, (byte)0xfe, (byte)0xd7, (byte)0xab, (byte)0x76,
            (byte)0xca, (byte)0x82, (byte)0xc9, (byte)0x7d, (byte)0xfa, (byte)0x59, (byte)0x47, (byte)0xf0,
            (byte)0xad, (byte)0xd4, (byte)0xa2, (byte)0xaf, (byte)0x9c, (byte)0xa4, (byte)0x72, (byte)0xc0,
            (byte)0xb7, (byte)0xfd, (byte)0x93, (byte)0x26, (byte)0x36, (byte)0x3f, (byte)0xf7, (byte)0xcc,
            (byte)0x34, (byte)0xa5, (byte)0xe5, (byte)0xf1, (byte)0x71, (byte)0xd8, (byte)0x31, (byte)0x15,
            (byte)0x04, (byte)0xc7, (byte)0x23, (byte)0xc3, (byte)0x18, (byte)0x96, (byte)0x05, (byte)0x9a,
            (byte)0x07, (byte)0x12, (byte)0x80, (byte)0xe2, (byte)0xeb, (byte)0x27, (byte)0xb2, (byte)0x75,
            (byte)0x09, (byte)0x83, (byte)0x2c, (byte)0x1a, (byte)0x1b, (byte)0x6e, (byte)0x5a, (byte)0xa0,
            (byte)0x52, (byte)0x3b, (byte)0xd6, (byte)0xb3, (byte)0x29, (byte)0xe3, (byte)0x2f, (byte)0x84,
            (byte)0x53, (byte)0xd1, (byte)0x00, (byte)0xed, (byte)0x20, (byte)0xfc, (byte)0xb1, (byte)0x5b,
            (byte)0x6a, (byte)0xcb, (byte)0xbe, (byte)0x39, (byte)0x4a, (byte)0x4c, (byte)0x58, (byte)0xcf,
            (byte)0xd0, (byte)0xef, (byte)0xaa, (byte)0xfb, (byte)0x43, (byte)0x4d, (byte)0x33, (byte)0x85,
            (byte)0x45, (byte)0xf9, (byte)0x02, (byte)0x7f, (byte)0x50, (byte)0x3c, (byte)0x9f, (byte)0xa8,
            (byte)0x51, (byte)0xa3, (byte)0x40, (byte)0x8f, (byte)0x92, (byte)0x9d, (byte)0x38, (byte)0xf5,
            (byte)0xbc, (byte)0xb6, (byte)0xda, (byte)0x21, (byte)0x10, (byte)0xff, (byte)0xf3, (byte)0xd2,
            (byte)0xcd, (byte)0x0c, (byte)0x13, (byte)0xec, (byte)0x5f, (byte)0x97, (byte)0x44, (byte)0x17,
            (byte)0xc4, (byte)0xa7, (byte)0x7e, (byte)0x3d, (byte)0x64, (byte)0x5d, (byte)0x19, (byte)0x73,
            (byte)0x60, (byte)0x81, (byte)0x4f, (byte)0xdc, (byte)0x22, (byte)0x2a, (byte)0x90, (byte)0x88,
            (byte)0x46, (byte)0xee, (byte)0xb8, (byte)0x14, (byte)0xde, (byte)0x5e, (byte)0x0b, (byte)0xdb,
            (byte)0xe0, (byte)0x32, (byte)0x3a, (byte)0x0a, (byte)0x49, (byte)0x06, (byte)0x24, (byte)0x5c,
            (byte)0xc2, (byte)0xd3, (byte)0xac, (byte)0x62, (byte)0x91, (byte)0x95, (byte)0xe4, (byte)0x79,
            (byte)0xe7, (byte)0xc8, (byte)0x37, (byte)0x6d, (byte)0x8d, (byte)0xd5, (byte)0x4e, (byte)0xa9,
            (byte)0x6c, (byte)0x56, (byte)0xf4, (byte)0xea, (byte)0x65, (byte)0x7a, (byte)0xae, (byte)0x08,
            (byte)0xba, (byte)0x78, (byte)0x25, (byte)0x2e, (byte)0x1c, (byte)0xa6, (byte)0xb4, (byte)0xc6,
            (byte)0xe8, (byte)0xdd, (byte)0x74, (byte)0x1f, (byte)0x4b, (byte)0xbd, (byte)0x8b, (byte)0x8a,
            (byte)0x70, (byte)0x3e, (byte)0xb5, (byte)0x66, (byte)0x48, (byte)0x03, (byte)0xf6, (byte)0x0e,
            (byte)0x61, (byte)0x35, (byte)0x57, (byte)0xb9, (byte)0x86, (byte)0xc1, (byte)0x1d, (byte)0x9e,
            (byte)0xe1, (byte)0xf8, (byte)0x98, (byte)0x11, (byte)0x69, (byte)0xd9, (byte)0x8e, (byte)0x94,
            (byte)0x9b, (byte)0x1e, (byte)0x87, (byte)0xe9, (byte)0xce, (byte)0x55, (byte)0x28, (byte)0xdf,
            (byte)0x8c, (byte)0xa1, (byte)0x89, (byte)0x0d, (byte)0xbf, (byte)0xe6, (byte)0x42, (byte)0x68,
            (byte)0x41, (byte)0x99, (byte)0x2d, (byte)0x0f, (byte)0xb0, (byte)0x54, (byte)0xbb, (byte)0x16
    };

    // Inverse S-box for inverse SubBytes operation
    private static final byte[] INV_S_BOX = {
            (byte)0x52, (byte)0x09, (byte)0x6a, (byte)0xd5, (byte)0x30, (byte)0x36, (byte)0xa5, (byte)0x38,
            (byte)0xbf, (byte)0x40, (byte)0xa3, (byte)0x9e, (byte)0x81, (byte)0xf3, (byte)0xd7, (byte)0xfb,
            (byte)0x7c, (byte)0xe3, (byte)0x39, (byte)0x82, (byte)0x9b, (byte)0x2f, (byte)0xff, (byte)0x87,
            (byte)0x34, (byte)0x8e, (byte)0x43, (byte)0x44, (byte)0xc4, (byte)0xde, (byte)0xe9, (byte)0xcb,
            (byte)0x54, (byte)0x7b, (byte)0x94, (byte)0x32, (byte)0xa6, (byte)0xc2, (byte)0x23, (byte)0x3d,
            (byte)0xee, (byte)0x4c, (byte)0x95, (byte)0x0b, (byte)0x42, (byte)0xfa, (byte)0xc3, (byte)0x4e,
            (byte)0x08, (byte)0x2e, (byte)0xa1, (byte)0x66, (byte)0x28, (byte)0xd9, (byte)0x24, (byte)0xb2,
            (byte)0x76, (byte)0x5b, (byte)0xa2, (byte)0x49, (byte)0x6d, (byte)0x8b, (byte)0xd1, (byte)0x25,
            (byte)0x72, (byte)0xf8, (byte)0xf6, (byte)0x64, (byte)0x86, (byte)0x68, (byte)0x98, (byte)0x16,
            (byte)0xd4, (byte)0xa4, (byte)0x5c, (byte)0xcc, (byte)0x5d, (byte)0x65, (byte)0xb6, (byte)0x92,
            (byte)0x6c, (byte)0x70, (byte)0x48, (byte)0x50, (byte)0xfd, (byte)0xed, (byte)0xb9, (byte)0xda,
            (byte)0x5e, (byte)0x15, (byte)0x46, (byte)0x57, (byte)0xa7, (byte)0x8d, (byte)0x9d, (byte)0x84,
            (byte)0x90, (byte)0xd8, (byte)0xab, (byte)0x00, (byte)0x8c, (byte)0xbc, (byte)0xd3, (byte)0x0a,
            (byte)0xf7, (byte)0xe4, (byte)0x58, (byte)0x05, (byte)0xb8, (byte)0xb3, (byte)0x45, (byte)0x06,
            (byte)0xd0, (byte)0x2c, (byte)0x1e, (byte)0x8f, (byte)0xca, (byte)0x3f, (byte)0x0f, (byte)0x02,
            (byte)0xc1, (byte)0xaf, (byte)0xbd, (byte)0x03, (byte)0x01, (byte)0x13, (byte)0x8a, (byte)0x6b,
            (byte)0x3a, (byte)0x91, (byte)0x11, (byte)0x41, (byte)0x4f, (byte)0x67, (byte)0xdc, (byte)0xea,
            (byte)0x97, (byte)0xf2, (byte)0xcf, (byte)0xce, (byte)0xf0, (byte)0xb4, (byte)0xe6, (byte)0x73,
            (byte)0x96, (byte)0xac, (byte)0x74, (byte)0x22, (byte)0xe7, (byte)0xad, (byte)0x35, (byte)0x85,
            (byte)0xe2, (byte)0xf9, (byte)0x37, (byte)0xe8, (byte)0x1c, (byte)0x75, (byte)0xdf, (byte)0x6e,
            (byte)0x47, (byte)0xf1, (byte)0x1a, (byte)0x71, (byte)0x1d, (byte)0x29, (byte)0xc5, (byte)0x89,
            (byte)0x6f, (byte)0xb7, (byte)0x62, (byte)0x0e, (byte)0xaa, (byte)0x18, (byte)0xbe, (byte)0x1b,
            (byte)0xfc, (byte)0x56, (byte)0x3e, (byte)0x4b, (byte)0xc6, (byte)0xd2, (byte)0x79, (byte)0x20,
            (byte)0x9a, (byte)0xdb, (byte)0xc0, (byte)0xfe, (byte)0x78, (byte)0xcd, (byte)0x5a, (byte)0xf4,
            (byte)0x1f, (byte)0xdd, (byte)0xa8, (byte)0x33, (byte)0x88, (byte)0x07, (byte)0xc7, (byte)0x31,
            (byte)0xb1, (byte)0x12, (byte)0x10, (byte)0x59, (byte)0x27, (byte)0x80, (byte)0xec, (byte)0x5f,
            (byte)0x60, (byte)0x51, (byte)0x7f, (byte)0xa9, (byte)0x19, (byte)0xb5, (byte)0x4a, (byte)0x0d,
            (byte)0x2d, (byte)0xe5, (byte)0x7a, (byte)0x9f, (byte)0x93, (byte)0xc9, (byte)0x9c, (byte)0xef,
            (byte)0xa0, (byte)0xe0, (byte)0x3b, (byte)0x4d, (byte)0xae, (byte)0x2a, (byte)0xf5, (byte)0xb0,
            (byte)0xc8, (byte)0xeb, (byte)0xbb, (byte)0x3c, (byte)0x83, (byte)0x53, (byte)0x99, (byte)0x61,
            (byte)0x17, (byte)0x2b, (byte)0x04, (byte)0x7e, (byte)0xba, (byte)0x77, (byte)0xd6, (byte)0x26,
            (byte)0xe1, (byte)0x69, (byte)0x14, (byte)0x63, (byte)0x55, (byte)0x21, (byte)0x0c, (byte)0x7d
    };

    // Rcon values for key expansion
    private static final int[] RCON = {
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    /**
     * Set the debug flag to enable/disable debug output
     * @param debug true to enable debug output, false to disable
     */
    public static void setDebug(boolean debug) {
        DEBUG = debug;
    }

    /**
     * Encrypts a plaintext string using AES in either ECB or CBC mode
     * @param plaintext The plaintext string to encrypt
     * @param keyString The key string (will be padded/truncated to 16 bytes)
     * @param isCBC true for CBC mode, false for ECB mode
     * @return Base64-encoded encrypted string
     */
    public static String encrypt(String plaintext, String keyString, boolean isCBC) {
        if (DEBUG) {
            System.out.println("========== AES ENCRYPTION ==========");
            System.out.println("Plaintext: " + plaintext);
            System.out.println("Key: " + keyString);
            System.out.println("Mode: " + (isCBC ? "CBC" : "ECB"));
        }

        // Convert inputs to byte arrays
        byte[] input = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] key = prepareKey(keyString);

        // Pad input to multiple of 16 bytes (PKCS#7 padding)
        input = padPKCS7(input);

        // Generate key schedule
        byte[][] keySchedule = keyExpansion(key);

        if (DEBUG) {
            System.out.println("\nKey Schedule:");
            for (int i = 0; i < keySchedule.length; i++) {
                System.out.println("Round " + i + ": " + bytesToHex(keySchedule[i]));
            }
        }

        // Process each block
        byte[] output = new byte[input.length];
        byte[] iv = new byte[BLOCK_SIZE];  // Initialization vector for CBC (all zeros)

        for (int i = 0; i < input.length; i += BLOCK_SIZE) {
            byte[] block = new byte[BLOCK_SIZE];
            System.arraycopy(input, i, block, 0, BLOCK_SIZE);

            if (DEBUG) {
                System.out.println("\nProcessing block " + (i / BLOCK_SIZE + 1) + ":");
                System.out.println("Input block: " + bytesToHex(block));
            }

            // For CBC mode, XOR with previous ciphertext block (or IV for first block)
            if (isCBC) {
                xorBlocks(block, iv);
                if (DEBUG) {
                    System.out.println("After XOR with IV/previous: " + bytesToHex(block));
                }
            }

            // Encrypt the block
            block = encryptBlock(block, keySchedule);

            // Copy to output
            System.arraycopy(block, 0, output, i, BLOCK_SIZE);

            // For CBC mode, update IV for next block
            if (isCBC) {
                System.arraycopy(block, 0, iv, 0, BLOCK_SIZE);
            }

            if (DEBUG) {
                System.out.println("Output block: " + bytesToHex(block));
            }
        }

        // Encode result as Base64
        String result = Base64.getEncoder().encodeToString(output);

        if (DEBUG) {
            System.out.println("\nFinal ciphertext (Base64): " + result);
            System.out.println("===================================");
        }

        return result;
    }

    /**
     * Decrypts a ciphertext string using AES in either ECB or CBC mode
     * @param ciphertext The Base64-encoded ciphertext
     * @param keyString The key string (will be padded/truncated to 16 bytes)
     * @param isCBC true for CBC mode, false for ECB mode
     * @return The decrypted plaintext string
     */
    public static String decrypt(String ciphertext, String keyString, boolean isCBC) {
        if (DEBUG) {
            System.out.println("========== AES DECRYPTION ==========");
            System.out.println("Ciphertext (Base64): " + ciphertext);
            System.out.println("Key: " + keyString);
            System.out.println("Mode: " + (isCBC ? "CBC" : "ECB"));
        }

        // Decode Base64 input
        byte[] input = Base64.getDecoder().decode(ciphertext);
        byte[] key = prepareKey(keyString);

        // Generate key schedule
        byte[][] keySchedule = keyExpansion(key);

        if (DEBUG) {
            System.out.println("\nKey Schedule:");
            for (int i = 0; i < keySchedule.length; i++) {
                System.out.println("Round " + i + ": " + bytesToHex(keySchedule[i]));
            }
        }

        // Process each block
        byte[] output = new byte[input.length];
        byte[] iv = new byte[BLOCK_SIZE];  // Initialization vector for CBC (all zeros)
        byte[] prevBlock = new byte[BLOCK_SIZE]; // For CBC mode, store previous block

        for (int i = 0; i < input.length; i += BLOCK_SIZE) {
            byte[] block = new byte[BLOCK_SIZE];
            System.arraycopy(input, i, block, 0, BLOCK_SIZE);

            if (DEBUG) {
                System.out.println("\nProcessing block " + (i / BLOCK_SIZE + 1) + ":");
                System.out.println("Input block: " + bytesToHex(block));
            }

            // Store current block for CBC mode (before decryption)
            if (isCBC) {
                System.arraycopy(block, 0, prevBlock, 0, BLOCK_SIZE);
            }

            // Decrypt the block
            block = decryptBlock(block, keySchedule);

            // For CBC mode, XOR with previous ciphertext block (or IV for first block)
            if (isCBC) {
                if (i == 0) {
                    xorBlocks(block, iv);
                } else {
                    byte[] temp = new byte[BLOCK_SIZE];
                    System.arraycopy(input, i - BLOCK_SIZE, temp, 0, BLOCK_SIZE);
                    xorBlocks(block, temp);
                }

                if (DEBUG) {
                    System.out.println("After XOR with IV/previous: " + bytesToHex(block));
                }
            }

            // Copy to output
            System.arraycopy(block, 0, output, i, BLOCK_SIZE);

            if (DEBUG) {
                System.out.println("Output block: " + bytesToHex(block));
            }
        }

        // Remove PKCS#7 padding
        output = removePKCS7Padding(output);

        // Convert to string
        String result = new String(output, StandardCharsets.UTF_8);

        if (DEBUG) {
            System.out.println("\nFinal plaintext: " + result);
            System.out.println("===================================");
        }

        return result;
    }

    /**
     * Encrypts a single 16-byte block using AES
     * @param block The 16-byte input block
     * @param keySchedule The expanded key schedule
     * @return The encrypted 16-byte block
     */
    private static byte[] encryptBlock(byte[] block, byte[][] keySchedule) {
        byte[] state = new byte[BLOCK_SIZE];
        System.arraycopy(block, 0, state, 0, BLOCK_SIZE);

        // Initial round: AddRoundKey
        if (DEBUG) {
            System.out.println("\nRound 0:");
            System.out.println("Start state: " + bytesToHex(state));
            System.out.println("Round key: " + bytesToHex(keySchedule[0]));
        }

        addRoundKey(state, keySchedule[0]);

        if (DEBUG) {
            System.out.println("After AddRoundKey: " + bytesToHex(state));
        }

        // Main rounds
        for (int round = 1; round < ROUNDS; round++) {
            if (DEBUG) {
                System.out.println("\nRound " + round + ":");
                System.out.println("Start state: " + bytesToHex(state));
            }

            // SubBytes
            subBytes(state);
            if (DEBUG) {
                System.out.println("After SubBytes: " + bytesToHex(state));
            }

            // ShiftRows
            shiftRows(state);
            if (DEBUG) {
                System.out.println("After ShiftRows: " + bytesToHex(state));
            }

            // MixColumns
            mixColumns(state);
            if (DEBUG) {
                System.out.println("After MixColumns: " + bytesToHex(state));
            }

            // AddRoundKey
            if (DEBUG) {
                System.out.println("Round key: " + bytesToHex(keySchedule[round]));
            }

            addRoundKey(state, keySchedule[round]);

            if (DEBUG) {
                System.out.println("After AddRoundKey: " + bytesToHex(state));
            }
        }

        // Final round (no MixColumns)
        if (DEBUG) {
            System.out.println("\nRound " + ROUNDS + " (Final):");
            System.out.println("Start state: " + bytesToHex(state));
        }

        // SubBytes
        subBytes(state);
        if (DEBUG) {
            System.out.println("After SubBytes: " + bytesToHex(state));
        }

        // ShiftRows
        shiftRows(state);
        if (DEBUG) {
            System.out.println("After ShiftRows: " + bytesToHex(state));
        }

        // AddRoundKey
        if (DEBUG) {
            System.out.println("Round key: " + bytesToHex(keySchedule[ROUNDS]));
        }

        addRoundKey(state, keySchedule[ROUNDS]);

        if (DEBUG) {
            System.out.println("After AddRoundKey: " + bytesToHex(state));
        }

        return state;
    }

    /**
     * Decrypts a single 16-byte block using AES
     * @param block The 16-byte input block
     * @param keySchedule The expanded key schedule
     * @return The decrypted 16-byte block
     */
    private static byte[] decryptBlock(byte[] block, byte[][] keySchedule) {
        byte[] state = new byte[BLOCK_SIZE];
        System.arraycopy(block, 0, state, 0, BLOCK_SIZE);

        // Initial round: AddRoundKey
        if (DEBUG) {
            System.out.println("\nRound 0 (Inverse):");
            System.out.println("Start state: " + bytesToHex(state));
            System.out.println("Round key: " + bytesToHex(keySchedule[ROUNDS]));
        }

        addRoundKey(state, keySchedule[ROUNDS]);

        if (DEBUG) {
            System.out.println("After AddRoundKey: " + bytesToHex(state));
        }

        // Main rounds
        for (int round = ROUNDS - 1; round > 0; round--) {
            if (DEBUG) {
                System.out.println("\nRound " + (ROUNDS - round) + " (Inverse):");
                System.out.println("Start state: " + bytesToHex(state));
            }

            // InvShiftRows
            invShiftRows(state);
            if (DEBUG) {
                System.out.println("After InvShiftRows: " + bytesToHex(state));
            }

            // InvSubBytes
            invSubBytes(state);
            if (DEBUG) {
                System.out.println("After InvSubBytes: " + bytesToHex(state));
            }

            // AddRoundKey
            if (DEBUG) {
                System.out.println("Round key: " + bytesToHex(keySchedule[round]));
            }

            addRoundKey(state, keySchedule[round]);

            if (DEBUG) {
                System.out.println("After AddRoundKey: " + bytesToHex(state));
            }

            // InvMixColumns
            invMixColumns(state);
            if (DEBUG) {
                System.out.println("After InvMixColumns: " + bytesToHex(state));
            }
        }

        // Final round (no InvMixColumns)
        if (DEBUG) {
            System.out.println("\nRound " + ROUNDS + " (Inverse, Final):");
            System.out.println("Start state: " + bytesToHex(state));
        }

        // InvShiftRows
        invShiftRows(state);
        if (DEBUG) {
            System.out.println("After InvShiftRows: " + bytesToHex(state));
        }

        // InvSubBytes
        invSubBytes(state);
        if (DEBUG) {
            System.out.println("After InvSubBytes: " + bytesToHex(state));
        }

        // AddRoundKey
        if (DEBUG) {
            System.out.println("Round key: " + bytesToHex(keySchedule[0]));
        }

        addRoundKey(state, keySchedule[0]);

        if (DEBUG) {
            System.out.println("After AddRoundKey: " + bytesToHex(state));
        }

        return state;
    }

    /**
     * Prepares a key string by padding or truncating to 16 bytes
     * @param keyString The input key string
     * @return A 16-byte key array
     */
    private static byte[] prepareKey(String keyString) {
        byte[] key = new byte[16];
        byte[] keyBytes = keyString.getBytes(StandardCharsets.UTF_8);

        // Copy keyBytes to key, padding with zeros if necessary
        int length = Math.min(keyBytes.length, 16);
        System.arraycopy(keyBytes, 0, key, 0, length);

        if (DEBUG) {
            System.out.println("Prepared key: " + bytesToHex(key));
        }

        return key;
    }

    /**
     * Applies PKCS#7 padding to make the input length a multiple of 16 bytes
     * @param input The input byte array
     * @return The padded byte array
     */
    private static byte[] padPKCS7(byte[] input) {
        int padLength = BLOCK_SIZE - (input.length % BLOCK_SIZE);
        if (padLength == 0) {
            padLength = BLOCK_SIZE;  // If the input is already a multiple of 16, add a full block of padding
        }

        byte[] padded = new byte[input.length + padLength];
        System.arraycopy(input, 0, padded, 0, input.length);
        // Fill the padding bytes with the padding length value
        for (int i = input.length; i < padded.length; i++) {
            padded[i] = (byte) padLength;
        }

        if (DEBUG) {
            System.out.println("After PKCS#7 padding: " + bytesToHex(padded));
        }

        return padded;
    }

    /**
     * Removes PKCS#7 padding from a byte array
     * @param input The padded byte array
     * @return The unpadded byte array
     */
    private static byte[] removePKCS7Padding(byte[] input) {
        int padLength = input[input.length - 1] & 0xFF;

        // Validate padding
        if (padLength <= 0 || padLength > BLOCK_SIZE) {
            throw new IllegalArgumentException("Invalid PKCS#7 padding");
        }

        // Check that all padding bytes have the correct value
        for (int i = input.length - padLength; i < input.length; i++) {
            if ((input[i] & 0xFF) != padLength) {
                throw new IllegalArgumentException("Invalid PKCS#7 padding");
            }
        }

        byte[] unpadded = new byte[input.length - padLength];
        System.arraycopy(input, 0, unpadded, 0, unpadded.length);

        if (DEBUG) {
            System.out.println("After removing PKCS#7 padding: " + bytesToHex(unpadded));
        }

        return unpadded;
    }

    /**
     * Performs the key expansion to generate the round keys
     * @param key The 16-byte key
     * @return An array of round keys (11 keys for AES-128)
     */
    private static byte[][] keyExpansion(byte[] key) {
        byte[][] expandedKey = new byte[ROUNDS + 1][16];

        // First round key is the original key
        System.arraycopy(key, 0, expandedKey[0], 0, 16);

        // Generate the remaining round keys
        for (int round = 1; round <= ROUNDS; round++) {
            // Start with the previous round key
            byte[] prevKey = expandedKey[round - 1];
            byte[] newKey = new byte[16];

            // Copy first 12 bytes from previous key
            System.arraycopy(prevKey, 4, newKey, 0, 12);

            // Process the last 4 bytes
            byte[] temp = new byte[4];
            System.arraycopy(prevKey, 12, temp, 0, 4);

            // Rotate word
            byte t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // Apply S-box
            for (int i = 0; i < 4; i++) {
                temp[i] = S_BOX[temp[i] & 0xFF];
            }

            // XOR with Rcon
            temp[0] ^= RCON[round - 1];

            // XOR with previous words
            for (int i = 0; i < 4; i++) {
                newKey[i] = (byte) (prevKey[i] ^ temp[i]);
            }

            for (int i = 4; i < 16; i++) {
                newKey[i] = (byte) (newKey[i - 4] ^ prevKey[i]);
            }

            expandedKey[round] = newKey;
        }

        return expandedKey;
    }

    /**
     * Applies the SubBytes transformation to the state
     * @param state The current state (16 bytes)
     */
    private static void subBytes(byte[] state) {
        for (int i = 0; i < state.length; i++) {
            state[i] = S_BOX[state[i] & 0xFF];
        }
    }

    /**
     * Applies the inverse SubBytes transformation to the state
     * @param state The current state (16 bytes)
     */
    private static void invSubBytes(byte[] state) {
        for (int i = 0; i < state.length; i++) {
            state[i] = INV_S_BOX[state[i] & 0xFF];
        }
    }

    /**
     * Applies the ShiftRows transformation to the state
     * @param state The current state (16 bytes)
     */
    private static void shiftRows(byte[] state) {
        byte[] temp = new byte[16];

        // Row 0: No shift
        temp[0] = state[0];
        temp[4] = state[4];
        temp[8] = state[8];
        temp[12] = state[12];

        // Row 1: Shift left by 1
        temp[1] = state[5];
        temp[5] = state[9];
        temp[9] = state[13];
        temp[13] = state[1];

        // Row 2: Shift left by 2
        temp[2] = state[10];
        temp[6] = state[14];
        temp[10] = state[2];
        temp[14] = state[6];

        // Row 3: Shift left by 3
        temp[3] = state[15];
        temp[7] = state[3];
        temp[11] = state[7];
        temp[15] = state[11];

        System.arraycopy(temp, 0, state, 0, 16);
    }

    /**
     * Applies the inverse ShiftRows transformation to the state
     * @param state The current state (16 bytes)
     */
    private static void invShiftRows(byte[] state) {
        byte[] temp = new byte[16];

        // Row 0: No shift
        temp[0] = state[0];
        temp[4] = state[4];
        temp[8] = state[8];
        temp[12] = state[12];

        // Row 1: Shift right by 1
        temp[1] = state[13];
        temp[5] = state[1];
        temp[9] = state[5];
        temp[13] = state[9];

        // Row 2: Shift right by 2
        temp[2] = state[10];
        temp[6] = state[14];
        temp[10] = state[2];
        temp[14] = state[6];

        // Row 3: Shift right by 3
        temp[3] = state[7];
        temp[7] = state[11];
        temp[11] = state[15];
        temp[15] = state[3];

        System.arraycopy(temp, 0, state, 0, 16);
    }

    /**
     * Applies the MixColumns transformation to the state
     * @param state The current state (16 bytes)
     */
    private static void mixColumns(byte[] state) {
        for (int i = 0; i < 4; i++) {
            byte a = state[i * 4];
            byte b = state[i * 4 + 1];
            byte c = state[i * 4 + 2];
            byte d = state[i * 4 + 3];

            state[i * 4] = (byte) (gmul(a, 2) ^ gmul(b, 3) ^ c ^ d);
            state[i * 4 + 1] = (byte) (a ^ gmul(b, 2) ^ gmul(c, 3) ^ d);
            state[i * 4 + 2] = (byte) (a ^ b ^ gmul(c, 2) ^ gmul(d, 3));
            state[i * 4 + 3] = (byte) (gmul(a, 3) ^ b ^ c ^ gmul(d, 2));
        }
    }

    /**
     * Applies the inverse MixColumns transformation to the state
     * @param state The current state (16 bytes)
     */
    private static void invMixColumns(byte[] state) {
        for (int i = 0; i < 4; i++) {
            byte a = state[i * 4];
            byte b = state[i * 4 + 1];
            byte c = state[i * 4 + 2];
            byte d = state[i * 4 + 3];

            state[i * 4] = (byte) (gmul(a, 14) ^ gmul(b, 11) ^ gmul(c, 13) ^ gmul(d, 9));
            state[i * 4 + 1] = (byte) (gmul(a, 9) ^ gmul(b, 14) ^ gmul(c, 11) ^ gmul(d, 13));
            state[i * 4 + 2] = (byte) (gmul(a, 13) ^ gmul(b, 9) ^ gmul(c, 14) ^ gmul(d, 11));
            state[i * 4 + 3] = (byte) (gmul(a, 11) ^ gmul(b, 13) ^ gmul(c, 9) ^ gmul(d, 14));
        }
    }

    /**
     * Adds (XORs) the round key to the state
     * @param state The current state (16 bytes)
     * @param roundKey The round key to add (16 bytes)
     */
    private static void addRoundKey(byte[] state, byte[] roundKey) {
        for (int i = 0; i < 16; i++) {
            state[i] ^= roundKey[i];
        }
    }

    /**
     * Galois Field (2^8) multiplication for MixColumns
     * @param a First byte
     * @param b Second byte
     * @return The product in GF(2^8)
     */
    private static byte gmul(byte a, int b) {
        int p = 0;
        int high_bit;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) != 0) {
                p ^= a & 0xFF;
            }
            high_bit = (a & 0x80);
            a <<= 1;
            if (high_bit != 0) {
                a ^= 0x1B; // x^8 + x^4 + x^3 + x + 1
            }
            b >>= 1;
        }
        return (byte) (p & 0xFF);
    }

    /**
     * XORs two blocks of equal length
     * @param block1 First block (will be modified)
     * @param block2 Second block
     */
    private static void xorBlocks(byte[] block1, byte[] block2) {
        for (int i = 0; i < block1.length; i++) {
            block1[i] ^= block2[i];
        }
    }

    /**
     * Converts a byte array to a hexadecimal string
     * @param bytes The byte array
     * @return The hexadecimal string
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02X", b & 0xFF));
        }
        return hex.toString();
    }

    /**
     * Main method for testing
     */
    public static void main(String[] args) {
        // Enable debug output
        setDebug(true);

        // Test ECB mode
        System.out.println("TESTING AES-ECB MODE");
        String plaintext = "This is a test message for AES encryption.";
        String key = "MySuperSecretKey";

        String encrypted = encrypt(plaintext, key, false); // ECB mode
        String decrypted = decrypt(encrypted, key, false); // ECB mode

        System.out.println("\nECB Results:");
        System.out.println("Original: " + plaintext);
        System.out.println("Encrypted (Base64): " + encrypted);
        System.out.println("Decrypted: " + decrypted);

        // Test CBC mode
        System.out.println("\n\nTESTING AES-CBC MODE");

        encrypted = encrypt(plaintext, key, true); // CBC mode
        decrypted = decrypt(encrypted, key, true); // CBC mode

        System.out.println("\nCBC Results:");
        System.out.println("Original: " + plaintext);
        System.out.println("Encrypted (Base64): " + encrypted);
        System.out.println("Decrypted: " + decrypted);
    }
}


