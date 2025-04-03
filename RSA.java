import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

/**
 * Implementation of the RSA cryptosystem
 */
public class RSA {
    private static final int DEFAULT_KEY_SIZE = 1024;
    private static final SecureRandom RANDOM = new SecureRandom();

    private BigInteger n; // modulus
    private BigInteger e; // public exponent
    private BigInteger d; // private exponent
    private int keySize;

    /**
     * Generates an RSA key pair with the default key size (1024 bits)
     */
    public RSA() {
        this(DEFAULT_KEY_SIZE);
    }

    /**
     * Generates an RSA key pair with the specified key size
     * @param keySize the key size in bits
     */
    public RSA(int keySize) {
        this.keySize = keySize;
        generateKeyPair();
    }

    /**
     * Generates a new RSA key pair
     */
    public void generateKeyPair() {
        // Generate two large prime numbers
        BigInteger p = generateLargePrime(keySize / 2);
        BigInteger q = generateLargePrime(keySize / 2);

        // Calculate n = p * q
        n = p.multiply(q);

        // Calculate φ(n) = (p-1) * (q-1)
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
        e = BigInteger.valueOf(65537); // Common value for e

        // Ensure e and phi are coprime
        while (phi.gcd(e).compareTo(BigInteger.ONE) != 0) {
            e = e.add(BigInteger.TWO);
        }

        // Calculate d such that (d * e) % φ(n) = 1
        d = e.modInverse(phi);
    }

    /**
     * Generates a large prime number of the specified bit length
     * @param bitLength the bit length of the prime
     * @return a large prime number
     */
    private BigInteger generateLargePrime(int bitLength) {
        return BigInteger.probablePrime(bitLength, RANDOM);
    }

    /**
     * Encrypts the given message using the public key (n, e)
     * @param message the message to encrypt
     * @return the encrypted message
     */
    public BigInteger encrypt(BigInteger message) {
        if (message.compareTo(n) >= 0) {
            throw new IllegalArgumentException("Message must be less than n");
        }

        // c = m^e mod n
        return message.modPow(e, n);
    }

    /**
     * Decrypts the given ciphertext using the private key (n, d)
     * @param ciphertext the ciphertext to decrypt
     * @return the decrypted message
     */
    public BigInteger decrypt(BigInteger ciphertext) {
        if (ciphertext.compareTo(n) >= 0) {
            throw new IllegalArgumentException("Ciphertext must be less than n");
        }

        // m = c^d mod n
        return ciphertext.modPow(d, n);
    }

    /**
     * Creates a digital signature for the given message using the private key
     * @param message the message to sign
     * @return the digital signature
     */
    public BigInteger sign(BigInteger message) {
        if (message.compareTo(n) >= 0) {
            throw new IllegalArgumentException("Message must be less than n");
        }

        // signature = message^d mod n (same as decryption)
        return message.modPow(d, n);
    }

    /**
     * Verifies a digital signature using the public key
     * @param message the original message
     * @param signature the digital signature to verify
     * @return true if the signature is valid, false otherwise
     */
    public boolean verify(BigInteger message, BigInteger signature) {
        if (signature.compareTo(n) >= 0) {
            throw new IllegalArgumentException("Signature must be less than n");
        }

        // Verify by checking if message == signature^e mod n
        BigInteger computedMessage = signature.modPow(e, n);

        return message.equals(computedMessage);
    }

    /**
     * Gets the modulus (n)
     * @return the modulus
     */
    public BigInteger getModulus() {
        return n;
    }

    /**
     * Gets the public exponent (e)
     * @return the public exponent
     */
    public BigInteger getPublicExponent() {
        return e;
    }

    /**
     * Gets the private exponent (d)
     * @return the private exponent
     */
    public BigInteger getPrivateExponent() {
        return d;
    }

    /**
     * Main method for testing
     */
    public static void main(String[] args) {
        // Create a new RSA instance with a 1024-bit key
        RSA rsa = new RSA(1024);

        // Test message
        BigInteger message = new BigInteger("123456789");
        System.out.println("Original message: " + message);

        // Test encryption and decryption
        BigInteger ciphertext = rsa.encrypt(message);
        System.out.println("Encrypted: " + ciphertext);

        BigInteger decrypted = rsa.decrypt(ciphertext);
        System.out.println("Decrypted: " + decrypted);

        // Test signature and verification
        BigInteger signature = rsa.sign(message);
        System.out.println("\nSignature: " + signature);

        boolean isValid = rsa.verify(message, signature);
        System.out.println("Signature valid: " + isValid);

        // Testing with a different message to show invalid signature
        BigInteger differentMessage = new BigInteger("987654321");
        boolean invalidTest = rsa.verify(differentMessage, signature);
        System.out.println("Different message with same signature valid (should be false): " + invalidTest);
    }
}
