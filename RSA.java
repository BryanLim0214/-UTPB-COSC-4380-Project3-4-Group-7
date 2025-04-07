import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.io.File; // For primes.txt
import java.io.FileNotFoundException; // For primes.txt
import java.util.Scanner; // For primes.txt

/**
 * <h1>RSA</h1>
 * <p>This class implements a basic form of the RSA asymmetric encryption and digital signing system.</p>
 * <p>Includes self-contained helper methods for prime generation, primality testing, etc.</p>
 */
public class RSA {

    // --- SecureRandom Instance ---
    // Initialize a secure random number generator
    private static SecureRandom random;
    static {
        try {
            // Prefer NIST default if available, fallback to SHA1PRNG
            random = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            try {
                System.err.println("Warning: Strong SecureRandom unavailable, falling back to SHA1PRNG.");
                random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
                // Fallback to default if specific providers fail
                System.err.println("Warning: SHA1PRNG from SUN unavailable, using default SecureRandom. Seeding recommended.");
                // Use system default, potentially less secure or slower
                random = new SecureRandom();
            }
        }
        // Optional: Seed the generator if needed, especially for less trusted defaults
        // byte[] seed = SecureRandom.getSeed(128); // Get system-provided seed
        // random.setSeed(seed); // Re-seed
        System.out.println("SecureRandom initialized: " + random.getAlgorithm());
    }


    // --- Member Variables ---
    // Correctly private for security
    private BigInteger p;
    private BigInteger q;
    private BigInteger n;
    private BigInteger phi;
    private BigInteger e;
    private BigInteger d;

    // Certainty level for Miller-Rabin primality test
    // Higher value means lower probability of a composite passing, but slower generation.
    // 80-100 is generally considered very strong for cryptographic purposes.
    private static final int PRIMALITY_CERTAINTY = 100;

    /**
     * <h3>RSA Constructor</h3>
     * <p>Generates an RSA key pair with the specified bit length for the modulus n.</p>
     * @param bits The desired bit length for the modulus n (e.g., 2048, 4096). Must be >= 512.
     */
    public RSA(int bits) {
        if (bits < 512) {
            throw new IllegalArgumentException("RSA key size must be at least 512 bits for minimal security.");
        }
        System.out.printf("RSA Constructor: Generating %d-bit RSA key pair...%n", bits);
        long startTime = System.currentTimeMillis();

        int primeBits = bits / 2; // Each prime p, q will have roughly half the bits of n

        // 1. Generate first prime p
        System.out.printf("RSA Constructor: Generating first prime p (%d bits)...%n", primeBits);
        this.p = generateProbablePrime(primeBits, PRIMALITY_CERTAINTY);

        // 2. Generate second prime q (distinct from p)
        System.out.printf("RSA Constructor: Generating second prime q (%d bits)...%n", primeBits);
        do {
            this.q = generateProbablePrime(primeBits, PRIMALITY_CERTAINTY);
        } while (this.p.equals(this.q));
        System.out.println("RSA Constructor: Primes p and q generated.");
        // System.out.printf(" p = %s... (%d bits)%n", p.toString().substring(0,10), p.bitLength());
        // System.out.printf(" q = %s... (%d bits)%n", q.toString().substring(0,10), q.bitLength());


        // 3. Calculate n = p * q
        this.n = this.p.multiply(this.q);
        // System.out.printf(" n = %s... (%d bits)%n", n.toString().substring(0,10), n.bitLength());

        // 4. Calculate phi(n) = (p-1) * (q-1)
        this.phi = this.p.subtract(BigInteger.ONE).multiply(
                this.q.subtract(BigInteger.ONE));

        // 5. Choose public exponent e (standard choice 65537)
        this.e = new BigInteger("65537");
        // Verify e is coprime with phi (highly likely, but check)
        if (!this.e.gcd(this.phi).equals(BigInteger.ONE)) {
            // This should realistically never happen for large random primes p, q
            throw new ArithmeticException("Chosen e=65537 is not coprime with phi. This is highly unusual.");
            // If needed, could implement logic to find another e, but standard e=65537 is preferred.
        }

        // 6. Calculate private exponent d using reliable BigInteger.modInverse
        // System.out.println("Calculating d...");
        this.d = this.e.modInverse(this.phi);

        long endTime = System.currentTimeMillis();
        System.out.printf("RSA Constructor: Key generation complete (%d ms).%n", (endTime - startTime));
    }

    /**
     * <h3>getPubKey</h3>
     * <p>Returns the public key components (e, n).</p>
     * @return An array of BigInteger containing [e, n].
     */
    public BigInteger[] getPubKey() {
        return new BigInteger[] {this.e, this.n};
    }

    // --- Core RSA Operations ---

    /**
     * <h3>encrypt</h3>
     * <p>Encrypts a message string using the provided public key.</p>
     * <p>C = M^e mod n</p>
     * <p><b>Note:</b> Does not use padding (like OAEP), which is required for semantic security.</p>
     * @param message The plaintext message String.
     * @param pubKey The recipient's public key [e, n].
     * @return The ciphertext as a base-10 String representation of the resulting BigInteger.
     */
    public String encrypt(String message, BigInteger[] pubKey) {
        if (message == null) return null;
        BigInteger m = new BigInteger(message.getBytes(StandardCharsets.UTF_8));
        BigInteger keyE = pubKey[0];
        BigInteger keyN = pubKey[1];
        BigInteger c = m.modPow(keyE, keyN);
        return c.toString();
    }

    /**
     * <h3>decrypt</h3>
     * <p>Decrypts a ciphertext string using the instance's private key.</p>
     * <p>M = C^d mod n</p>
     * <p><b>Note:</b> Assumes no padding was used during encryption.</p>
     * @param ciphertext The ciphertext String (base-10 representation of a BigInteger).
     * @return The decrypted plaintext message String, or null if ciphertext format is invalid.
     */
    public String decrypt(String ciphertext) {
        if (ciphertext == null) return null;
        try {
            BigInteger c = new BigInteger(ciphertext);
            BigInteger m = c.modPow(this.d, this.n);
            return new String(m.toByteArray(), StandardCharsets.UTF_8);
        } catch (NumberFormatException e) {
            System.err.println("Error: Could not decrypt - ciphertext is not a valid BigInteger representation.");
            return null;
        }
    }

    /**
     * <h3>sign</h3>
     * <p>Creates a digital signature for a message string using the instance's private key.</p>
     * <p>S = M^d mod n</p>
     * <p><b>SECURITY WARNING:</b> This basic implementation signs the raw message bytes.
     * Secure signing requires hashing the message first (e.g., SHA-256) and using a padding scheme (e.g., PSS),
     * then signing the padded hash.</p>
     * @param message The message String to sign.
     * @return The signature as a base-10 String representation of the resulting BigInteger.
     */
    public String sign(String message) {
        if (message == null) return null;
        BigInteger m = new BigInteger(message.getBytes(StandardCharsets.UTF_8));
        BigInteger s = m.modPow(this.d, this.n);
        return s.toString();
    }

    /**
     * <h3>authenticate</h3>
     * <p>Verifies a digital signature using the sender's public key.</p>
     * <p>M = S^e mod n</p>
     * <p><b>SECURITY WARNING:</b> This complements the basic sign method (verifies against raw message bytes).
     * Secure verification involves hashing the received message, verifying the signature against the hash
     * using the appropriate padding scheme, and comparing the result to the calculated hash.</p>
     * @param signature The signature String (base-10 representation of a BigInteger).
     * @param pubKey The sender's public key [e, n].
     * @return The original message bytes recovered from the signature String, or null if signature format is invalid.
     */
    public String authenticate(String signature, BigInteger[] pubKey) {
        if (signature == null) return null;
        try {
            BigInteger s = new BigInteger(signature);
            BigInteger keyE = pubKey[0];
            BigInteger keyN = pubKey[1];
            BigInteger m = s.modPow(keyE, keyN);
            return new String(m.toByteArray(), StandardCharsets.UTF_8);
        } catch (NumberFormatException e) {
            System.err.println("Error: Could not authenticate - signature is not a valid BigInteger representation.");
            return null;
        }
    }


    // --- Internal Helper Methods ---

    /**
     * Generates a random BigInteger with exactly the specified number of bits.
     * Ensures the number is >= 2^(bits-1).
     * @param bits The exact desired bit length (must be >= 2).
     * @return A random BigInteger with the specified bit length.
     */
    private static BigInteger getRandomOfExactBits(int bits) {
        if (bits < 2) throw new IllegalArgumentException("Bit length must be >= 2.");
        BigInteger minRequiredValue = BigInteger.ONE.shiftLeft(bits - 1); // 2^(bits-1)
        BigInteger result;
        do {
            result = new BigInteger(bits, random);
        } while (result.compareTo(minRequiredValue) < 0); // Loop until result >= 2^(bits-1)
        return result;
    }

    /**
     * Checks if a BigInteger is probably prime using Miller-Rabin test.
     * Optionally includes trial division optimization.
     * @param n The number to test.
     * @param certainty The number of Miller-Rabin iterations (higher means more certain).
     * @return true if n is probably prime, false otherwise.
     */
    private static boolean isProbablePrime(BigInteger n, int certainty) {
        // Basic checks
        if (n.compareTo(BigInteger.ONE) <= 0) return false;
        if (n.compareTo(BigInteger.TWO) == 0 || n.compareTo(BigInteger.valueOf(3)) == 0) return true;
        if (n.mod(BigInteger.TWO).equals(BigInteger.ZERO)) return false; // Even numbers > 2

        // Optional: Trial Division using primes.txt (optimization)
        // Set this path correctly or remove this section if primes.txt is not available/desired.
        final String PRIMES_FILE_PATH = "primes.txt";
        try {
            File primesFile = new File(PRIMES_FILE_PATH);
            if (primesFile.exists()) {
                Scanner scan = new Scanner(primesFile);
                BigInteger sqrtN = n.sqrt(); // Approx sqrt for optimization
                while(scan.hasNext()) {
                    BigInteger smallPrime = new BigInteger(scan.nextLine());
                    if (smallPrime.compareTo(sqrtN) > 0) break; // No need to check larger primes
                    if (n.mod(smallPrime).equals(BigInteger.ZERO)) {
                        scan.close();
                        return false; // Found a small factor
                    }
                }
                scan.close();
            } else {
                // System.err.println("Note: primes.txt not found at " + PRIMES_FILE_PATH + ", skipping trial division.");
            }
        } catch (FileNotFoundException | NumberFormatException e) {
            System.err.println("Warning: Error reading primes.txt - " + e.getMessage() + ". Skipping trial division.");
        }

        // Miller-Rabin Test (using reliable BigInteger.modPow)
        // Find d, s such that n-1 = d * 2^s, where d is odd
        BigInteger nMinus1 = n.subtract(BigInteger.ONE);
        BigInteger d = nMinus1;
        int s = 0;
        while (d.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
            s++;
            d = d.shiftRight(1);
        }

        // Perform test 'certainty' times
        for (int i = 0; i < certainty; i++) {
            // Choose a random base 'a' in [2, n-2]
            BigInteger a = getRandomInRange(BigInteger.TWO, n.subtract(BigInteger.TWO));
            BigInteger x = a.modPow(d, n); // x = a^d mod n

            if (x.equals(BigInteger.ONE) || x.equals(nMinus1)) continue; // Probably prime, try next 'a'

            boolean maybePrime = false;
            for (int r = 1; r < s; r++) { // Loop s-1 times
                x = x.modPow(BigInteger.TWO, n); // x = x^2 mod n
                if (x.equals(BigInteger.ONE)) return false; // Definitely composite
                if (x.equals(nMinus1)) {
                    maybePrime = true; // Probably prime, break inner loop, try next 'a'
                    break;
                }
            }
            if (!maybePrime) return false; // Definitely composite
        }
        return true; // Probably prime
    }

    /**
     * Generates a probable prime number with a specific bit length.
     * @param bits The exact desired bit length.
     * @param certainty The certainty level for primality testing.
     * @return A BigInteger that is probably prime.
     */
    private static BigInteger generateProbablePrime(int bits, int certainty) {
        if (bits < 2) throw new IllegalArgumentException("Cannot generate prime with fewer than 2 bits.");
        BigInteger p;
        int attempts = 0;
        long startTime = System.currentTimeMillis();
        do {
            attempts++;
            // Ensure candidate has exact bit length and is odd
            do {
                p = getRandomOfExactBits(bits);
            } while (p.mod(BigInteger.TWO).equals(BigInteger.ZERO)); // Ensure it's odd

            // Debugging output - Limit frequency
            if (attempts % 50 == 0 || attempts <= 5) {
                long currentTime = System.currentTimeMillis();
                System.out.printf(" generateProbablePrime(%d bits): Checked %d candidates (%d ms)...%n",
                        bits, attempts, (currentTime - startTime));
            }
            if (attempts > 5000) { // Safety break
                throw new RuntimeException("Prime generation took too many attempts (> 5000).");
            }

        } while (!isProbablePrime(p, certainty)); // Loop until a probable prime is found
        // System.out.printf(" generateProbablePrime(%d bits): Found after %d attempts.%n", bits, attempts);
        return p;
    }

    /** Helper to get random BigInteger in [min, max] range. */
    private static BigInteger getRandomInRange(BigInteger min, BigInteger max) {
        if (min.compareTo(max) >= 0) {
            if (min.equals(max)) return min;
            throw new IllegalArgumentException("min must be less than max for getRandomInRange");
        }
        BigInteger range = max.subtract(min);
        int len = range.bitLength();
        BigInteger result;
        do {
            result = new BigInteger(len, random);
        } while (result.compareTo(range) > 0);
        return result.add(min);
    }


    // --- REVISED Main Method for Testing (using public methods only) ---
    public static void main(String[] args) {
        try {
            int testBits = 512; // Faster for testing, use 2048+ for security
            System.out.println("\n===== RSA Test Run (Self-Contained) =====");
            System.out.println("Generating keys for Alice...");
            RSA alice = new RSA(testBits);
            BigInteger[] alicePubKey = alice.getPubKey();
            System.out.println("Alice Public Key generated.");

            System.out.println("\nGenerating keys for Bob...");
            RSA bob = new RSA(testBits);
            BigInteger[] bobPubKey = bob.getPubKey();
            System.out.println("Bob Public Key generated.");

            // --- Test Scenario 1: Alice Encrypts for Bob ---
            System.out.println("\n--- Test: Alice Encrypts for Bob ---");
            String secretMessage = "Self-contained RSA test message.";
            System.out.printf("Original Message: '%s'%n", secretMessage);

            String encryptedForBob = alice.encrypt(secretMessage, bobPubKey);
            System.out.printf("Encrypted Ciphertext: %s...%n", encryptedForBob.substring(0, Math.min(60, encryptedForBob.length())));

            String decryptedByBob = bob.decrypt(encryptedForBob);
            System.out.printf("Decrypted Message: '%s'%n", decryptedByBob);
            System.out.printf("Encryption/Decryption Successful: %b%n", secretMessage.equals(decryptedByBob));

            // --- Test Scenario 2: Alice Signs, Bob Verifies ---
            System.out.println("\n--- Test: Alice Signs, Bob Authenticates ---");
            String statement = "Alice confirms this test works.";
            System.out.printf("Original Statement: '%s'%n", statement);

            String signatureByAlice = alice.sign(statement);
            System.out.printf("Alice's Signature: %s...%n", signatureByAlice.substring(0, Math.min(60, signatureByAlice.length())));

            String authenticatedStatement = bob.authenticate(signatureByAlice, alicePubKey);
            System.out.printf("Authenticated Statement: '%s'%n", authenticatedStatement);
            System.out.printf("Signature Verification Successful: %b%n", statement.equals(authenticatedStatement));

            // --- Test Scenario 3: Tampering ---
            System.out.println("\n--- Test: Tampered Signature ---");
            String tamperedSignature = signatureByAlice.replaceFirst("1", "9"); // Modify signature
            String resultFromTampered = bob.authenticate(tamperedSignature, alicePubKey);
            System.out.printf("Authentication Result (Tampered): '%s'%n", resultFromTampered);
            if (statement.equals(resultFromTampered)) {
                System.out.println("Tampering Test: FAILED (Tampered signature produced original message!)");
            } else if (resultFromTampered != null){
                System.out.println("Tampering Test: PASSED (Authentication produced different result)");
            } else {
                // This case might happen if authenticate returns null on NumberFormatException
                System.out.println("Tampering Test: PASSED (Authentication returned null or failed)");
            }

            System.out.println("\n===== RSA Test Run Complete =====");

        } catch (Exception e) {
            System.err.println("\nAn error occurred during the RSA test run:");
            e.printStackTrace();
        }
    }
}
