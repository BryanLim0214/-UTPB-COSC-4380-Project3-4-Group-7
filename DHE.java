import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Implementation of the Diffie-Hellman Key Exchange protocol
 */
public class DHE {
    private static final SecureRandom RANDOM = new SecureRandom();

    private BigInteger g; // generator
    private BigInteger p; // prime modulus
    private int gBits; // bit length of generator
    private int pBits; // bit length of prime

    /**
     * Creates a new DHE instance with specified bit lengths
     * @param gBits bit length for the generator base
     * @param pBits bit length for the prime modulus
     */
    public DHE(int gBits, int pBits) {
        this.gBits = gBits;
        this.pBits = pBits;
        generateParameters();
    }

    /**
     * Generates parameters for Diffie-Hellman
     */
    private void generateParameters() {
        // Generate a prime p
        p = BigInteger.probablePrime(pBits, RANDOM);

        // Use a common generator (5 is often used for demonstration)
        g = BigInteger.valueOf(5);
    }

    /**
     * Generates a random private base value for Diffie-Hellman
     * @param bits the bit length of the private base
     * @return a random private base
     */
    public BigInteger generatePrivateBase(int bits) {
        BigInteger base = new BigInteger(bits, RANDOM);
        return base;
    }

    /**
     * Computes the public value for Diffie-Hellman
     * @param privateBase the private base value
     * @return the public value (g^privateBase mod p)
     */
    public BigInteger computePublicValue(BigInteger privateBase) {
        // Calculate g^privateBase mod p
        BigInteger publicValue = g.modPow(privateBase, p);
        return publicValue;
    }

    /**
     * Computes the shared secret key
     * @param privateBase the private base value
     * @param otherPublicValue the other party's public value
     * @return the shared secret key
     */
    public BigInteger computeSharedSecret(BigInteger privateBase, BigInteger otherPublicValue) {
        // Calculate (otherPublicValue)^privateBase mod p
        BigInteger sharedSecret = otherPublicValue.modPow(privateBase, p);
        return sharedSecret;
    }

    /**
     * Gets the generator value
     * @return the generator g
     */
    public BigInteger getGenerator() {
        return g;
    }

    /**
     * Gets the prime modulus
     * @return the prime modulus p
     */
    public BigInteger getPrime() {
        return p;
    }

    /**
     * Main method for testing
     */
    public static void main(String[] args) {
        // Two-party Diffie-Hellman key exchange
        System.out.println("=== TWO-PARTY DIFFIE-HELLMAN KEY EXCHANGE ===");
        DHE dhe = new DHE(512, 2048);

        System.out.println("Generator (g) = " + dhe.getGenerator());
        System.out.println("Prime (p) = " + dhe.getPrime());

        // Alice's calculations
        System.out.println("\n--- ALICE'S CALCULATIONS ---");
        BigInteger a = dhe.generatePrivateBase(512);
        BigInteger A = dhe.computePublicValue(a);
        System.out.println("Alice's private base (a) = " + a);
        System.out.println("Alice's public value (A) = " + A);

        // Bob's calculations
        System.out.println("\n--- BOB'S CALCULATIONS ---");
        BigInteger b = dhe.generatePrivateBase(512);
        BigInteger B = dhe.computePublicValue(b);
        System.out.println("Bob's private base (b) = " + b);
        System.out.println("Bob's public value (B) = " + B);

        // Shared secret calculation
        System.out.println("\n--- SHARED SECRET COMPUTATION ---");
        BigInteger aliceSecret = dhe.computeSharedSecret(a, B);
        BigInteger bobSecret = dhe.computeSharedSecret(b, A);

        System.out.println("Alice's computed shared secret = " + aliceSecret);
        System.out.println("Bob's computed shared secret   = " + bobSecret);
        System.out.println("\nShared secrets match: " + aliceSecret.equals(bobSecret));

        // Three-party Diffie-Hellman key exchange
        System.out.println("\n=== THREE-PARTY DIFFIE-HELLMAN KEY EXCHANGE ===");
        DHE dhe3 = new DHE(512, 2048);

        System.out.println("Generator (g) = " + dhe3.getGenerator());
        System.out.println("Prime (p) = " + dhe3.getPrime());

        // Party X's calculations
        System.out.println("\n--- PARTY X'S CALCULATIONS ---");
        BigInteger x = dhe3.generatePrivateBase(512);
        BigInteger X = dhe3.computePublicValue(x);
        System.out.println("X's private base (x) = " + x);
        System.out.println("X's public value (X) = " + X);

        // Party Y's calculations
        System.out.println("\n--- PARTY Y'S CALCULATIONS ---");
        BigInteger y = dhe3.generatePrivateBase(512);
        BigInteger Y = dhe3.computePublicValue(y);
        System.out.println("Y's private base (y) = " + y);
        System.out.println("Y's public value (Y) = " + Y);

        // Party Z's calculations
        System.out.println("\n--- PARTY Z'S CALCULATIONS ---");
        BigInteger z = dhe3.generatePrivateBase(512);
        BigInteger Z = dhe3.computePublicValue(z);
        System.out.println("Z's private base (z) = " + z);
        System.out.println("Z's public value (Z) = " + Z);

        // Intermediate values for three-party exchange
        System.out.println("\n--- INTERMEDIATE VALUE COMPUTATIONS ---");

        System.out.println("X computing intermediate value with Y's public value:");
        BigInteger XY = dhe3.computeSharedSecret(x, Y);

        System.out.println("Y computing intermediate value with Z's public value:");
        BigInteger YZ = dhe3.computeSharedSecret(y, Z);

        System.out.println("Z computing intermediate value with X's public value:");
        BigInteger ZX = dhe3.computeSharedSecret(z, X);

        // Final shared secret for three-party exchange
        System.out.println("\n--- FINAL SHARED SECRET COMPUTATION ---");

        System.out.println("X computing final shared secret:");
        // X computes (Y^z)^x = g^(y*z*x)
        BigInteger secretX = dhe3.computeSharedSecret(x, YZ);

        System.out.println("Y computing final shared secret:");
        // Y computes (Z^x)^y = g^(z*x*y)
        BigInteger secretY = dhe3.computeSharedSecret(y, ZX);

        System.out.println("Z computing final shared secret:");
        // Z computes (X^y)^z = g^(x*y*z)
        BigInteger secretZ = dhe3.computeSharedSecret(z, XY);

        System.out.println("X's computed shared secret = " + secretX);
        System.out.println("Y's computed shared secret = " + secretY);
        System.out.println("Z's computed shared secret = " + secretZ);

        System.out.println("\nMulti-party shared secrets match: " +
                (secretX.equals(secretY) && secretY.equals(secretZ)));

        // Alternative (direct) three-party key exchange
        System.out.println("\n=== ALTERNATIVE THREE-PARTY KEY EXCHANGE METHOD ===");
        System.out.println("Computing three-party shared secret directly:");

        // Calculate g^xyz directly using a different order of operations
        // Party X
        BigInteger temp1 = dhe3.computePublicValue(y); // g^y
        BigInteger temp2 = dhe3.computeSharedSecret(z, temp1); // (g^y)^z = g^yz
        BigInteger YZ_X = dhe3.computeSharedSecret(x, temp2); // (g^yz)^x = g^xyz

        // Party Y
        temp1 = dhe3.computePublicValue(z); // g^z
        temp2 = dhe3.computeSharedSecret(x, temp1); // (g^z)^x = g^zx
        BigInteger ZX_Y = dhe3.computeSharedSecret(y, temp2); // (g^zx)^y = g^zxy

        // Party Z
        temp1 = dhe3.computePublicValue(x); // g^x
        temp2 = dhe3.computeSharedSecret(y, temp1); // (g^x)^y = g^xy
        BigInteger XY_Z = dhe3.computeSharedSecret(z, temp2); // (g^xy)^z = g^xyz

        System.out.println("X's direct computation: " + YZ_X);
        System.out.println("Y's direct computation: " + ZX_Y);
        System.out.println("Z's direct computation: " + XY_Z);

        System.out.println("\nAlternative shared secrets match: " +
                (YZ_X.equals(ZX_Y) && ZX_Y.equals(XY_Z)));

        System.out.println("\nBoth methods produce same result: " +
                secretX.equals(YZ_X));
    }
}
