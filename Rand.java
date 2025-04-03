import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public class Rand {
    private static SecureRandom rand;

    static {new Rand();}

    public Rand() {
        try {
            rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
        } catch (NoSuchAlgorithmException nsaEx) {
            nsaEx.printStackTrace();
            byte[] seed = SecureRandom.getSeed(128);
            rand = new SecureRandom(seed);
        } catch (NoSuchProviderException nspEx) {
            nspEx.printStackTrace();
            byte[] seed = SecureRandom.getSeed(128);
            rand = new SecureRandom(seed);
        }
    }

    public Rand(byte[] seed) {
        rand = new SecureRandom(seed);
    }

    public static SecureRandom getRand() {
        return rand;
    }

    public static int randInt(int max) {
        return rand.nextInt(max);
    }

    public static long randLong() {
        return rand.nextLong(0L, Long.MAX_VALUE);
    }

    public static boolean[] randBits(int len) {
        boolean[] bits = new boolean[len];
        byte[] randomBytes = new byte[(len + 7) / 8];
        rand.nextBytes(randomBytes);

        for (int i = 0; i < len; i++) {
            int byteIndex = i / 8;
            int bitIndex = i % 8;
            bits[i] = ((randomBytes[byteIndex] >> (7 - bitIndex)) & 1) == 1;
        }
        return bits;
    }

    public static int randInt(int min, int max) {
        return rand.nextInt(min, max+1);
    }

    public static double randGauss(double mean, double stddev) {
        return rand.nextGaussian(mean, stddev);
    }

    public static void main(String[] args) {
        Rand rand = new Rand();
        for (int i = 0; i < 20; i++) {
            System.out.println(rand.randInt(5));
        }
        System.out.println();
        for (int i = 0; i < 20; i++) {
            System.out.println(rand.randInt(1, 6));
        }
        System.out.println();
        for (int i = 0; i < 20; i++) {
            System.out.println(rand.randGauss(100, 10));
        }
    }
}