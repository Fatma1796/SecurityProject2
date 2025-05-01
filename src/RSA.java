

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;

public class RSA {

    private BigInteger n; // Modulus
    private BigInteger e; // Public exponent
    private BigInteger d; // Private exponent
    private int bitLength = 256; // Length of modulus

    /**
     * Constructor to generate public and private keys
     */
    public RSA() {
        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(bitLength / 2, random); // First prime number
        BigInteger q = BigInteger.probablePrime(bitLength / 2, random); // Second prime number
        n = p.multiply(q); // n = p * q
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE)); // φ(n) = (p-1)*(q-1)
        e = BigInteger.probablePrime(bitLength / 2, random); // Public exponent e

        // Ensure gcd(e, φ(n)) = 1
        while (!phi.gcd(e).equals(BigInteger.ONE)) {
            e = e.add(BigInteger.ONE);
        }

        d = e.modInverse(phi); // Private exponent d
    }

    /**
     * Encrypts a message using the public key
     */
    public BigInteger encrypt(BigInteger message) {
        return message.modPow(e, n); // ciphertext = (message^e) % n
    }

    /**
     * Decrypts a message using the private key
     */
    public BigInteger decrypt(BigInteger ciphertext) {
        return ciphertext.modPow(d, n); // plaintext = (ciphertext^d) % n
    }

    /**
     * Converts a string to a BigInteger
     */
    public BigInteger fromStringToBigInteger(String input) {
        return new BigInteger(input.getBytes());
    }

    /**
     * Converts a BigInteger to a string
     */
    public String fromBigIntegerToString(BigInteger input) {
        return new String(input.toByteArray());
    }

    public static void main(String[] args) {
        try {
            RSA rsa = new RSA();

            // Display public and private keys
            System.out.println("The generated public key in plaintext: " + rsa.fromBigIntegerToString(rsa.e));
            System.out.println("The generated public key in big integer: " + rsa.e);
            System.out.println("The generated private key in plaintext: " + rsa.fromBigIntegerToString(rsa.d));
            System.out.println("The generated private key in big integer: " + rsa.d);

            // Step 1: Read plaintext from the file "security.txt"
            String plaintextFilePath = "security.txt";
            String plaintext = new String(Files.readAllBytes(Paths.get(plaintextFilePath))).trim();
            System.out.println("Original Message from file: " + plaintext);

            // Convert plaintext to BigInteger
            BigInteger plaintextBigInt = rsa.fromStringToBigInteger(plaintext);

            // Encrypt the message
            BigInteger encryptedBigInt = rsa.encrypt(plaintextBigInt);
            String encryptedPlaintext = rsa.fromBigIntegerToString(encryptedBigInt);

            // Decrypt the message
            BigInteger decryptedBigInt = rsa.decrypt(encryptedBigInt);
            String decryptedPlaintext = rsa.fromBigIntegerToString(decryptedBigInt);

            // Display results
            System.out.println("Message in plaintext: " + plaintext);
            System.out.println("Message in big integer: " + plaintextBigInt);

            System.out.println("Encrypted Cipher in plaintext: " + encryptedPlaintext);
            System.out.println("Encrypted Cipher in big integer: " + encryptedBigInt);

            System.out.println("Decrypted Message in plaintext: " + decryptedPlaintext);
            System.out.println("Decrypted Message in big integer: " + decryptedBigInt);

            // Step 2: Save results to files
            try (BufferedWriter encryptedWriter = new BufferedWriter(new FileWriter("encryptedRSA.txt"));
                 BufferedWriter decryptedWriter = new BufferedWriter(new FileWriter("decryptedRSA.txt"))) {

                // Save encrypted results
                encryptedWriter.write("Encrypted Cipher in plaintext: " + encryptedPlaintext + "\n");
                encryptedWriter.write("Encrypted Cipher in big integer: " + encryptedBigInt);

                // Save decrypted results
                decryptedWriter.write("Decrypted Message in plaintext: " + decryptedPlaintext + "\n");
                decryptedWriter.write("Decrypted Message in big integer: " + decryptedBigInt);
            }

            System.out.println("Results saved to encryptedRSA.txt and decryptedRSA.txt.");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}