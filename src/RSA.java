

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


    public RSA() {
        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger q = BigInteger.probablePrime(bitLength / 2, random);
        n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        e = BigInteger.probablePrime(bitLength / 2, random);


        while (!phi.gcd(e).equals(BigInteger.ONE)) {
            e = e.add(BigInteger.ONE);
        }

        d = e.modInverse(phi); // Private exponent d
    }


    public BigInteger encrypt(BigInteger message) {
        return message.modPow(e, n); // ciphertext = (message^e) % n
    }


    public BigInteger decrypt(BigInteger ciphertext) {
        return ciphertext.modPow(d, n); // plaintext = (ciphertext^d) % n
    }

    /**
     * Converts a string to a BigInteger
     */
    public BigInteger fromStringToBigInteger(String input) {
        return new BigInteger(input.getBytes());
    }


    public String fromBigIntegerToString(BigInteger input) {
        return new String(input.toByteArray());
    }

    public static void main(String[] args) {
        try {
            RSA rsa = new RSA();


            System.out.println("The generated public key in plaintext: " + rsa.fromBigIntegerToString(rsa.e));
            System.out.println("The generated public key in big integer: " + rsa.e);
            System.out.println("The generated private key in plaintext: " + rsa.fromBigIntegerToString(rsa.d));
            System.out.println("The generated private key in big integer: " + rsa.d);


            String plaintextFilePath = "security.txt";
            String plaintext = new String(Files.readAllBytes(Paths.get(plaintextFilePath))).trim();
            System.out.println("Original Message from file: " + plaintext);


            BigInteger plaintextBigInt = rsa.fromStringToBigInteger(plaintext);


            BigInteger encryptedBigInt = rsa.encrypt(plaintextBigInt);
            String encryptedPlaintext = rsa.fromBigIntegerToString(encryptedBigInt);


            BigInteger decryptedBigInt = rsa.decrypt(encryptedBigInt);
            String decryptedPlaintext = rsa.fromBigIntegerToString(decryptedBigInt);


            System.out.println("Message in plaintext: " + plaintext);
            System.out.println("Message in big integer: " + plaintextBigInt);

            System.out.println("Encrypted Cipher in plaintext: " + encryptedPlaintext);
            System.out.println("Encrypted Cipher in big integer: " + encryptedBigInt);

            System.out.println("Decrypted Message in plaintext: " + decryptedPlaintext);
            System.out.println("Decrypted Message in big integer: " + decryptedBigInt);


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