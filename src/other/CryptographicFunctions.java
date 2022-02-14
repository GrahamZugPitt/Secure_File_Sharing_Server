package other;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.util.encoders.Hex;

public final class CryptographicFunctions {

    private static final int AES_KEY_SIZE = 128;
    private static final int IV_SIZE = 16;
    private static final int RSA_KEY_SIZE = 4096;

    private static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";
    private static final String AES_ALGORITHM = "AES/CBC/PKCS7Padding";

    //Creating a cryptographic random number generator
    private static final SecureRandom SEC_RNG = new SecureRandom();

    // Creates 256 bit digest
    private static final SHA3.DigestSHA3 SHA_DIGEST = new SHA3.Digest256();

    public static KeyPair generateRSAKeyPair() {
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(RSA_KEY_SIZE);
            return keyPairGen.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }

    public static SecretKey generateAESKey() throws GeneralSecurityException {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        // Initialize KeyGenerator
        kg.init(AES_KEY_SIZE, SEC_RNG);
        // Create the key
        return kg.generateKey();
    }

    public static SecretKey generateAESKey(int customSize) throws GeneralSecurityException {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        // Initialize KeyGenerator
        kg.init(customSize, SEC_RNG);
        // Create the key
        return kg.generateKey();
    }

    //For file encryption
    public static SecretKey hashKey(SecretKey seedKey, int keyIndex) {
        byte[] digest = seedKey.getEncoded();
        for (int i = 1; i < keyIndex; i++) {
            digest = hash(digest);
        }
        return new SecretKeySpec(digest, 0, digest.length, "AES");
    }

    public static SecretKey deriveKey(SecretKey currentKey, int currentKeyVersion, int fileKeyVersion) {
        if (currentKeyVersion == fileKeyVersion) {
            return currentKey;
        }
        int numHashes = currentKeyVersion - fileKeyVersion;
        return hashKey(currentKey, numHashes);
    }

    public static PublicKey decodePublicRSAKey(String input) throws GeneralSecurityException {
        input = input.trim();
        byte[] encoded = Hex.decode(input);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(keySpec);
    }

    public static IvParameterSpec generateIV() {
        byte[] iv = new byte[IV_SIZE];
        SEC_RNG.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static Cipher createEncryptionCipher(PublicKey key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher;
    }

    public static Cipher createDecryptionCipher(PrivateKey key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher;
    }

    public static Cipher createSignatureCipher(PrivateKey key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher;
    }

    public static Cipher createVerificationCipher(PublicKey key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher;
    }

    public static Cipher createEncryptionCipher(SecretKey key, IvParameterSpec iv) throws GeneralSecurityException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher;
    }

    public static Cipher createDecryptionCipher(SecretKey key, IvParameterSpec iv) throws GeneralSecurityException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher;
    }

    public static byte[] hash(byte[] bytes) {
        return SHA_DIGEST.digest(bytes);
    }

    public static byte[] hash(byte[] bytes, byte[] salt) {
        byte[] merged = new byte[bytes.length + salt.length];  //resultant array of size first array and second array  
        System.arraycopy(bytes, 0, merged, 0, bytes.length);
        System.arraycopy(salt, 0, merged, bytes.length, salt.length);
        return hash(merged);
    }

    public static byte[] bruteForceHash(byte[] hash, byte[] salt, int size) {
        if (hash == null) {
            throw new NullPointerException();
        } else if (size <= 0) {
            throw new IllegalArgumentException();
        }

        byte[] beforeHash = new byte[size];
        final int numLoops = (1 << (size * Byte.SIZE));
        for (int i = 0; i < numLoops; i++) {
            // Treat beforeHash like one giant integer. Keep incrementing it and use a for-loop to handle overflows.
            beforeHash[0]++;
            for (int j = 1; beforeHash[j - 1] == 0 && j < beforeHash.length; j++) {
                beforeHash[j]++;
            }
            // See if the hash is a correct one
            byte[] newHash = hash(beforeHash, salt);
            if (Arrays.equals(hash, newHash)) {
                return beforeHash;
            }
        }

        return null;
    }
}
