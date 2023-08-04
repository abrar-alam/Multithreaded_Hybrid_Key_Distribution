package project;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class AESUtil {

	/* Encryption Method */
	public static String encrypt(String strToEncrypt, String secret_key, String salt_value) {
		try {
			/* Declare a byte array. */
			byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			IvParameterSpec ivspec = new IvParameterSpec(iv);
			/* Create factory for secret keys. */
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			/* PBEKeySpec class implements KeySpec interface. */
			KeySpec spec = new PBEKeySpec(secret_key.toCharArray(), salt_value.getBytes(), 65536, 256);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
			/* Retruns encrypted value. */
			return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
		} catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException
				| InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException
				| NoSuchPaddingException e) {
			System.out.println("Error occured during encryption: " + e.toString());
		}
		return null;
	}

	/* Decryption Method */
	public static String decrypt(String strToDecrypt, String secret_key, String salt_value) {
		try {
			/* Declare a byte array. */
			byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			IvParameterSpec ivspec = new IvParameterSpec(iv);
			/* Create factory for secret keys. */
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			/* PBEKeySpec class implements KeySpec interface. */
			KeySpec spec = new PBEKeySpec(secret_key.toCharArray(), salt_value.getBytes(), 65536, 256);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
			/* Retruns decrypted value. */
			return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
		} catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException
				| InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException
				| NoSuchPaddingException e) {
			System.out.println("Error occured during decryption: " + e.toString());
		}
		return null;
	}

	/* Driver Code */
	public static void main(String[] args) {
		/* Message to be encrypted. */
		String originalval = "13";
		/* Call the encrypt() method and store result of encryption. */
		String encryptedval = encrypt(originalval, "12345", "54321");
		/* Call the decrypt() method and store result of decryption. */
		String decryptedval = decrypt(encryptedval, "12345", "54321");
		/*
		 * Display the original message, encrypted message and decrypted message on the
		 * console.
		 */
		System.out.println("Original value: " + originalval);
		System.out.println("Encrypted value: " + encryptedval);
		System.out.println("Length of the encrypted text: " + encryptedval.length());
		System.out.println("Decrypted value: " + decryptedval);
	}
}
