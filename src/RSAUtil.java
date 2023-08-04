package project;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAUtil {

	private static String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCGUQlmkIAwg2FC4BoRabfQPLucnAL5/Tk4IVGEqdGmQJRccm4ERICnjAfYLLNbqs0ZHM/aG9yRLN4vloZe8V0onqXfpaq6IBKIlMDS03NVNaZ/oQFYO8XTN5E7XulwKg60qx9WHeJKy1Trmoq6O7yAy1HobMTGgyug2vQMSJiZEQIDAQAB";
	private static String privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIZRCWaQgDCDYULgGhFpt9A8u5ycAvn9OTghUYSp0aZAlFxybgREgKeMB9gss1uqzRkcz9ob3JEs3i+Whl7xXSiepd+lqrogEoiUwNLTc1U1pn+hAVg7xdM3kTte6XAqDrSrH1Yd4krLVOuairo7vIDLUehsxMaDK6Da9AxImJkRAgMBAAECgYAMmpCZAwDAbKelDJ3tmd/Bht1tB/fAiRpEMd4yJnRRlzhEx4ka1enDryByUNmAxdGKpHk9pIUpS05LJWMVCC2fVezTBFDi7VhLRi52q91sXWfl/lBpOshXDoFlyE359QG9SDiTfVvwnMa1EjvLQFx+/mqLiCZpHYSz6wkJ9CX8xQJBAKctQnZ1vpfr6V1AbQLWWhGl7Xxq3HPjKxaG2zIjF2OroiW+S6qGBnu/ywrbyGaNnFOTLn3fHCDjgWh+C1MSK70CQQDNrkDzzulkshczBEUfm7ZTpQPRwK6JqNJd5vLsyuo5DYFF7xYr6M2cYfvGdez8sB8NT8+6QuPimKd/U2FfGG3lAkBNCqSIZvawmH1xBhG2rwXPAEKThcOWfGgM95ToZBeRTTVqY2oHacBvIxH1LRgLetNCCJ/yTfFujqnCd+PMIqGZAkEAjEYDVkQPOPWcjNakreHsfy9TY4IdhxT0I8aWdpgNFcv4FlHwtRGY6MaKh9d1QQB8rP95lHZ6JNgno9ah2dE3YQJAVEAtMltbPFiDLOkxQM92TBTN7RfwJFRurtDqfRwhqzm95UmcmFTfCreahgS8BotxPktrlyZ2ddBjWwI69lpQPA==";

	public static PublicKey getPublicKey(String base64PublicKey) {
		PublicKey publicKey = null;
		try {
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			publicKey = keyFactory.generatePublic(keySpec);
			return publicKey;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return publicKey;
	}

	public static PrivateKey getPrivateKey(String base64PrivateKey) {
		PrivateKey privateKey = null;
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
		KeyFactory keyFactory = null;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		try {
			privateKey = keyFactory.generatePrivate(keySpec);
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return privateKey;
	}

	// Encrypts based on public key
	public static byte[] encrypt_public_key(String data, String publicKey) throws BadPaddingException,
			IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
		return cipher.doFinal(data.getBytes());
	}

	// AA: AA: My defined method that encrypts based on public key
	public static String encrypt_public_key_to_string(String data, String publicKey) throws BadPaddingException,
			IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
		return Base64.getEncoder().encodeToString(encrypt_public_key(data, publicKey));
	}

	// AA: My defined method that encrypts based on private key
	public static byte[] encrypt_private_key(String data, String privateKey) throws BadPaddingException,
			IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, getPrivateKey(privateKey));
		return cipher.doFinal(data.getBytes());
	}

	// AA: AA: My defined method that encrypts based on private key
	public static String encrypt_private_key_to_string(String data, String privateKey) throws BadPaddingException,
			IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
		return Base64.getEncoder().encodeToString(encrypt_private_key(data, privateKey));
	}

	// AA: My defined method that decrypts using public key
	public static String decrypt_public_key(byte[] data, PublicKey publicKey) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		return new String(cipher.doFinal(data));
	}

	// AA: My defined method that decrypts using public key
	public static String decrypt_public_key_to_string(String data, String base64PublicKey)
			throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException,
			NoSuchPaddingException {
		return decrypt_public_key(Base64.getDecoder().decode(data.getBytes()), getPublicKey(base64PublicKey));
	}

	// Decrypts based on private key
	public static String decrypt_private_key(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return new String(cipher.doFinal(data));
	}

	// Decrypts based on private key
	public static String decrypt_private_key_to_string(String data, String base64PrivateKey)
			throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException,
			NoSuchPaddingException {
		return decrypt_private_key(Base64.getDecoder().decode(data.getBytes()), getPrivateKey(base64PrivateKey));
	}

	public static void main(String[] args)
			throws IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {
		try {
//			String encryptedString = Base64.getEncoder()
//					.encodeToString(encrypt_public_key("Dhiraj is the author", publicKey));
			RSAKeyPairGenerator r1 = new RSAKeyPairGenerator();
			RSAKeyPairGenerator r2 = new RSAKeyPairGenerator();
			String encryptedString = encrypt_public_key_to_string("Dhiraj is the author", r1.getPublicKeyString());
			System.out.println("encrypted using public key: " + encryptedString);
			String decryptedString = RSAUtil.decrypt_private_key_to_string(encryptedString, r1.getPrivateKeyString());
			System.out.println("decrypted using private key: " + decryptedString);

			// AA: My added codes
//			encryptedString = encrypt_private_key_to_string("Dhiraj is the author", r2.getPrivateKeyString());
//			System.out.println("encrypted using private key: " + encryptedString);
//			decryptedString = decrypt_public_key_to_string(encryptedString, r2.getPublicKeyString());
//			System.out.println("Decrypted using public key: " + decryptedString);
			
			encryptedString = encrypt_private_key_to_string("234", privateKey);
			System.out.println("encrypted using private key: " + encryptedString);
			decryptedString = decrypt_public_key_to_string(encryptedString, publicKey);
			System.out.println("Decrypted using public key: " + decryptedString);
			
		} catch (NoSuchAlgorithmException e) {
			System.err.println(e.getMessage());
		}

	}
}
