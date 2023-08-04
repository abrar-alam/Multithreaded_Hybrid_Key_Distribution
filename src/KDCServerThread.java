package project;

import java.net.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.io.*;

public class KDCServerThread extends Thread {
	private static final int SESSION_KEY_LENGTH = 8; // Length of symmetric key or precisely password as it is in
														// AESUtil
	private static final int SALT_VALUE_LENGTH = 4; // Length of the salt value used in symmetric encryption.
													// In our case, we use the first 4 char of the
													// symmetric key or password as salt value.
	private static final int ID_NONCE_LENGTH = 3; // Length of either ID or NONCE is 3 digit

	private Map<String, String> env = System.getenv();
	private static final String ID_K = env.get("ID_K");
	private static final String ID_A = env.get("ID_A");
	private static final String ID_B = env.get("ID_B");
	private static String public_key_a = env.get("public_key_a");
	private static String public_key_b = env.get("public_key_b");
	private static String public_key_KDC = env.get("public_key_KDC");
	private static String private_key_KDC = env.get("private_key_KDC");
	private static String PASSWORD = env.get("PASSWORD"); // One time password for creating a digital enevelope.
														  // This password is salted and then encrypted with a public key
	private static String N_K1 = env.get("N_K1"); //The nonce value to be sent to client A
	private static String N_K2 = env.get("N_K2"); //The nonce value to be sent to client B
	private static String K_A = env.get("K_A"); // Master symmetric key shared by this KDC server and client A
	private static String K_B = env.get("K_B"); // Master symmetric key shared by this KDC server and client B
	private static String K_AB = env.get("K_AB"); // The session key generated by this KDC server and supposed to be shared between client A, and B



	private static volatile int LOCK = 1;// Volatile to ensure thread safety (visibility of changes immediately to other threads)

	private Socket socket = null;

	public KDCServerThread(Socket socket) {
		super("KDCMultiServerThread");
		this.socket = socket;
	}

	

	public void run() {

		try (PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
				BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));) {
			String inputLine, outputLine, decryptedInputLine, encryptedOutputLine, authMessage1, authMessage2,
					authMessage3, authMessage4, authMessage5_seg1, authMessage5_seg2, authMessage6, authMessage7,
					N_A = "", N_B = "", temp;

			// Receive authMessage 1 containig ID_A or ID_B
			authMessage1 = in.readLine();
			// Send the authmessage 2
			if (authMessage1.equalsIgnoreCase(ID_A)) {
				authMessage2 = N_K1 + ID_K;
				authMessage2 = RSAUtil.encrypt_public_key_to_string(authMessage2, public_key_a);
			} else {
				authMessage2 = N_K2 + ID_K;
				authMessage2 = RSAUtil.encrypt_public_key_to_string(authMessage2, public_key_b);
			}

			out.println(authMessage2);

			// Npw recieve authMessage 3
			authMessage3 = in.readLine();
			// Dexrypt the public key encrypted authMessage3
			authMessage3 = RSAUtil.decrypt_private_key_to_string(authMessage3, private_key_KDC);

			if (authMessage1.equalsIgnoreCase(ID_A)) {// If this server is talking to A
				temp = StringUtil.get_trailing_string(authMessage3, ID_NONCE_LENGTH);
				if (!(temp.equalsIgnoreCase(N_K1))) {
					out.println(""); // Telling A that he has been denied
					socket.close();

					// stdIn.close();
					in.close();
					out.close();
				}
				// The temp var below contains the received nonce from A
				N_A = StringUtil.get_leading_string(authMessage3, ID_NONCE_LENGTH);
				authMessage4 = RSAUtil.encrypt_public_key_to_string(N_A, public_key_a);
			}

			else {// If this server is talking to B
				temp = StringUtil.get_trailing_string(authMessage3, ID_NONCE_LENGTH);
				if (!(temp.equalsIgnoreCase(N_K2))) {
					out.println(""); // Telling B that he has been denied
					socket.close();

					// stdIn.close();
					in.close();
					out.close();
				}
				// The temp var below contains the received nonce from A
				N_B = StringUtil.get_leading_string(authMessage3, ID_NONCE_LENGTH);
				authMessage4 = RSAUtil.encrypt_public_key_to_string(N_B, public_key_b);
			}

			out.println(authMessage4);
			// Now send authMessage5
			if (authMessage1.equalsIgnoreCase(ID_A)) {
				authMessage5_seg1 = AESUtil.encrypt(K_A, PASSWORD, PASSWORD.substring(0, 4));
				authMessage5_seg1 = RSAUtil.encrypt_public_key_to_string(authMessage5_seg1, public_key_a);
			} else {
				authMessage5_seg1 = AESUtil.encrypt(K_B, PASSWORD, PASSWORD.substring(0, 4));
				authMessage5_seg1 = RSAUtil.encrypt_public_key_to_string(authMessage5_seg1, public_key_b);
			}
			authMessage5_seg2 = RSAUtil.encrypt_private_key_to_string(PASSWORD, private_key_KDC);

			// Now send the authMessage 5
			System.out.println("About to send authMessage 5");
			out.println(authMessage5_seg1);
			out.println(authMessage5_seg2);

			System.out.println("Phase 1 completed!");

			// Now enter phase 2
			// if this server thread is dealing with side A, then wait to receive
			// "ID_A||ID_B"
			if (authMessage1.equalsIgnoreCase(ID_A)) {
				authMessage6 = in.readLine();
				// Now send the authMessage7
				temp = K_AB + ID_B;
				authMessage7 = AESUtil.encrypt(temp, K_A, K_A.substring(0, 4));
				out.println(authMessage7);
				LOCK = 0;

			}

			else {
				while (LOCK == 1) {
				}
				temp = K_AB + ID_A;
				authMessage7 = AESUtil.encrypt(temp, K_B, K_B.substring(0, 4));
				out.println(authMessage7);
			}

			System.out.println("Phase 2 completed");
			

			while ((inputLine = in.readLine()) != null) { // Continously listen to the client's question

			}
			socket.close();
		} catch (IOException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException
				| NoSuchPaddingException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
}
