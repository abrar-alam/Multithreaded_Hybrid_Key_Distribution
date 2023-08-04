package project;

import java.io.*;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class ClientA {

	private static final int ID_NONCE_LENGTH = 3; // Length of either ID or NONCE is 3 digit
	private Map<String, String> env = System.getenv();

	private static String public_key_a = env.get("public_key_a");

	private static String private_key_a = env.get("private_key_a");

	private static String public_key_KDC = env.get("public_key_KDC");

	private static String N_A = env.get("N_A"); // The nonce value to be sent to the KDC to authenticate it afterwards
	private static final String ID_A = env.get("ID_A"); // ID number of client A
	private static final String ID_B = env.get("ID_B"); // ID number of client B

	public static void main(String[] args) throws IOException, IOException, BadPaddingException,
			IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {

		ClientA A = new ClientA();

		if (args.length != 2) {
			System.err.println("Usage: java Alice <host name> <port number>");
			System.exit(1);
		}

		String hostName = args[0];
		int portNumber = Integer.parseInt(args[1]);

		try (Socket kkSocket = new Socket(hostName, portNumber);
				PrintWriter out = new PrintWriter(kkSocket.getOutputStream(), true);
				BufferedReader in = new BufferedReader(new InputStreamReader(kkSocket.getInputStream()));) {
			BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
			String ID_A, K_AB, N_B = "", N_K1 = "", ID_K = "", temp = "", authMessage1, authMessage2, authMessage3,
					authMessage4, authMessage5_seg1, authMessage5_seg2, authMessage7, userInput,
					encrypted_secret_pass, decrypted_secret_password = "";

			System.out.println("Please enter your 3 digit ID:");
			ID_A = stdIn.readLine();
			// Commented because nonce is not supposed to be sent in this lab
			// System.out.println("Please enter you 3 digit nonce:");
			// N_A = stdIn.readLine();
			authMessage1 = ID_A;

			System.out.println("Sending your ID to KDC...");

			out.println(authMessage1);

			// Now A will wait for KDC's response
			authMessage2 = in.readLine();
			// encrypted_secret_pass = in.readLine();

			// Print the received message2:
			System.out.println("Received encrypted auth message 2 from KDC: " + authMessage2);
			// Check for validity
			if ((authMessage2.equalsIgnoreCase(""))) {
				// out.println("");
				stdIn.close();
				in.close();
				out.close();
				kkSocket.close();
				System.out.println("Authmessage 1 validation failed.. Closing connection");
				System.exit(1);
			} else {
				// N_B = get_trailing_string(authMessage2, ID_NONCE_LENGTH);
				// temp = get_leading_string(authMessage2, ID_NONCE_LENGTH);
				temp = RSAUtil.decrypt_private_key_to_string(authMessage2, private_key_a);
				N_K1 = StringUtil.get_leading_string(temp, ID_NONCE_LENGTH);
				ID_K = StringUtil.get_trailing_string(temp, ID_NONCE_LENGTH);
				// temp = RSAUtil.decrypt_public_key_to_string(temp, A.public_key_bob);
				// decrypted_secret_password =
				// RSAUtil.decrypt_public_key_to_string(encrypted_secret_pass,
				// A.public_key_bob);

				// temp = AESUtil.decrypt(temp, decrypted_secret_password,
				// decrypted_secret_password.substring(0, 4));
				temp = N_A + N_K1;
			}
			// Now send authMessage3
			System.out.println("preparing to send authMessage3 to KDC..\nSending Auth message "
					+ "3: concatenation of N_A and N_K!: " + temp);
			// authMessage3 = stdIn.readLine();
			// temp = AESUtil.encrypt(N_B, PASSWORD, PASSWORD.substring(0, 4));
			authMessage3 = RSAUtil.encrypt_public_key_to_string(temp, public_key_KDC);

			// encrypted_secret_pass = RSAUtil.encrypt_private_key_to_string(PASSWORD,
			// private_key_alice);
			System.out.println("About to send the authMessage 3 to KDC");
			out.println(authMessage3);
			// out.println(encrypted_secret_pass);

			// Now wait for the flag from Bob telling us the status of the authentication
			// process
			if ((authMessage4 = in.readLine()).equalsIgnoreCase("")) {
				stdIn.close();
				in.close();
				out.close();
				kkSocket.close();
				System.out.println("Authmessage3 validation failed.. Closing connection");
				System.exit(1);
			} else {
				System.out.println("Authentication message 3 successful!y validated by KDC");
			}

			temp = RSAUtil.decrypt_private_key_to_string(authMessage4, private_key_a);

			if (!(temp.equalsIgnoreCase(N_A))) {
				stdIn.close();
				in.close();
				out.close();
				kkSocket.close();
				System.out.println("KDC returned invalid nonce N_A! Closing connection");
				System.exit(1);
			}

			// Now receive the auth message 5 part1
			authMessage5_seg1 = in.readLine();
			authMessage5_seg2 = in.readLine();

			// Seg 1 is the public key encrypted symmetric encrypted K_A,
			authMessage5_seg1 = RSAUtil.decrypt_private_key_to_string(authMessage5_seg1, private_key_a);
			// Seg2 is the private key encrypted symmetric key
			authMessage5_seg2 = RSAUtil.decrypt_public_key_to_string(authMessage5_seg2, public_key_KDC);

			// The received K_A, that is the master key of A shared with LDC
			authMessage5_seg1 = AESUtil.decrypt(authMessage5_seg1, authMessage5_seg2,
					authMessage5_seg2.substring(0, 4));
			System.out.println("Decrypted K_A: " + authMessage5_seg1);
			// By now whe completed phase 1 for A
			// Now entering the main application after the authentication

			System.out.println("Phase 1 completed");

			// Send the ID_A||ID_B AKA authMessage6
			out.println(ID_A + ID_B);

			authMessage7 = in.readLine();

			authMessage7 = AESUtil.decrypt(authMessage7, authMessage5_seg1, authMessage5_seg1.substring(0, 4));
			K_AB = get_leading_string(authMessage7, ID_NONCE_LENGTH);

			System.out.println("Session key K_AB received from the server: \n" + K_AB);
			System.out.println("Phase 2 completed");

			while ((userInput = stdIn.readLine()) != null) {

			}

		} catch (UnknownHostException e) {
			System.err.println("Don't know about host " + hostName);
			System.exit(1);
		} catch (IOException e) {
			System.err.println("Couldn't get I/O for the connection to " + hostName);
			System.exit(1);
		}
	}

}
