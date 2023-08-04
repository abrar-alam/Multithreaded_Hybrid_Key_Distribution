package project;

import java.io.*;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class ClientB {

	private static final int ID_NONCE_LENGTH = 3; // Length of either ID or NONCE is 3 digit

	private Map<String, String> env = System.getenv();
	private static String public_key_b = env.get("public_key_b");
	private static String private_key_b = env.get("private_key_b");
	private static String public_key_KDC = env.get("public_key_KDC");
	private static String private_key_KDC = env.get("private_key_KDC");
	
	private static String N_B = env.get("N_B"); // The nonce value to be sent to the KDC to authenticate it afterwards

	public static void main(String[] args) throws IOException, IOException, BadPaddingException,
			IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {

		ClientB B = new ClientB();

		if (args.length != 2) {
			System.err.println("Usage: java ClientB <host name> <port number>");
			System.exit(1);
		}

		String hostName = args[0];
		int portNumber = Integer.parseInt(args[1]);

		try (Socket kkSocket = new Socket(hostName, portNumber);
				PrintWriter out = new PrintWriter(kkSocket.getOutputStream(), true);
				BufferedReader in = new BufferedReader(new InputStreamReader(kkSocket.getInputStream()));) {
			BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
			String ID_B, N_K2 = "", ID_K = "", temp = "", authMessage1, authMessage2, authMessage3, authMessage4,
					authMessage5_seg1, authMessage5_seg2, authMessage7, userInput, encrypted_secret_pass,
					decrypted_secret_password = "", K_AB;

			System.out.println("Please enter your 3 digit ID:");
			ID_B = stdIn.readLine();
			// Commented because nonce is not supposed to be sent in this lab
			// System.out.println("Please enter you 3 digit nonce:");
			// N_A = stdIn.readLine();
			authMessage1 = ID_B;

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

				temp = RSAUtil.decrypt_private_key_to_string(authMessage2, private_key_b);
				N_K2 = StringUtil.get_leading_string(temp, ID_NONCE_LENGTH);
				ID_K = StringUtil.get_trailing_string(temp, ID_NONCE_LENGTH);

				temp = N_B + N_K2;
			}
			// Now send authMessage3
			System.out.println("preparing to send authMessage3 to KDC..\nSending Auth message "
					+ "3: concatenation of N_B and N_K2: " + temp);

			authMessage3 = RSAUtil.encrypt_public_key_to_string(temp, public_key_KDC);

			System.out.println("About to send the authMessage 3 to KDC");
			out.println(authMessage3);

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

			temp = RSAUtil.decrypt_private_key_to_string(authMessage4, private_key_b);

			if (!(temp.equalsIgnoreCase(N_B))) {
				stdIn.close();
				in.close();
				out.close();
				kkSocket.close();
				System.out.println("KDC returned invalid nonce N_B! Closing connection");
				System.exit(1);
			}

			// Now receive the auth message 5 part1
			authMessage5_seg1 = in.readLine();
			authMessage5_seg2 = in.readLine();

			// Seg 1 is the public key encrypted symmetric encrypted K_B,
			authMessage5_seg1 = RSAUtil.decrypt_private_key_to_string(authMessage5_seg1, private_key_b);
			// Seg2 is the private key encrypted symmetric key
			authMessage5_seg2 = RSAUtil.decrypt_public_key_to_string(authMessage5_seg2, public_key_KDC);

			// The received K_B, that is the master key of B shared with KDC
			authMessage5_seg1 = AESUtil.decrypt(authMessage5_seg1, authMessage5_seg2,
					authMessage5_seg2.substring(0, 4));
			System.out.println("Decrypted K_B: " + authMessage5_seg1);

			// By now whe completed phase 1 for A
			// Now entering the main application after the authentication

			System.out.println("Phase 1 completed");

			// Now start phase 2
			authMessage7 = in.readLine();

			authMessage7 = AESUtil.decrypt(authMessage7, authMessage5_seg1, authMessage5_seg1.substring(0, 4));
			K_AB = StringUtil.get_leading_string(authMessage7, ID_NONCE_LENGTH);

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
