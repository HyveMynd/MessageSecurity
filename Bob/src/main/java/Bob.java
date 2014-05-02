import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;

import java.io.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Created by andresmonroy on 4/28/14.
 */
public class Bob extends SecureEntity {
	private static Bob bob;
	private static final Logger logger = org.slf4j.LoggerFactory.getLogger(Bob.class.getName());
	ServerSocket socket;
	PrivateKey caPrivate;
	PublicKey alicePublic;

	private Bob(boolean showOutput) {
		super("bob", showOutput);
	}

	private Bob(){
		super("bob", false);
	}

	public void start(String address, int port){
		try {
			logger.info("Waiting for connection on {}:{}", address, port);
			socket = new ServerSocket(port, 0, InetAddress.getByName(address));
			Socket conn = socket.accept();
			logger.info("Accepted connection. Beginning transaction.");
			beginTransaction(conn);
		} catch (IOException e) {
			logger.error(e.getMessage(), e);
		} catch (IllegalArgumentException e){
			logger.error(e.getMessage(), e);
		}
	}

	private void beginTransaction(Socket socket) {
		caPrivate = KeyManager.getPrivateKey("ca");
		alicePublic = KeyManager.getPublicKey("alice");

		byte[] digestedKey = KeyGenerator.signData(caPrivate, publicKey.getEncoded());
		try {
			OutputStream out = socket.getOutputStream();
			InputStream in = socket.getInputStream();

			// Send digested public key
			logger.info("Sending digested public key.");
			logger.info("Public key digest is {}", Hex.encodeHexString(digestedKey));
			sendLength(digestedKey.length, out);
			IOUtils.write(digestedKey, socket.getOutputStream());

			// Send public key
			logger.info("Sending bobs public key");
			logger.info("Public key is {}", Hex.encodeHexString(publicKey.getEncoded()));
			sendLength(publicKey.getEncoded().length, out);
			IOUtils.write(publicKey.getEncoded(), socket.getOutputStream());

			// Receive the secret key
			int length = getLength(in);
			byte[] encodedKey = IOUtils.toByteArray(in, length);
			logger.info("Encoded secret key is {}", Hex.encodeHexString(encodedKey));

			// Receive the sym encoded message
			length = getLength(in);
			byte[] symMessage = IOUtils.toByteArray(in, length);
			logger.info("Symmetrically encoded message is {}", Hex.encodeHexString(symMessage));

			// Decode Secret key
			logger.info("Decoding secret key.");
			byte[] secretKey = KeyGenerator.decodeData(privateKey, encodedKey);
			logger.info("Secret key is: {}", new String(secretKey));

			// Decode the Sym message
			logger.info("Decoding the Symmetrically encoded message");
			byte[] decodedMessage = KeyGenerator.symmetricDecrypt(symMessage, secretKey);
			logger.info("Concatenated message is: {}", Hex.encodeHexString(decodedMessage));
			logger.debug(new String(decodedMessage));

			// Decode the concatenated message
			String[] concatMessage = new String(decodedMessage).split("\n");
			String orignal = concatMessage[0];
			byte[] signedMessage = null;
			for (int i = 0; i < decodedMessage.length; i++){
				if ((byte)'\n' == decodedMessage[i]){
					signedMessage = new byte[decodedMessage.length - i - 1];
					System.arraycopy(decodedMessage, i+1, signedMessage, 0, signedMessage.length);
					break;
				}
			}
			logger.info("Original message is: {}", orignal);
			logger.info("Signed message digest is {}", Hex.encodeHexString(signedMessage));
			logger.info("Verifying original message against signed digest.");
			if(!KeyGenerator.verifySignature(alicePublic, signedMessage, orignal.getBytes())){
				socket.close();
				logger.error("Signed digest and message are not authentic. Exiting.");
				System.exit(1);
			}
			logger.info("Message Verified! Message is: {}", orignal);

			logger.info("Bob done. Exiting.");
			socket.close();
		} catch (IOException e) {
			logger.error(e.getMessage(), e);
		}
	}

	private static void parseArgs(String[] args){
		String address = "";
		int port = 0;
		if (args.length > 2){
			if (!args[0].startsWith("-")){
				System.out.println("Incorrect format. Options must start with a '-'. ");
				System.exit(1);
			}
			String options = args[0].substring(1);
			bob =  new Bob(options.contains("v"));
			address = args[1];
			try{
				port = Integer.parseInt(args[2]);
			} catch (NumberFormatException e){
				System.out.println("Not a valid port number.");
				System.exit(1);
			}
			bob.start(address, port);
		} else {
			bob = new Bob();
			address = args[0];
			try{
				port = Integer.parseInt(args[1]);
			} catch (NumberFormatException e){
				System.out.println("Not a valid port number.");
				System.exit(1);
			}
			bob.start(address, port);
		}
	}

	public static void main(String[] args) {
		if (args.length < 1){
			System.out.println("Incorrect number of arguments.");
		}
		parseArgs(args);
	}
}
