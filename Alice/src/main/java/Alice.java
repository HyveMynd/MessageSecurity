
import com.sun.org.apache.xalan.internal.xsltc.compiler.sym;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.spi.LoggerFactory;
import org.slf4j.Logger;

import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;

/**
 * Created by andresmonroy on 4/28/14.
 */
public class Alice extends SecureEntity {
	private static Alice alice;
	private static final Logger logger = org.slf4j.LoggerFactory.getLogger(Alice.class.getName());
	private KeyPair keys;
	private PublicKey caPublic;
	private Socket socket;
	private PublicKey bobKey;
	private String message = "This is the sent message";
	private String secretKey = "ThisIsSpartaThisIsSparta";


	private Alice(boolean showOutput) {
		super("alice", showOutput);
	}

	private Alice(){
		super("alice", false);
	}

	public void start(String address, int port){
		try {
			logger.info("Connecting to {}:{}", address, port);
			socket = new Socket(address, port);
		} catch (IOException e) {
			logger.error(e.getMessage(), e);
		} catch (IllegalArgumentException e){
			logger.error(e.getMessage(), e);
		}
		beginTransaction();
	}

	private void beginTransaction() {
		keys = KeyManager.getKeys("alice");
		caPublic = KeyManager.getPublicKey("ca");

		try {
			InputStream in = socket.getInputStream();
			OutputStream out = socket.getOutputStream();

			// Get bobs public key digest
			int length = getLength(in);
			byte[] keyDigest = IOUtils.toByteArray(socket.getInputStream(), length);
			logger.info("Received message.");
			logger.info("Bob's signed digest is {}", Hex.encodeHexString(keyDigest));

			// Get Bobs public key and compare
			length = getLength(in);
			byte[] bobPublic = IOUtils.toByteArray(socket.getInputStream(), length);
			logger.info("Received message.");
			logger.info("Bob's public key is {}", Hex.encodeHexString(bobPublic));
			logger.info("Comparing messages for CA verification.");
			if (!KeyGenerator.verifySignature(caPublic, keyDigest, bobPublic)){
				socket.close();
				logger.error("Signed digest and public key are not authentic. Exiting.");
				System.exit(1);
			}
			logger.info("Verification successful.");
			bobKey = KeyManager.createPublicKey(bobPublic);

			// Hash and encode the message to send
			logger.info("Hashing and encoding message with SHA-1 and  Alice's public key");
			byte[] signedData = KeyGenerator.signData(privateKey, message.getBytes());
			logger.info("Signed digest of orginal message is {}", Hex.encodeHexString(signedData));

			// Concatenate encoded message to original and encode with symmetric key
			logger.info("Concatenating original message to signed message and encrypting with 3DES");
			ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
			byteStream.write(message.getBytes());
			byteStream.write("\n".getBytes());
			byteStream.write(signedData);
			logger.info("Concatenated message is {}", Hex.encodeHexString(byteStream.toByteArray()));
			byte[] symMessage = KeyGenerator.symmetricEncrypt(byteStream.toByteArray(), secretKey);
			logger.info("Symmetrically encoded message is {}", Hex.encodeHexString(symMessage));

			// Encode the secret key with bobs public
			logger.info("Encoding secret key: {} with bob's public key", secretKey);
			byte[] publicEncodedData = KeyGenerator.encodeData(bobKey, secretKey.getBytes());

			// Send the encoded key
			logger.info("Sending encoded symmetric key: {}", Hex.encodeHexString(publicEncodedData));
			sendLength(publicEncodedData.length, out);
			IOUtils.write(publicEncodedData, out);

			// Send the encoded message
			logger.info("Sending symmetrically encoded data: {}", Hex.encodeHexString(symMessage));
			sendLength(symMessage.length, out);
			IOUtils.write(symMessage, out);

			// Close socket
			logger.info("Alice done. Exiting.");
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
			alice =  new Alice(options.contains("v"));
			address = args[1];
			try{
				port = Integer.parseInt(args[2]);
			} catch (NumberFormatException e){
				System.out.println("Not a valid port number.");
				System.exit(1);
			}
			alice.start(address, port);
		} else {
			alice = new Alice();
			address = args[0];
			try{
				port = Integer.parseInt(args[1]);
			} catch (NumberFormatException e){
				System.out.println("Not a valid port number.");
				System.exit(1);
			}
			alice.start(address, port);
		}
	}

	public static void main(String[] args) {
		if (args.length < 1){
			System.out.println("Incorrect number of arguments.");
		}
		parseArgs(args);
	}
}
