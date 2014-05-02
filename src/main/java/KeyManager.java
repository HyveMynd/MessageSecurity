import org.apache.commons.io.IOUtils;

import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by andresmonroy on 4/28/14.
 */
public class KeyManager {

	private static final String KEY_DIR = "keys/";
	private static final String PRIVATE_SUFFIX = "-private.key";
	private static final String PUBLIC_SUFFIX = "-public.key";

	/**
	 * Check whether both the public and private key files exist for the given entity.
	 * @param entity
	 * @return
	 */
	public static boolean keyExists(String entity){
		boolean publicExists = new File(KEY_DIR + entity + PRIVATE_SUFFIX).exists();
		boolean privateExists = new File(KEY_DIR + entity + PUBLIC_SUFFIX).exists();
		return publicExists && privateExists;
	}

	/**
	 * Save the key pair to disk for the given entity.
	 * @param keyPair the RSA key pair
	 * @param entity the name of the entity to which the keys belong to.
	 * @return true if the keys were saved
	 */
	public static boolean saveKeys(KeyPair keyPair, String entity){
		File file = new File(KEY_DIR);
		if (!file.exists()){
			file.mkdirs();
		}

		try {
			// Write the private key
			File keyFile = new File(file, entity + PRIVATE_SUFFIX);
			IOUtils.write(keyPair.getPrivate().getEncoded(), new FileOutputStream(keyFile));

			// Write the public key
			keyFile = new File(file, entity + PUBLIC_SUFFIX);
			IOUtils.write(keyPair.getPublic().getEncoded(), new FileOutputStream(keyFile));
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	/**
	 * Gets the key pair belonging to the given entity from disk. Assumes the key pair exists on disk.
	 * @param entity the name of the entity to which the keys belong to.
	 * @return The public and private key pair.
	 */
	public static KeyPair getKeys(String entity){
		File privateKeyFile = new File(KEY_DIR + entity + PRIVATE_SUFFIX);
		File publicKeyFile = new File(KEY_DIR + entity + PUBLIC_SUFFIX);
		byte[] publicKeyArray = new byte[(int) publicKeyFile.length()];
		byte[] privateKeyArray = new byte[(int) privateKeyFile.length()];
		PublicKey publicKey = null;
		PrivateKey privateKey = null;
		System.out.println(System.getProperty("user.dir"));
		try{
			IOUtils.read(new FileInputStream(privateKeyFile), privateKeyArray);
			IOUtils.read(new FileInputStream(publicKeyFile), publicKeyArray);
			publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyArray));
			privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyArray));
		} catch(IOException e){
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return new KeyPair(publicKey, privateKey);
	}

	public static PublicKey getPublicKey(String entity) {
		byte[] keyBytes = null;
		File f = new File(KEY_DIR + entity + PUBLIC_SUFFIX);
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(f);
			DataInputStream dis = new DataInputStream(fis);
			keyBytes = new byte[(int)f.length()];
			dis.readFully(keyBytes);
			dis.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		X509EncodedKeySpec spec =
				new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = null;
		try {
			kf = KeyFactory.getInstance("RSA");
			return kf.generatePublic(spec);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static PublicKey createPublicKey(byte[] keyBytes){
		X509EncodedKeySpec spec =
				new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = null;
		try {
			kf = KeyFactory.getInstance("RSA");
			return kf.generatePublic(spec);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static PrivateKey createPrivateKey(byte[] keyBytes){
		PKCS8EncodedKeySpec spec =
				new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = null;
		try {
			kf = KeyFactory.getInstance("RSA");
			return kf.generatePrivate(spec);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static PrivateKey getPrivateKey(String entity) {
		byte[] keyBytes = null;
		File f = new File(KEY_DIR + entity + PRIVATE_SUFFIX);
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(f);
			DataInputStream dis = new DataInputStream(fis);
			keyBytes = new byte[(int)f.length()];
			dis.readFully(keyBytes);
			dis.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		PKCS8EncodedKeySpec spec =
				new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = null;
		try {
			kf = KeyFactory.getInstance("RSA");
			return kf.generatePrivate(spec);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return null;
	}
}
