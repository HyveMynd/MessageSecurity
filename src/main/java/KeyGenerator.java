import com.sun.swing.internal.plaf.metal.resources.metal;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.spi.LoggerFactory;
import org.slf4j.Logger;

import javax.crypto.*;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * Created by andresmonroy on 4/28/14.
 */
public class KeyGenerator {
	private static final Logger logger = org.slf4j.LoggerFactory.getLogger(KeyGenerator.class.getName());

	public static KeyPair getKeyPair() {
		KeyPairGenerator rsaGen = null;
		try {
			rsaGen = KeyPairGenerator.getInstance("RSA");
			rsaGen.initialize(512);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return rsaGen.generateKeyPair();
	}

	public static byte[] digestMessage(byte[] message){
		MessageDigest md = null;
		byte[] digestedMsg = null;
		try{
			md = MessageDigest.getInstance("SHA-1");
			digestedMsg = md.digest(message);
		} catch (NoSuchAlgorithmException e){
			e.printStackTrace();
		}
		return digestedMsg;
	}

	public static byte[] symmetricEncrypt(byte[] message, String key)  {
		byte[] encMessage = null;
		try {
			logger.debug(key);
			logger.debug(Hex.encodeHexString(key.getBytes()));
			Cipher cipher = Cipher.getInstance("DESede");
			DESedeKeySpec keySpec = new DESedeKeySpec(key.getBytes());
			SecretKey secretKey = SecretKeyFactory.getInstance("DESede").generateSecret(keySpec);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			encMessage = cipher.doFinal(message);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		}
		return encMessage;
	}

	public static byte[] symmetricDecrypt(byte[] encMessage, byte[] key){
		byte[] message = null;
		try {
			logger.debug(Hex.encodeHexString(key));
			Cipher cipher = Cipher.getInstance("DESede");
			DESedeKeySpec keySpec = new DESedeKeySpec(key);
			SecretKey secretKey = SecretKeyFactory.getInstance("DESede").generateSecret(keySpec);
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			message = cipher.doFinal(encMessage);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		}
		return message;
	}

	public static byte[] signData(PrivateKey keyToSign, byte[] dataToSign){
		byte[] signedData = null;
		try {
			Signature signer = Signature.getInstance("SHA1withRSA");
			signer.initSign(keyToSign);
			signer.update(dataToSign);
			signedData = signer.sign();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}

		return signedData;
	}

	public static byte[] encodeData(PublicKey publicKey, byte[] dataToEncode){
		byte[] encodedData = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			encodedData = cipher.doFinal(dataToEncode);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		}
		return encodedData;
	}

	public static byte[] decodeData(PrivateKey privateKey, byte[] dataToDecode){
		byte[] encodedData = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			encodedData = cipher.doFinal(dataToDecode);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		}
		return encodedData;
	}

	public static byte[] decodeData(PublicKey publicKey, byte[] dataToDecode){
		byte[] encodedData = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
			encodedData = cipher.doFinal(dataToDecode);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		}
		return encodedData;
	}

	public static boolean verifySignature(PublicKey keyToVerify, byte[] signedData, byte[] dataToVerify){
		boolean verified = false;
		try{
			Signature signer = Signature.getInstance("SHA1withRSA");
			signer.initVerify(keyToVerify);
			signer.update(dataToVerify);
			verified = signer.verify(signedData);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		return verified;
	}

	public static void main(String[] args) {
		KeyPair alice = getKeyPair();
		KeyPair bob = getKeyPair();
		KeyPair ca = getKeyPair();
		KeyManager.saveKeys(alice, "alice");
		KeyManager.saveKeys(bob, "bob");
		KeyManager.saveKeys(ca, "ca");
	}

}
