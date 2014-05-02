import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;

import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

/**
 * Created by andresmonroy on 4/28/14.
 */
public abstract class SecureEntity {
	private final String entityName;
	protected PrivateKey privateKey;
	protected PublicKey publicKey;

	protected SecureEntity(String entityName, boolean showLogging){
		this.entityName = entityName;
		privateKey = KeyManager.getPrivateKey(entityName);
		publicKey = KeyManager.getPublicKey(entityName);
		LoggingManager.initLogging(showLogging);
	}

	protected int getLength(InputStream in) throws IOException {
		byte[] buff = new byte[4];
		ByteBuffer bytes = ByteBuffer.wrap(buff);
		IOUtils.read(in, buff, 0, 4);
		return bytes.getInt();
	}

	protected void sendLength(int length, OutputStream out) throws IOException {
		IOUtils.write(ByteBuffer.allocate(4).putInt(length).array(), out);
	}

	public String getEntityName(){
		return entityName;
	}



}
