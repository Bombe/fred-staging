package freenet.store;

import freenet.crypt.CryptFormatException;
import freenet.crypt.DSAGroup;
import freenet.crypt.DSAPrivateKey;
import freenet.crypt.DSAPublicKey;
import freenet.keys.StorableBlock;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

public class StoreDSAPublicKey extends DSAPublicKey implements StorableBlock {


    public StoreDSAPublicKey(DSAGroup g, BigInteger y) {
        super(g, y);
    }

    public StoreDSAPublicKey(DSAGroup g, String yAsHexString) throws NumberFormatException {
        super(g, yAsHexString);
    }

    public StoreDSAPublicKey(DSAGroup g, DSAPrivateKey p) {
        super(g, p);
    }

    public StoreDSAPublicKey(InputStream is) throws IOException, CryptFormatException {
        super(is);
    }

    public StoreDSAPublicKey(byte[] pubkeyBytes) throws IOException, CryptFormatException {
        super(pubkeyBytes);
    }

    public StoreDSAPublicKey() {
    }

    public static StoreDSAPublicKey create(byte[] pubkeyAsBytes) throws CryptFormatException {
        try {
            return new StoreDSAPublicKey(new ByteArrayInputStream(pubkeyAsBytes));
        } catch(IOException e) {
            throw new CryptFormatException(e);
        }
    }

    public static StoreDSAPublicKey from(DSAPublicKey key) {
        try {
            return StoreDSAPublicKey.create(key.asBytes());
        } catch (CryptFormatException e) {
            throw new RuntimeException(e);
        }
    }


        @Override
	public byte[] getFullKey() {
		return asBytesHash();
	}

	@Override
	public byte[] getRoutingKey() {
		return asBytesHash();
	}
}
