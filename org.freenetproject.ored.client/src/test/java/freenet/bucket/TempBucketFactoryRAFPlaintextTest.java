package freenet.bucket;

public class TempBucketFactoryRAFPlaintextTest extends TempBucketFactoryRAFBase {

	@Override
	public boolean enableCrypto() {
		return false;
	}

}
