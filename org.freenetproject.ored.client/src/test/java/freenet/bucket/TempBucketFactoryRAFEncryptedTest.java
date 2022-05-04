package freenet.bucket;

public class TempBucketFactoryRAFEncryptedTest extends TempBucketFactoryRAFBase {

    @Override
    public boolean enableCrypto() {
        return true;
    }

}
