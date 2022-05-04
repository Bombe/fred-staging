package freenet.nodeapp;

import java.net.MalformedURLException;

import freenet.bucket.RandomAccessBucket;
import freenet.bucket.SimpleReadOnlyArrayBucket;
import freenet.client.ClientMetadata;
import freenet.client.InsertBlock;
import freenet.client.request.RequestClient;
import freenet.crypt.DummyRandomSource;
import freenet.keys.FreenetURI;
import freenet.keys.InsertableClientSSK;

public class NodeAndClientLayerTestBase {

    static final int PORT = 2048;
    static final int FILE_SIZE = 1024*1024;
    
    static RequestClient rc = new RequestClient() {

        @Override
        public boolean persistent() {
            return false;
        }

        @Override
        public boolean realTimeFlag() {
            return false;
        }
        
    };
    
    protected InsertBlock generateBlock(DummyRandomSource random) throws MalformedURLException {
        byte[] data = new byte[FILE_SIZE];
        random.nextBytes(data);
        RandomAccessBucket bucket = new SimpleReadOnlyArrayBucket(data);
        FreenetURI uri = InsertableClientSSK.createRandom(random, "test").getInsertURI();
        return new InsertBlock(bucket, new ClientMetadata(null), uri);
    }
    
}
