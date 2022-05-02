package freenet.bucket;

import java.io.IOException;

public class NullBucketFactory implements BucketFactory {

	@Override
	public RandomAccessBucket makeBucket(long size) throws IOException {
		return new NullBucket();
	}

}
