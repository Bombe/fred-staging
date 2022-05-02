package freenet.bucket;

import freenet.support.Logger;
import freenet.support.io.Closer;

public class BucketCloser extends Closer {
	/**
	 * Frees the given bucket. Notice that you have to do removeFrom() for persistent buckets yourself.
	 * @param bucket The Bucket to close.
	 */
	public static void close(Bucket bucket) {
		if (bucket != null) {
			try {
				bucket.free();
			} catch(RuntimeException e) {
				Logger.error(Closer.class, "Error during free().", e);
			}
		}
	}
}
