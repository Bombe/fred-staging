/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.bucket;

import java.io.IOException;


public class ArrayBucketTest extends BucketTestBase {
	public ArrayBucketFactory abf = new ArrayBucketFactory();

	@Override
	protected Bucket makeBucket(long size) throws IOException {
		return abf.makeBucket(size);
	}

	@Override
	protected void freeBucket(Bucket bucket) throws IOException {
		bucket.free();
	}
}
