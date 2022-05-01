package freenet.bucket;

import freenet.support.api.Bucket;

// A Bucket which does not support being stored to the database. E.g. SegmentedBCB.
public interface NotPersistentBucket extends Bucket {

	// No methods
	
}
