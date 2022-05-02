package freenet.client.async;

import freenet.bucket.Bucket;
import freenet.client.ClientMetadata;
import freenet.client.FetchResult;

public class CacheFetchResult extends FetchResult {
	
	public final boolean alreadyFiltered;

	public CacheFetchResult(ClientMetadata dm, Bucket fetched, boolean alreadyFiltered) {
		super(dm, fetched);
		this.alreadyFiltered = alreadyFiltered;
	}

}
