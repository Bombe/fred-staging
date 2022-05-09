package freenet.client.async;

import freenet.bucket.Bucket;
import freenet.keys.FreenetURI;

public interface DownloadCache {

	public CacheFetchResult lookupInstant(FreenetURI key, boolean noFilter, boolean mustCopy, Bucket preferred);

	public CacheFetchResult lookup(FreenetURI key, boolean noFilter, ClientContext context, boolean mustCopy,
			Bucket preferred);

}
