package freenet.client.request;

import freenet.keys.Key;

public interface KeysFetchingLocally extends RecentlyFailedChecker {

	/**
	 * Is this key currently being fetched locally?
	 * LOCKING: This should be safe just about anywhere, the lock protecting it is always taken last.
	 */
	public boolean hasKey(Key key, BaseSendableGet getterWaiting);
	
	/**
	 * Is this request:token pair being executed? FIXME this should be tracked by the inserter 
	 * itself.
	 */
	public boolean hasInsert(SendableRequestItemKey token);

}
