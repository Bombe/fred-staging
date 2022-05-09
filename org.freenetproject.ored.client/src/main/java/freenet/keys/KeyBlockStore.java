package freenet.keys;

// TODO: Modularity: Make Node class implement this
public interface KeyBlockStore {

	/**
	 * Store a datum.
	 * @param block a KeyBlock
	 * @param deep If true, insert to the store as well as the cache. Do not set this to
	 * true unless the store results from an insert, and this node is the closest node to
	 * the target; see the description of chkDatastore.
	 */
	void store(KeyBlock block, boolean deep, boolean canWriteClientCache, boolean canWriteDatastore, boolean forULPR)
			throws KeyCollisionException;

	void store(SSKBlock block, boolean deep, boolean overwrite, boolean canWriteClientCache, boolean canWriteDatastore,
			boolean forULPR) throws KeyCollisionException;

	/**
	 * Fetch a block from the datastore.
	 */
	KeyBlock fetch(Key key, boolean canReadClientCache, boolean canWriteClientCache, boolean canWriteDatastore,
			boolean forULPR, BlockMetadata meta);

	ClientKeyBlock fetch(ClientSSK clientSSK, boolean canReadClientCache, boolean canWriteClientCache,
			boolean canWriteDatastore) throws SSKVerifyException;

	CHKBlock fetch(NodeCHK key, boolean dontPromote, boolean canReadClientCache, boolean canWriteClientCache,
			boolean canWriteDatastore, boolean forULPR, BlockMetadata meta);

	SSKBlock fetch(NodeSSK key, boolean dontPromote, boolean canReadClientCache, boolean canWriteClientCache,
			boolean canWriteDatastore, boolean forULPR, BlockMetadata meta);

}
