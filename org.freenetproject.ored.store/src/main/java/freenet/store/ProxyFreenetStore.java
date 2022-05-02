package freenet.store;

import java.io.IOException;

import freenet.client.async.UserAlertRegister;
import freenet.keys.BlockMetadata;
import freenet.keys.KeyCollisionException;
import freenet.keys.StorableBlock;
import freenet.support.Ticker;
import freenet.support.node.stats.StoreAccessStats;

public class ProxyFreenetStore<T extends StorableBlock> implements FreenetStore<T> {
	
	protected final FreenetStore<T> backDatastore;

	public ProxyFreenetStore(FreenetStore<T> backDatastore) {
		this.backDatastore = backDatastore;
	}
	
	@Override
	public long getBloomFalsePositive() {
		return backDatastore.getBloomFalsePositive();
	}

	@Override
	public long getMaxKeys() {
		return backDatastore.getMaxKeys();
	}

	@Override
	public long hits() {
		return backDatastore.hits();
	}

	@Override
	public long keyCount() {
		return backDatastore.keyCount();
	}

	@Override
	public long misses() {
		return backDatastore.misses();
	}

	@Override
	public void setMaxKeys(long maxStoreKeys, boolean shrinkNow)
			throws IOException {
		backDatastore.setMaxKeys(maxStoreKeys, shrinkNow);
	}

	@Override
	public long writes() {
		return backDatastore.writes();
	}

	@Override
	public StoreAccessStats getSessionAccessStats() {
		return backDatastore.getSessionAccessStats();
	}

	@Override
	public StoreAccessStats getTotalAccessStats() {
		return backDatastore.getTotalAccessStats();
	}

	@Override
	public void setUserAlertRegister(UserAlertRegister userAlertRegister) {
		this.backDatastore.setUserAlertRegister(userAlertRegister);
	}
	
	@Override
	public FreenetStore<T> getUnderlyingStore() {
		return this.backDatastore;
	}

	@Override
	public T fetch(byte[] routingKey, byte[] fullKey, boolean dontPromote,
			boolean canReadClientCache, boolean canReadSlashdotCache,
			boolean ignoreOldBlocks, BlockMetadata meta) throws IOException {
		return backDatastore.fetch(routingKey, fullKey, dontPromote, canReadClientCache, canReadSlashdotCache, ignoreOldBlocks, meta);
	}

	@Override
	public void put(T block, byte[] data, byte[] header, boolean overwrite,
			boolean oldBlock) throws IOException, KeyCollisionException {
		backDatastore.put(block, data, header, overwrite, oldBlock);
	}

	@Override
	public boolean probablyInStore(byte[] routingKey) {
		return backDatastore.probablyInStore(routingKey);
	}

	@Override
	public boolean start(Ticker ticker, boolean longStart) throws IOException {
		return backDatastore.start(ticker, longStart);
	}

	@Override
	public void close() {
		backDatastore.close();
	}

}
