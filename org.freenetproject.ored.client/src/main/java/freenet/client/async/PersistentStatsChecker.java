package freenet.client.async;

// TODO: Modularity: class Node should implement this
public interface PersistentStatsChecker {

	long[] getTotalIO();

	/**
	 * Get the time since the node was started in milliseconds.
	 * @return Uptime in milliseconds
	 */
	long getUptime();

}
