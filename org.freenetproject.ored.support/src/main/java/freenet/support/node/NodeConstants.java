package freenet.support.node;

import static java.util.concurrent.TimeUnit.*;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

// TODO: Modularity: Remove these constants from class Node
public class NodeConstants {
    public static final int PACKETS_IN_BLOCK = 32;
    public static final int PACKET_SIZE = 1024;
    public static final double DECREMENT_AT_MIN_PROB = 0.25;
    public static final double DECREMENT_AT_MAX_PROB = 0.5;
    // Send keepalives every 7-14 seconds. Will be acked and if necessary resent.
    // Old behaviour was keepalives every 14-28. Even that was adequate for a 30 second
    // timeout. Most nodes don't need to send keepalives because they are constantly busy,
    // this is only an issue for disabled darknet connections, very quiet private networks
    // etc.
    public static final long KEEPALIVE_INTERVAL = SECONDS.toMillis(7);
    // If no activity for 30 seconds, node is dead
    // 35 seconds allows plenty of time for resends etc even if above is 14 sec as it is on older nodes.
    public static final long MAX_PEER_INACTIVITY = SECONDS.toMillis(35);
    /** Time after which a handshake is assumed to have failed. */
    public static final int HANDSHAKE_TIMEOUT = (int) MILLISECONDS.toMillis(4800); // Keep the below within the 30 second assumed timeout.
    // Inter-handshake time must be at least 2x handshake timeout
    public static final int MIN_TIME_BETWEEN_HANDSHAKE_SENDS = HANDSHAKE_TIMEOUT*2; // 10-20 secs
    public static final int RANDOMIZED_TIME_BETWEEN_HANDSHAKE_SENDS = HANDSHAKE_TIMEOUT*2; // avoid overlap when the two handshakes are at the same time
    public static final int MIN_TIME_BETWEEN_VERSION_PROBES = HANDSHAKE_TIMEOUT*4;
    public static final int RANDOMIZED_TIME_BETWEEN_VERSION_PROBES = HANDSHAKE_TIMEOUT*2; // 20-30 secs
    public static final int MIN_TIME_BETWEEN_VERSION_SENDS = HANDSHAKE_TIMEOUT*4;
    public static final int RANDOMIZED_TIME_BETWEEN_VERSION_SENDS = HANDSHAKE_TIMEOUT*2; // 20-30 secs
    public static final int MIN_TIME_BETWEEN_BURSTING_HANDSHAKE_BURSTS = HANDSHAKE_TIMEOUT*24; // 2-5 minutes
    public static final int RANDOMIZED_TIME_BETWEEN_BURSTING_HANDSHAKE_BURSTS = HANDSHAKE_TIMEOUT*36;
    public static final int MIN_BURSTING_HANDSHAKE_BURST_SIZE = 1; // 1-4 handshake sends per burst
    public static final int RANDOMIZED_BURSTING_HANDSHAKE_BURST_SIZE = 3;
    // If we don't receive any packets at all in this period, from any node, tell the user
    public static final long ALARM_TIME = MINUTES.toMillis(1);

    static final long MIN_INTERVAL_BETWEEN_INCOMING_SWAP_REQUESTS = MILLISECONDS.toMillis(900);
    static final long MIN_INTERVAL_BETWEEN_INCOMING_PROBE_REQUESTS = MILLISECONDS.toMillis(1000);
    public static final int SYMMETRIC_KEY_LENGTH = 32; // 256 bits - note that this isn't used everywhere to determine it
    /** Should inserts ignore low backoff times by default? */
    public static final boolean IGNORE_LOW_BACKOFF_DEFAULT = false;
    /** Definition of "low backoff times" for above. */
    public static final long LOW_BACKOFF = SECONDS.toMillis(30);
    /** Should inserts be fairly blatently prioritised on accept by default? */
    public static final boolean PREFER_INSERT_DEFAULT = false;
    /** Should inserts fork when the HTL reaches cacheability? */
    public static final boolean FORK_ON_CACHEABLE_DEFAULT = true;
}
