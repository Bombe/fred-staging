/*
 * Copyright 1999-2022 The Freenet Project
 * Copyright 2022 Marine Master
 *
 * This file is part of Oldenet.
 *
 * Oldenet is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or any later version.
 *
 * Oldenet is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with Oldenet.
 * If not, see <https://www.gnu.org/licenses/>.
 */

package freenet.node;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.io.Serial;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import freenet.bucket.ArrayBucketFactory;
import freenet.client.FetchContext;
import freenet.client.async.PersistentStatsChecker;
import freenet.client.request.RequestClient;
import freenet.client.request.RequestClientBuilder;
import freenet.clients.fcp.FCPMessage;
import freenet.clients.fcp.FCPUserAlert;
import freenet.clients.fcp.FeedMessage;
import freenet.clients.http.SecurityLevelsToadlet;
import freenet.clients.http.SimpleToadletServer;
import freenet.config.BooleanCallback;
import freenet.config.EnumerableOptionCallback;
import freenet.config.FilePersistentConfig;
import freenet.config.FreenetFilePersistentConfig;
import freenet.config.IntCallback;
import freenet.config.InvalidConfigValueException;
import freenet.config.LongCallback;
import freenet.config.NodeNeedRestartException;
import freenet.config.PersistentConfig;
import freenet.config.ShortCallback;
import freenet.config.StringCallback;
import freenet.config.SubConfig;
import freenet.crypt.DSAPublicKey;
import freenet.crypt.ECDH;
import freenet.crypt.MasterSecret;
import freenet.crypt.PersistentRandomSource;
import freenet.crypt.RandomSource;
import freenet.crypt.Yarrow;
import freenet.io.comm.DMT;
import freenet.io.comm.DisconnectedException;
import freenet.io.comm.FreenetInetAddress;
import freenet.io.comm.IOStatisticCollector;
import freenet.io.comm.Message;
import freenet.io.comm.MessageCore;
import freenet.io.comm.MessageFilter;
import freenet.io.comm.Peer;
import freenet.io.comm.PeerParseException;
import freenet.io.comm.ReferenceSignatureVerificationException;
import freenet.io.comm.TrafficClass;
import freenet.io.comm.UdpSocketHandler;
import freenet.io.xfer.PartiallyReceivedBlock;
import freenet.keys.BlockMetadata;
import freenet.keys.CHKBlock;
import freenet.keys.CHKVerifyException;
import freenet.keys.ClientCHK;
import freenet.keys.ClientCHKBlock;
import freenet.keys.ClientKey;
import freenet.keys.ClientKeyBlock;
import freenet.keys.ClientSSK;
import freenet.keys.ClientSSKBlock;
import freenet.keys.DatabaseKey;
import freenet.keys.Key;
import freenet.keys.KeyBlock;
import freenet.keys.KeyBlockStore;
import freenet.keys.KeyCollisionException;
import freenet.keys.KeyVerifyException;
import freenet.keys.MasterKeys;
import freenet.keys.MasterKeysFileSizeException;
import freenet.keys.MasterKeysWrongPasswordException;
import freenet.keys.NodeCHK;
import freenet.keys.NodeSSK;
import freenet.keys.SSKBlock;
import freenet.keys.SSKVerifyException;
import freenet.keys.StorableBlock;
import freenet.l10n.BaseL10n;
import freenet.l10n.NodeL10n;
import freenet.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import freenet.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import freenet.node.diagnostics.DefaultNodeDiagnostics;
import freenet.node.diagnostics.NodeDiagnostics;
import freenet.node.math.TimeSkewDetectorCallback;
import freenet.node.probe.Listener;
import freenet.node.probe.Probe;
import freenet.node.probe.Type;
import freenet.node.stats.DataStoreInstanceType;
import freenet.node.stats.DataStoreKeyType;
import freenet.node.stats.DataStoreStats;
import freenet.node.stats.DataStoreType;
import freenet.node.stats.NotAvailNodeStoreStats;
import freenet.node.stats.StoreCallbackStats;
import freenet.node.updater.NodeUpdateManager;
import freenet.node.useralerts.JVMVersionAlert;
import freenet.node.useralerts.MeaningfulNodeNameUserAlert;
import freenet.node.useralerts.NotEnoughNiceLevelsUserAlert;
import freenet.node.useralerts.PeersOffersUserAlert;
import freenet.node.useralerts.SimpleUserAlert;
import freenet.node.useralerts.TimeSkewDetectedUserAlert;
import freenet.nodelogger.Logger;
import freenet.pluginmanager.ForwardPort;
import freenet.pluginmanager.PluginDownLoaderOfficialHTTPS;
import freenet.pluginmanager.PluginManager;
import freenet.store.CHKStore;
import freenet.store.FreenetStore;
import freenet.store.NullFreenetStore;
import freenet.store.PubkeyStore;
import freenet.store.RAMFreenetStore;
import freenet.store.SSKStore;
import freenet.store.SlashdotStore;
import freenet.store.StoreCallback;
import freenet.store.StoreDSAPublicKey;
import freenet.store.caching.CachingFreenetStore;
import freenet.store.caching.CachingFreenetStoreTracker;
import freenet.store.saltedhash.ResizablePersistentIntBuffer;
import freenet.store.saltedhash.SaltedHashFreenetStore;
import freenet.support.Dimension;
import freenet.support.Executor;
import freenet.support.Fields;
import freenet.support.HTMLNode;
import freenet.support.HexUtil;
import freenet.support.JVMVersion;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger.LogLevel;
import freenet.support.PooledExecutor;
import freenet.support.PrioritizedTicker;
import freenet.support.ShortBuffer;
import freenet.support.SimpleFieldSet;
import freenet.support.Ticker;
import freenet.support.TokenBucket;
import freenet.support.io.Closer;
import freenet.support.io.FileUtil;
import freenet.support.io.NativeThread;
import freenet.support.math.MersenneTwister;
import freenet.support.node.FSParseException;
import freenet.support.node.NodeInitException;
import freenet.support.node.SemiOrderedShutdownHook;
import freenet.support.transport.ip.HostnameSyntaxException;
import org.tanukisoftware.wrapper.WrapperManager;

/**
 * Main Fred App entry class.
 *
 * @author Matthew Toseland
 */
public class Node implements TimeSkewDetectorCallback, KeyBlockStore, PersistentStatsChecker {

	volatile CHKStore oldCHK;

	volatile PubkeyStore oldPK;

	volatile SSKStore oldSSK;

	volatile CHKStore oldCHKCache;

	volatile PubkeyStore oldPKCache;

	volatile SSKStore oldSSKCache;

	volatile CHKStore oldCHKClientCache;

	volatile PubkeyStore oldPKClientCache;

	volatile SSKStore oldSSKClientCache;

	private <T extends StorableBlock> void migrateOldStore(StoreCallback<T> old, StoreCallback<T> newStore,
			boolean canReadClientCache) {
		FreenetStore<T> store = old.getStore();
		if (store instanceof RAMFreenetStore<T> ramstore) {
			try {
				ramstore.migrateTo(newStore, canReadClientCache);
			}
			catch (IOException ex) {
				Logger.error(this, "Caught migrating old store: " + ex, ex);
			}
			ramstore.clear();
		}
		else if (store instanceof SaltedHashFreenetStore) {
			Logger.error(this, "Migrating from from a saltedhashstore not fully supported yet: will not keep old keys");
		}
	}

	public <T extends StorableBlock> void closeOldStore(StoreCallback<T> old) {
		FreenetStore<T> store = old.getStore();
		if (store instanceof SaltedHashFreenetStore<T> saltstore) {
			saltstore.close();
			saltstore.destruct();
		}
	}

	private static volatile boolean logMINOR;

	private static volatile boolean logDEBUG;

	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback() {
			@Override
			public void shouldUpdate() {
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
				logDEBUG = Logger.shouldLog(LogLevel.DEBUG, this);
			}
		});
	}

	private static MeaningfulNodeNameUserAlert nodeNameUserAlert;

	private static TimeSkewDetectedUserAlert timeSkewDetectedUserAlert;

	/** Encryption key for client.dat.crypt or client.dat.bak.crypt. */
	private DatabaseKey databaseKey;

	/**
	 * Encryption keys, if loaded, null if waiting for a password. We must be able to
	 * write them, and they're all used elsewhere anyway, so there's no point trying not
	 * to keep them in memory.
	 */
	private MasterKeys keys;

	/** Stats. */
	public final NodeStats nodeStats;

	/** Config object for the whole node. */
	public final PersistentConfig config;

	/** Log config handler. */
	public static LoggingConfigHandler logConfigHandler;

	public static final int PACKETS_IN_BLOCK = 32;

	public static final int PACKET_SIZE = 1024;

	public static final double DECREMENT_AT_MIN_PROB = 0.25;

	public static final double DECREMENT_AT_MAX_PROB = 0.5;

	// Send keepalives every 7-14 seconds. Will be acked and if necessary resent.
	// Old behaviour was keepalives every 14-28. Even that was adequate for a 30 second
	// timeout. Most nodes don't need to send keepalives because they are constantly busy,
	// this is only an issue for disabled darknet connections, very quiet private networks
	// etc.
	public static final long KEEPALIVE_INTERVAL = TimeUnit.SECONDS.toMillis(7);

	// If no activity for 30 seconds, node is dead
	// 35 seconds allows plenty of time for resends etc even if above is 14 sec as it is
	// on older nodes.
	public static final long MAX_PEER_INACTIVITY = TimeUnit.SECONDS.toMillis(35);

	/**
	 * Time after which a handshake is assumed to have failed. Keep the below within the
	 * 30 second assumed timeout.
	 */
	public static final int HANDSHAKE_TIMEOUT = (int) TimeUnit.MILLISECONDS.toMillis(4800);

	// Inter-handshake time must be at least 2x handshake timeout
	// 10-20 secs
	public static final int MIN_TIME_BETWEEN_HANDSHAKE_SENDS = HANDSHAKE_TIMEOUT * 2;

	// avoid overlap when the two handshakes are at the same time
	public static final int RANDOMIZED_TIME_BETWEEN_HANDSHAKE_SENDS = HANDSHAKE_TIMEOUT * 2;

	public static final int MIN_TIME_BETWEEN_VERSION_PROBES = HANDSHAKE_TIMEOUT * 4;

	// 20-30 secs
	public static final int RANDOMIZED_TIME_BETWEEN_VERSION_PROBES = HANDSHAKE_TIMEOUT * 2;

	public static final int MIN_TIME_BETWEEN_VERSION_SENDS = HANDSHAKE_TIMEOUT * 4;

	// 20-30 secs
	public static final int RANDOMIZED_TIME_BETWEEN_VERSION_SENDS = HANDSHAKE_TIMEOUT * 2;

	// 2-5 minutes
	public static final int MIN_TIME_BETWEEN_BURSTING_HANDSHAKE_BURSTS = HANDSHAKE_TIMEOUT * 24;

	public static final int RANDOMIZED_TIME_BETWEEN_BURSTING_HANDSHAKE_BURSTS = HANDSHAKE_TIMEOUT * 36;

	// 1-4 handshake sends per burst
	public static final int MIN_BURSTING_HANDSHAKE_BURST_SIZE = 1;

	public static final int RANDOMIZED_BURSTING_HANDSHAKE_BURST_SIZE = 3;

	// If we don't receive any packets at all in this period, from any node, tell the user
	public static final long ALARM_TIME = TimeUnit.MINUTES.toMillis(1);

	static final long MIN_INTERVAL_BETWEEN_INCOMING_SWAP_REQUESTS = TimeUnit.MILLISECONDS.toMillis(900);
	static final long MIN_INTERVAL_BETWEEN_INCOMING_PROBE_REQUESTS = TimeUnit.MILLISECONDS.toMillis(1000);

	// 256 bits - note that this isn't used everywhere to determine it
	public static final int SYMMETRIC_KEY_LENGTH = 32;

	/** Datastore directory */
	private final ProgramDirectory storeDir;

	/** Datastore properties */
	private String storeType;

	private boolean storeUseSlotFilters;

	private boolean storeSaltHashResizeOnStart;

	private int storeSaltHashSlotFilterPersistenceTime;

	/** Minimum total datastore size */
	static final long MIN_STORE_SIZE = 32 * 1024 * 1024;

	/** Default datastore size (must be at least MIN_STORE_SIZE) */
	static final long DEFAULT_STORE_SIZE = 32 * 1024 * 1024;

	/** Minimum client cache size */
	static final long MIN_CLIENT_CACHE_SIZE = 0;

	/** Default client cache size (must be at least MIN_CLIENT_CACHE_SIZE) */
	static final long DEFAULT_CLIENT_CACHE_SIZE = 10 * 1024 * 1024;

	/** Minimum slashdot cache size */
	static final long MIN_SLASHDOT_CACHE_SIZE = 0;

	/** Default slashdot cache size (must be at least MIN_SLASHDOT_CACHE_SIZE) */
	static final long DEFAULT_SLASHDOT_CACHE_SIZE = 10 * 1024 * 1024;

	/**
	 * The number of bytes per key total in all the different datastores. All the
	 * datastores are always the same size in number of keys.
	 */
	public static final int sizePerKey = CHKBlock.DATA_LENGTH + CHKBlock.TOTAL_HEADERS_LENGTH + DSAPublicKey.PADDED_SIZE
			+ SSKBlock.DATA_LENGTH + SSKBlock.TOTAL_HEADERS_LENGTH;

	/**
	 * The maximum number of keys stored in each of the datastores, cache and store
	 * combined.
	 */
	private long maxTotalKeys;

	long maxCacheKeys;

	long maxStoreKeys;

	/**
	 * The maximum size of the datastore. Kept to avoid rounding turning 5G into
	 * 5368698672
	 */
	private long maxTotalDatastoreSize;

	/**
	 * If true, store shrinks occur immediately even if they are over 10% of the store
	 * size. If false, we just set the storeSize and do an offline shrink on the next
	 * startup. Online shrinks do not preserve the most recently used data so are not
	 * recommended.
	 */
	private boolean storeForceBigShrinks;

	private final SemiOrderedShutdownHook shutdownHook;

	/**
	 * The CHK datastore. Long term storage; data should only be inserted here if this
	 * node is the closest location on the chain so far, and it is on an insert (because
	 * inserts will always reach the most specialized node; if we allow requests to store
	 * here, then we get pollution by inserts for keys not close to our specialization).
	 * These conclusions derived from Oskar's simulations.
	 */
	private CHKStore chkDatastore;

	/** The SSK datastore. See description for chkDatastore. */
	private SSKStore sskDatastore;

	/** The store of DSAPublicKeys (by hash). See description for chkDatastore. */
	private PubkeyStore pubKeyDatastore;

	/** Client cache store type */
	private String clientCacheType;

	/**
	 * Client cache could not be opened so is a RAMFS until the correct password is
	 * entered
	 */
	private boolean clientCacheAwaitingPassword;

	private boolean databaseAwaitingPassword;

	/** Client cache maximum cached keys for each type */
	long maxClientCacheKeys;

	/** Maximum size of the client cache. Kept to avoid rounding problems. */
	private long maxTotalClientCacheSize;

	/**
	 * The CHK datacache. Short term cache which stores everything that passes through
	 * this node.
	 */
	private CHKStore chkDatacache;

	/**
	 * The SSK datacache. Short term cache which stores everything that passes through
	 * this node.
	 */
	private SSKStore sskDatacache;

	/**
	 * The public key datacache (by hash). Short term cache which stores everything that
	 * passes through this node.
	 */
	private PubkeyStore pubKeyDatacache;

	/** The CHK client cache. Caches local requests only. */
	private CHKStore chkClientcache;

	/** The SSK client cache. Caches local requests only. */
	private SSKStore sskClientcache;

	/** The pubkey client cache. Caches local requests only. */
	private PubkeyStore pubKeyClientcache;

	// These only cache keys for 30 minutes.

	// FIXME make the first two configurable
	private long maxSlashdotCacheSize;

	private int maxSlashdotCacheKeys;
	static final long PURGE_INTERVAL = TimeUnit.SECONDS.toMillis(60);

	private final CHKStore chkSlashdotcache;

	private final SlashdotStore<CHKBlock> chkSlashdotcacheStore;

	private final SSKStore sskSlashdotcache;

	private final SlashdotStore<SSKBlock> sskSlashdotcacheStore;

	private final PubkeyStore pubKeySlashdotcache;

	private final SlashdotStore<StoreDSAPublicKey> pubKeySlashdotcacheStore;

	/** If false, only ULPRs will use the slashdot cache. If true, everything does. */
	private boolean useSlashdotCache;

	/**
	 * If true, we write stuff to the datastore even though we shouldn't because the HTL
	 * is too high. However it is flagged as old so it won't be included in the Bloom
	 * filter for sharing purposes.
	 */
	private boolean writeLocalToDatastore;

	final NodeGetPubkey getPubKey;

	/** FetchContext for ARKs */
	public final FetchContext arkFetcherContext;

	/** IP detector */
	public final NodeIPDetector ipDetector;

	/**
	 * For debugging/testing, set this to true to stop the probabilistic decrement at the
	 * edges of the HTLs.
	 */
	boolean disableProbabilisticHTLs;

	public final RequestTracker tracker;

	/**
	 * Semi-unique ID for swap requests. Used to identify us so that the topology can be
	 * reconstructed.
	 */
	public long swapIdentifier;

	private String myName;

	public final LocationManager lm;

	/** My peers */
	public final PeerManager peers;

	/** Node-reference directory (node identity, peers, etc) */
	final ProgramDirectory nodeDir;

	/** Config directory (l10n overrides, etc) */
	final ProgramDirectory cfgDir;

	/** User data directory (bookmarks, download lists, etc) */
	final ProgramDirectory userDir;

	/** Run-time state directory (bootID, PRNG seed, etc) */
	final ProgramDirectory runDir;

	/** Plugin directory */
	final ProgramDirectory pluginDir;

	/** File to write crypto master keys into, possibly passworded */
	final File masterKeysFile;

	/** Directory to put extra peer data into */
	final File extraPeerDataDir;

	private volatile boolean hasPanicked;

	/** Strong RNG */
	public final RandomSource random;

	/**
	 * JCA-compliant strong RNG. WARNING: DO NOT CALL THIS ON THE MAIN NETWORK HANDLING
	 * THREADS! In some configurations it can block, potentially forever, on nextBytes()!
	 */
	public final SecureRandom secureRandom;

	/** Weak but fast RNG */
	public final Random fastWeakRandom;

	/** The object which handles incoming messages and allows us to wait for them */
	final MessageCore usm;

	// Darknet stuff

	NodeCrypto darknetCrypto;

	// Back compat
	private boolean showFriendsVisibilityAlert;

	// Opennet stuff

	private final NodeCryptoConfig opennetCryptoConfig;

	OpennetManager opennet;

	private volatile boolean isAllowedToConnectToSeednodes;

	private int maxOpennetPeers;

	private boolean acceptSeedConnections;

	private boolean passOpennetRefsThroughDarknet;

	// General stuff

	public final Executor executor;

	public final PacketSender ps;

	public final PrioritizedTicker ticker;

	final DNSRequester dnsr;

	final NodeDispatcher dispatcher;

	public final UptimeEstimator uptime;

	public final TokenBucket outputThrottle;

	public boolean throttleLocalData;

	private int outputBandwidthLimit;

	private int inputBandwidthLimit;

	private long amountOfDataToCheckCompressionRatio;

	private int minimumCompressionPercentage;

	private int maxTimeForSingleCompressor;

	private boolean connectionSpeedDetection;

	boolean inputLimitDefault;

	final boolean enableARKs;

	final boolean enablePerNodeFailureTables;

	final boolean enableULPRDataPropagation;

	final boolean enableSwapping;

	private volatile boolean publishOurPeersLocation;

	private volatile boolean routeAccordingToOurPeersLocation;

	boolean enableSwapQueueing;

	boolean enablePacketCoalescing;

	public static final short DEFAULT_MAX_HTL = (short) 18;

	private short maxHTL;

	private boolean skipWrapperWarning;

	private int maxPacketSize;

	/** Should inserts ignore low backoff times by default? */
	public static final boolean IGNORE_LOW_BACKOFF_DEFAULT = false;

	/** Definition of "low backoff times" for above. */
	public static final long LOW_BACKOFF = TimeUnit.SECONDS.toMillis(30);

	/** Should inserts be fairly blatently prioritised on accept by default? */
	public static final boolean PREFER_INSERT_DEFAULT = false;

	/** Should inserts fork when the HTL reaches cacheability? */
	public static final boolean FORK_ON_CACHEABLE_DEFAULT = true;

	public final IOStatisticCollector collector;

	/**
	 * Type identifier for fproxy node to node messages, as sent on
	 * DMT.nodeToNodeMessage's
	 */
	public static final int N2N_MESSAGE_TYPE_FPROXY = 1;

	/**
	 * Type identifier for differential node reference messages, as sent on
	 * DMT.nodeToNodeMessage's
	 */
	public static final int N2N_MESSAGE_TYPE_DIFFNODEREF = 2;

	/**
	 * Identifier within fproxy messages for simple, short text messages to be displayed
	 * on the homepage as useralerts
	 */
	public static final int N2N_TEXT_MESSAGE_TYPE_USERALERT = 1;

	/** Identifier within fproxy messages for an offer to transfer a file */
	public static final int N2N_TEXT_MESSAGE_TYPE_FILE_OFFER = 2;

	/** Identifier within fproxy messages for accepting an offer to transfer a file */
	public static final int N2N_TEXT_MESSAGE_TYPE_FILE_OFFER_ACCEPTED = 3;

	/** Identifier within fproxy messages for rejecting an offer to transfer a file */
	public static final int N2N_TEXT_MESSAGE_TYPE_FILE_OFFER_REJECTED = 4;

	/** Identified within friend feed for the recommendation of a bookmark */
	public static final int N2N_TEXT_MESSAGE_TYPE_BOOKMARK = 5;

	/** Identified within friend feed for the recommendation of a file */
	public static final int N2N_TEXT_MESSAGE_TYPE_DOWNLOAD = 6;

	public static final int EXTRA_PEER_DATA_TYPE_N2NTM = 1;

	public static final int EXTRA_PEER_DATA_TYPE_PEER_NOTE = 2;

	public static final int EXTRA_PEER_DATA_TYPE_QUEUED_TO_SEND_N2NM = 3;

	public static final int EXTRA_PEER_DATA_TYPE_BOOKMARK = 4;

	public static final int EXTRA_PEER_DATA_TYPE_DOWNLOAD = 5;

	public static final int PEER_NOTE_TYPE_PRIVATE_DARKNET_COMMENT = 1;

	/**
	 * The bootID of the last time the node booted up. Or -1 if we don't know due to
	 * permissions problems, or we suspect that the node has been booted and not written
	 * the file e.g. if we can't write it. So if we want to compare data gathered in the
	 * last session and only recorded to disk on a clean shutdown to data we have now, we
	 * just include the lastBootID.
	 */
	public final long lastBootID;

	public final long bootID;

	public final long startupTime;

	public final NodeClientCore clientCore;

	// ULPRs, RecentlyFailed, per node failure tables, are all managed by FailureTable.
	final FailureTable failureTable;

	// The version we were before we restarted.
	public int lastVersion;

	/** NodeUpdater **/
	public final NodeUpdateManager nodeUpdater;

	public final SecurityLevels securityLevels;

	/** Diagnostics */
	private final DefaultNodeDiagnostics nodeDiagnostics;

	// Things that's needed to keep track of
	public final PluginManager pluginManager;

	// Helpers
	public final InetAddress localhostAddress;

	public final FreenetInetAddress fLocalhostAddress;

	// The node starter
	private static NodeStarter nodeStarter;

	// The watchdog will be silenced until it's true
	private boolean hasStarted;

	private boolean isStopping = false;

	/**
	 * Minimum uptime for us to consider a node an acceptable place to store a key. We
	 * store a key to the datastore only if it's from an insert, and we are a sink, but
	 * when calculating whether we are a sink we ignore nodes which have less uptime
	 * (percentage) than this parameter.
	 */
	static final int MIN_UPTIME_STORE_KEY = 40;

	private final boolean isPRNGReady;

	private boolean storePreallocate;

	private boolean enableRoutedPing;

	private boolean enableNodeDiagnostics;

	private boolean peersOffersDismissed;

	/**
	 * Minimum bandwidth limit in bytes considered usable: 10 KiB. If there is an attempt
	 * to set a limit below this - excluding the reserved -1 for input bandwidth - the
	 * callback will throw. See the callbacks for outputBandwidthLimit and
	 * inputBandwidthLimit. 10 KiB are equivalent to 50 GiB traffic per month.
	 */
	private static final int minimumBandwidth = 10 * 1024;

	/** Quality of Service mark we will use for all outgoing packets (opennet/darknet) */
	private TrafficClass trafficClass;

	public TrafficClass getTrafficClass() {
		return this.trafficClass;
	}

	/*
	 * Gets minimum bandwidth in bytes considered usable.
	 *
	 * @see #minimumBandwidth
	 */
	public static int getMinimumBandwidth() {
		return Node.minimumBandwidth;
	}

	/**
	 * Dispatches a probe request with the specified settings
	 * @see Probe#start(byte, long, Type, Listener)
	 */
	public void startProbe(final byte htl, final long uid, final Type type, final Listener listener) {
		this.dispatcher.probe.start(htl, uid, type, listener);
	}

	/**
	 * Read all storable settings (identity etc) from the node file.
	 * @param filename the name of the file to read from.
	 * @throws IOException throw when I/O error occur
	 */
	private void readNodeFile(String filename) throws IOException {
		// REDFLAG: Any way to share this code with NodePeer?
		FileInputStream fis = new FileInputStream(filename);
		InputStreamReader isr = new InputStreamReader(fis, StandardCharsets.UTF_8);
		BufferedReader br = new BufferedReader(isr);
		SimpleFieldSet fs = new SimpleFieldSet(br, false, true);
		br.close();
		// Read contents
		String[] udp = fs.getAll("physical.udp");
		if ((udp != null) && (udp.length > 0)) {
			for (String udpAddr : udp) {
				// Just keep the first one with the correct port number.
				Peer p;
				try {
					p = new Peer(udpAddr, false, true);
				}
				catch (HostnameSyntaxException ex) {
					Logger.error(this,
							"Invalid hostname or IP Address syntax error while parsing our darknet node reference: "
									+ udpAddr);
					System.err.println(
							"Invalid hostname or IP Address syntax error while parsing our darknet node reference: "
									+ udpAddr);
					continue;
				}
				catch (PeerParseException ex) {
					throw new IOException(ex);
				}
				if (p.getPort() == this.getDarknetPortNumber()) {
					// DNSRequester doesn't deal with our own node
					this.ipDetector.setOldIPAddress(p.getFreenetAddress());
					break;
				}
			}
		}

		this.darknetCrypto.readCrypto(fs);

		this.swapIdentifier = Fields.bytesToLong(this.darknetCrypto.identityHashHash);
		String loc = fs.get("location");
		double locD = Location.getLocation(loc);
		if (locD == -1.0) {
			throw new IOException("Invalid location: " + loc);
		}
		this.lm.setLocation(locD);
		this.myName = fs.get("myName");
		if (this.myName == null) {
			this.myName = this.newName();
		}

		String verString = fs.get("version");
		if (verString == null) {
			Logger.error(this, "No version!");
			System.err.println("No version!");
		}
		else {
			this.lastVersion = Version.getArbitraryBuildNumber(verString, -1);
		}
	}

	public void makeStore(String val) throws InvalidConfigValueException {
		String suffix = this.getStoreSuffix();
		if (val.equals("salt-hash")) {
			try {
				this.initSaltHashFS(suffix, true, null);
			}
			catch (NodeInitException ex) {
				Logger.error(this, "Unable to create new store", ex);
				System.err.println("Unable to create new store: " + ex);
				ex.printStackTrace();
				// FIXME l10n both on the NodeInitException and the wrapper message
				throw new InvalidConfigValueException("Unable to create new store: " + ex);
			}
		}
		else {
			this.initRAMFS();
		}

		synchronized (Node.this) {
			this.storeType = val;
		}
	}

	private String newName() {
		return "Freenet node with no name #" + this.random.nextLong();
	}

	private final Object writeNodeFileSync = new Object();

	public void writeNodeFile() {
		synchronized (this.writeNodeFileSync) {
			this.writeNodeFile(this.nodeDir.file("node-" + this.getDarknetPortNumber()),
					this.nodeDir.file("node-" + this.getDarknetPortNumber() + ".bak"));
		}
	}

	public void writeOpennetFile() {
		OpennetManager om = this.opennet;
		if (om != null) {
			om.writeFile();
		}
	}

	private void writeNodeFile(File orig, File backup) {
		SimpleFieldSet fs = this.darknetCrypto.exportPrivateFieldSet();

		if (orig.exists()) {
			backup.delete();
		}

		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(backup);
			fs.writeTo(fos);
			fos.close();
			fos = null;
			FileUtil.renameTo(backup, orig);
		}
		catch (IOException ioe) {
			Logger.error(this, "IOE :" + ioe.getMessage(), ioe);
		}
		finally {
			Closer.close(fos);
		}
	}

	private void initNodeFileSettings() {
		Logger.normal(this, "Creating new node file from scratch");
		// Don't need to set getDarknetPortNumber()
		// FIXME use a real IP!
		this.darknetCrypto.initCrypto();
		this.swapIdentifier = Fields.bytesToLong(this.darknetCrypto.identityHashHash);
		this.myName = this.newName();
	}

	/**
	 * Read the config file from the arguments. Then create a node. Anything that needs
	 * static init should ideally be in here.
	 * @param args command line arguments.
	 */
	public static void main(String[] args) throws IOException {
		NodeStarter.main(args);
	}

	public boolean isUsingWrapper() {
		return nodeStarter != null && WrapperManager.isControlledByNativeWrapper();
	}

	public NodeStarter getNodeStarter() {
		return nodeStarter;
	}

	/**
	 * Create a Node from a Config object.
	 * @param config The Config object for this node.
	 * @param r The random number generator for this node. Passed in because we may want
	 * to use a non-secure RNG for e.g. one-JVM live-code simulations. Should be a Yarrow
	 * in a production node. Yarrow will be used if that parameter is null
	 * @param weakRandom The fast random number generator the node will use. If null a MT
	 * instance will be used, seeded from the secure PRNG.
	 * @param lc logging config Handler
	 * @param ns NodeStarter
	 * @param executor Executor
	 * @throws NodeInitException If the node initialization fails.
	 */
	Node(PersistentConfig config, RandomSource r, RandomSource weakRandom, LoggingConfigHandler lc, NodeStarter ns,
			Executor executor) throws NodeInitException {
		this.shutdownHook = SemiOrderedShutdownHook.get();
		// Easy stuff
		String tmp = "Initializing Node using Freenet Build #" + Version.buildNumber() + " r" + Version.cvsRevision()
				+ " and freenet-ext Build #" + NodeStarter.extBuildNumber + " r" + NodeStarter.extRevisionNumber
				+ " with " + System.getProperty("java.vendor") + " JVM version " + System.getProperty("java.version")
				+ " running on " + System.getProperty("os.arch") + ' ' + System.getProperty("os.name") + ' '
				+ System.getProperty("os.version");
		this.fixCertsFiles();
		Logger.normal(this, tmp);
		System.out.println(tmp);
		this.collector = new IOStatisticCollector();
		this.executor = executor;
		nodeStarter = ns;
		if (logConfigHandler != lc) {
			logConfigHandler = lc;
		}
		this.getPubKey = new NodeGetPubkey(this);
		this.startupTime = System.currentTimeMillis();
		SimpleFieldSet oldConfig = config.getSimpleFieldSet();
		// Setup node-specific configuration
		final SubConfig nodeConfig = config.createSubConfig("node");
		final SubConfig installConfig = config.createSubConfig("node.install");

		int sortOrder = 0;

		// Default userDir is the dir where freenet.ini locates
		String defaultUserDir;
		if (config instanceof FilePersistentConfig filePersistentConfig) {
			defaultUserDir = filePersistentConfig.getConfigFile().getParent();
		}
		else {
			defaultUserDir = ".";
		}

		// Directory for node-related files other than store
		this.userDir = this.setupProgramDir(installConfig, "userDir", defaultUserDir, "Node.userDir",
				"Node.userDirLong", nodeConfig);
		this.cfgDir = this.setupProgramDir(installConfig, "cfgDir", this.getUserDir().toString(), "Node.cfgDir",
				"Node.cfgDirLong", nodeConfig);
		this.nodeDir = this.setupProgramDir(installConfig, "nodeDir", this.getUserDir().toString(), "Node.nodeDir",
				"Node.nodeDirLong", nodeConfig);
		this.runDir = this.setupProgramDir(installConfig, "runDir", this.getUserDir().toString(), "Node.runDir",
				"Node.runDirLong", nodeConfig);
		this.pluginDir = this.setupProgramDir(installConfig, "pluginDir", this.userDir().file("plugins").toString(),
				"Node.pluginDir", "Node.pluginDirLong", nodeConfig);

		// l10n stuffs
		nodeConfig.register("l10n", Locale.getDefault().getLanguage().toLowerCase(), sortOrder++, false, true,
				"Node.l10nLanguage", "Node.l10nLanguageLong", new L10nCallback());

		try {
			new NodeL10n(BaseL10n.LANGUAGE.mapToLanguage(nodeConfig.getString("l10n")), this.getCfgDir());
		}
		catch (MissingResourceException ex) {
			try {
				new NodeL10n(BaseL10n.LANGUAGE.mapToLanguage(nodeConfig.getOption("l10n").getDefault()),
						this.getCfgDir());
			}
			catch (MissingResourceException e1) {
				new NodeL10n(BaseL10n.LANGUAGE.mapToLanguage(BaseL10n.LANGUAGE.getDefault().shortCode),
						this.getCfgDir());
			}
		}

		// FProxy config needs to be here too
		SubConfig fproxyConfig = config.createSubConfig("fproxy");
		SimpleToadletServer toadlets;
		try {
			toadlets = new SimpleToadletServer(fproxyConfig, new ArrayBucketFactory(), executor, this);
			fproxyConfig.finishedInitialization();
			toadlets.start();
		}
		catch (IOException e4) {
			Logger.error(this, "Could not start web interface: " + e4, e4);
			System.err.println("Could not start web interface: " + e4);
			e4.printStackTrace();
			throw new NodeInitException(NodeInitException.EXIT_COULD_NOT_START_FPROXY, "Could not start FProxy: " + e4);
		}
		catch (InvalidConfigValueException e4) {
			System.err.println("Invalid config value, cannot start web interface: " + e4);
			e4.printStackTrace();
			throw new NodeInitException(NodeInitException.EXIT_COULD_NOT_START_FPROXY, "Could not start FProxy: " + e4);
		}

		final NativeThread entropyGatheringThread = new NativeThread(new Runnable() {

			long tLastAdded = -1;

			private void recurse(File f) {
				if (Node.this.isPRNGReady) {
					return;
				}
				this.extendTimeouts();
				File[] subDirs = f
						.listFiles((pathname) -> pathname.exists() && pathname.canRead() && pathname.isDirectory());

				// @see http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=5086412
				if (subDirs != null) {
					for (File currentDir : subDirs) {
						this.recurse(currentDir);
					}
				}
			}

			@Override
			public void run() {
				try {
					// Delay entropy generation helper hack if enough entropy available
					Thread.sleep(100);
				}
				catch (InterruptedException ignored) {
				}
				if (Node.this.isPRNGReady) {
					return;
				}
				System.out.println("Not enough entropy available.");
				System.out.println("Trying to gather entropy (randomness) by reading the disk...");
				if (File.separatorChar == '/') {
					if (new File("/dev/hwrng").exists()) {
						System.out.println("/dev/hwrng exists - have you installed rng-tools?");
					}
					else {
						System.out.println(
								"You should consider installing a better random number generator e.g. haveged.");
					}
				}
				this.extendTimeouts();
				for (File root : File.listRoots()) {
					if (Node.this.isPRNGReady) {
						return;
					}
					this.recurse(root);
				}
			}

			/**
			 * This is ridiculous, but for some users it can take more than an hour, and
			 * timing out sucks a few bytes and then times out again. :(
			 */
			static final int EXTEND_BY = 60 * 60 * 1000;

			private void extendTimeouts() {
				long now = System.currentTimeMillis();
				if (now - this.tLastAdded < EXTEND_BY / 2) {
					return;
				}
				long target = this.tLastAdded + EXTEND_BY;
				while (target < now) {
					target += EXTEND_BY;
				}
				long extend = target - now;
				assert (extend < Integer.MAX_VALUE);
				assert (extend > 0);
				WrapperManager.signalStarting((int) extend);
				this.tLastAdded = now;
			}

		}, "Entropy Gathering Thread", NativeThread.MIN_PRIORITY, true);

		// Setup RNG if needed : DO NOT USE IT BEFORE THAT POINT!
		if (r == null) {
			// Preload required freenet.crypt.Util and freenet.crypt.Rijndael classes
			// (selftest can delay Yarrow startup and trigger false lack-of-enthropy
			// message)
			// freenet.crypt.Util.mdProviders.size();
			freenet.crypt.ciphers.Rijndael.getProviderName();

			File seed = this.userDir.file("prng.seed");
			FileUtil.setOwnerRW(seed);
			entropyGatheringThread.start();
			// Can block.
			this.random = new Yarrow(seed);
			// http://bugs.sun.com/view_bug.do;jsessionid=ff625daf459fdffffffffcd54f1c775299e0?bug_id=4705093
			// This might block on /dev/random while doing new SecureRandom(). Once it's
			// created, it won't block.
			ECDH.blockingInit();
		}
		else {
			this.random = r;
			// if it's not null it's because we are running in the simulator
		}
		// This can block too.
		this.secureRandom = NodeStarter.getGlobalSecureRandom();
		this.isPRNGReady = true;
		toadlets.getStartupToadlet().setIsPRNGReady();
		if (weakRandom == null) {
			byte[] buffer = new byte[16];
			this.random.nextBytes(buffer);
			this.fastWeakRandom = new MersenneTwister(buffer);
		}
		else {
			this.fastWeakRandom = weakRandom;
		}

		nodeNameUserAlert = new MeaningfulNodeNameUserAlert(this);
		this.config = config;
		this.lm = new LocationManager(this.random, this);

		try {
			this.localhostAddress = InetAddress.getByName("127.0.0.1");
		}
		catch (UnknownHostException e3) {
			// Does not do a reverse lookup, so this is impossible
			throw new Error(e3);
		}
		this.fLocalhostAddress = new FreenetInetAddress(this.localhostAddress);

		this.securityLevels = new SecurityLevels(this, config);

		// Location of master key
		nodeConfig.register("masterKeyFile", this.userDir().file("master.keys").toString(), sortOrder++, true, true,
				"Node.masterKeyFile", "Node.masterKeyFileLong", new StringCallback() {

					@Override
					public String get() {
						if (Node.this.masterKeysFile == null) {
							return "none";
						}
						else {
							return Node.this.masterKeysFile.getPath();
						}
					}

					@Override
					public void set(String val) throws InvalidConfigValueException {
						// FIXME l10n
						// FIXME wipe the old one and move
						throw new InvalidConfigValueException(
								"Node.masterKeyFile cannot be changed on the fly, you must shutdown, wipe the old file and reconfigure");
					}

				});

		String value = nodeConfig.getString("masterKeyFile");
		File f;
		if (value.equalsIgnoreCase("none")) {
			f = null;
		}
		else {
			f = new File(value);

			if (f.exists() && !(f.canWrite() && f.canRead())) {
				throw new NodeInitException(NodeInitException.EXIT_CANT_WRITE_MASTER_KEYS,
						"Cannot read from and write to master keys file " + f);
			}
		}
		this.masterKeysFile = f;
		FileUtil.setOwnerRW(this.masterKeysFile);

		nodeConfig.register("showFriendsVisibilityAlert", false, sortOrder++, true, false,
				"Node.showFriendsVisibilityAlert", "Node.showFriendsVisibilityAlert", new BooleanCallback() {

					@Override
					public Boolean get() {
						synchronized (Node.this) {
							return Node.this.showFriendsVisibilityAlert;
						}
					}

					@Override
					public void set(Boolean val) {
						synchronized (this) {
							if (val == Node.this.showFriendsVisibilityAlert) {
								return;
							}
							if (val) {
								return;
							}
						}
						Node.this.unregisterFriendsVisibilityAlert();
					}

				});

		this.showFriendsVisibilityAlert = nodeConfig.getBoolean("showFriendsVisibilityAlert");

		byte[] clientCacheKey = null;

		MasterSecret persistentSecret = null;
		for (int i = 0; i < 2; i++) {

			try {
				if (this.securityLevels.physicalThreatLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM) {
					this.keys = MasterKeys.createRandom(this.secureRandom);
				}
				else {
					this.keys = MasterKeys.read(this.masterKeysFile, this.secureRandom, "");
				}
				clientCacheKey = this.keys.clientCacheMasterKey;
				persistentSecret = this.keys.getPersistentMasterSecret();
				this.databaseKey = this.keys.createDatabaseKey(this.secureRandom);
				if (this.securityLevels.getPhysicalThreatLevel() == PHYSICAL_THREAT_LEVEL.HIGH) {
					System.err.println(
							"Physical threat level is set to HIGH but no password, resetting to NORMAL - probably timing glitch");
					this.securityLevels.resetPhysicalThreatLevel(PHYSICAL_THREAT_LEVEL.NORMAL);
				}
				break;
			}
			catch (MasterKeysWrongPasswordException | IOException ignored) {
				break;
			}
			catch (MasterKeysFileSizeException ex) {
				System.err.println("Impossible: master keys file " + this.masterKeysFile + " too " + ex.sizeToString()
						+ "! Deleting to enable startup, but you will lose your client cache.");
				this.masterKeysFile.delete();
			}
		}

		// Boot ID
		this.bootID = this.random.nextLong();
		// Fixed length file containing boot ID. Accessed with random access file. So
		// hopefully it will always be
		// written. Note that we set lastBootID to -1 if we can't _write_ our ID as well
		// as if we can't read it,
		// because if we can't write it then we probably couldn't write it on the last
		// bootup either.
		File bootIDFile = this.runDir.file("bootID");
		int BOOT_FILE_LENGTH = 64 / 4; // A long in padded hex bytes
		long oldBootID = -1;
		RandomAccessFile raf = null;
		try {
			raf = new RandomAccessFile(bootIDFile, "rw");
			if (raf.length() >= BOOT_FILE_LENGTH) {
				byte[] buf = new byte[BOOT_FILE_LENGTH];
				raf.readFully(buf);
				String s = new String(buf, StandardCharsets.ISO_8859_1);
				try {
					oldBootID = Fields.bytesToLong(HexUtil.hexToBytes(s));
				}
				catch (NumberFormatException ignored) {
				}
				raf.seek(0);
			}
			String s = HexUtil.bytesToHex(Fields.longToBytes(this.bootID));
			byte[] buf = s.getBytes(StandardCharsets.ISO_8859_1);
			if (buf.length != BOOT_FILE_LENGTH) {
				System.err.println("Not 16 bytes for boot ID " + this.bootID + " - WTF??");
			}
			raf.write(buf);
		}
		catch (IOException ignored) {
			oldBootID = -1;
			// If we have an error in reading, *or in writing*, we don't reliably know the
			// last boot ID.
		}
		finally {
			Closer.close(raf);
		}
		this.lastBootID = oldBootID;

		nodeConfig.register("disableProbabilisticHTLs", false, sortOrder++, true, false, "Node.disablePHTLS",
				"Node.disablePHTLSLong", new BooleanCallback() {

					@Override
					public Boolean get() {
						return Node.this.disableProbabilisticHTLs;
					}

					@Override
					public void set(Boolean val) {
						Node.this.disableProbabilisticHTLs = val;
					}

				});

		this.disableProbabilisticHTLs = nodeConfig.getBoolean("disableProbabilisticHTLs");

		nodeConfig.register("maxHTL", DEFAULT_MAX_HTL, sortOrder++, true, false, "Node.maxHTL", "Node.maxHTLLong",
				new ShortCallback() {

					@Override
					public Short get() {
						return Node.this.maxHTL;
					}

					@Override
					public void set(Short val) throws InvalidConfigValueException {
						if (val < 0) {
							throw new InvalidConfigValueException("Impossible max HTL");
						}
						Node.this.maxHTL = val;
					}
				}, false);

		this.maxHTL = nodeConfig.getShort("maxHTL");

		class TrafficClassCallback extends StringCallback implements EnumerableOptionCallback {

			@Override
			public String get() {
				return Node.this.trafficClass.name();
			}

			@Override
			public void set(String tcName) throws InvalidConfigValueException, NodeNeedRestartException {
				try {
					Node.this.trafficClass = TrafficClass.fromNameOrValue(tcName);
				}
				catch (IllegalArgumentException ex) {
					throw new InvalidConfigValueException(ex);
				}
				throw new NodeNeedRestartException("TrafficClass cannot change on the fly");
			}

			@Override
			public String[] getPossibleValues() {
				ArrayList<String> array = new ArrayList<>();
				for (TrafficClass tc : TrafficClass.values()) {
					array.add(tc.name());
				}
				return array.toArray(new String[0]);
			}

		}

		nodeConfig.register("trafficClass", TrafficClass.getDefault().name(), sortOrder++, true, false,
				"Node.trafficClass", "Node.trafficClassLong", new TrafficClassCallback());
		String trafficClassValue = nodeConfig.getString("trafficClass");
		try {
			this.trafficClass = TrafficClass.fromNameOrValue(trafficClassValue);
		}
		catch (IllegalArgumentException ex) {
			Logger.error(this, "Invalid trafficClass:" + trafficClassValue + " resetting the value to default.", ex);
			this.trafficClass = TrafficClass.getDefault();
		}

		// FIXME maybe these should persist? They need to be private.
		this.decrementAtMax = this.random.nextDouble() <= DECREMENT_AT_MAX_PROB;
		this.decrementAtMin = this.random.nextDouble() <= DECREMENT_AT_MIN_PROB;

		// Determine where to bind to

		this.usm = new MessageCore(executor);

		// FIXME maybe these configs should actually be under a node.ip subconfig?
		this.ipDetector = new NodeIPDetector(this);
		sortOrder = this.ipDetector.registerConfigs(nodeConfig, sortOrder);

		// ARKs enabled?

		nodeConfig.register("enableARKs", true, sortOrder++, true, false, "Node.enableARKs", "Node.enableARKsLong",
				new BooleanCallback() {

					@Override
					public Boolean get() {
						return Node.this.enableARKs;
					}

					@Override
					public void set(Boolean val) throws InvalidConfigValueException {
						throw new InvalidConfigValueException("Cannot change on the fly");
					}

					@Override
					public boolean isReadOnly() {
						return true;
					}
				});
		this.enableARKs = nodeConfig.getBoolean("enableARKs");

		nodeConfig.register("enablePerNodeFailureTables", true, sortOrder++, true, false,
				"Node.enablePerNodeFailureTables", "Node.enablePerNodeFailureTablesLong", new BooleanCallback() {

					@Override
					public Boolean get() {
						return Node.this.enablePerNodeFailureTables;
					}

					@Override
					public void set(Boolean val) throws InvalidConfigValueException {
						throw new InvalidConfigValueException("Cannot change on the fly");
					}

					@Override
					public boolean isReadOnly() {
						return true;
					}
				});
		this.enablePerNodeFailureTables = nodeConfig.getBoolean("enablePerNodeFailureTables");

		nodeConfig.register("enableULPRDataPropagation", true, sortOrder++, true, false,
				"Node.enableULPRDataPropagation", "Node.enableULPRDataPropagationLong", new BooleanCallback() {

					@Override
					public Boolean get() {
						return Node.this.enableULPRDataPropagation;
					}

					@Override
					public void set(Boolean val) throws InvalidConfigValueException {
						throw new InvalidConfigValueException("Cannot change on the fly");
					}

					@Override
					public boolean isReadOnly() {
						return true;
					}
				});
		this.enableULPRDataPropagation = nodeConfig.getBoolean("enableULPRDataPropagation");

		nodeConfig.register("enableSwapping", true, sortOrder++, true, false, "Node.enableSwapping",
				"Node.enableSwappingLong", new BooleanCallback() {

					@Override
					public Boolean get() {
						return Node.this.enableSwapping;
					}

					@Override
					public void set(Boolean val) throws InvalidConfigValueException {
						throw new InvalidConfigValueException("Cannot change on the fly");
					}

					@Override
					public boolean isReadOnly() {
						return true;
					}
				});
		this.enableSwapping = nodeConfig.getBoolean("enableSwapping");

		/*
		 * Publish our peers' locations is enabled, even in MAXIMUM network security
		 * and/or HIGH friends security, because a node which doesn't publish its peers'
		 * locations will get dramatically less traffic.
		 *
		 * Publishing our peers' locations does make us slightly more vulnerable to some
		 * attacks, but I don't think it's a big difference: swapping reveals the same
		 * information, it just doesn't update as quickly. This may help slightly, but
		 * probably not dramatically against a clever attacker.
		 *
		 * FIXME review this decision.
		 */
		nodeConfig.register("publishOurPeersLocation", true, sortOrder++, true, false, "Node.publishOurPeersLocation",
				"Node.publishOurPeersLocationLong", new BooleanCallback() {

					@Override
					public Boolean get() {
						return Node.this.publishOurPeersLocation;
					}

					@Override
					public void set(Boolean val) {
						Node.this.publishOurPeersLocation = val;
					}
				});
		this.publishOurPeersLocation = nodeConfig.getBoolean("publishOurPeersLocation");

		nodeConfig.register("routeAccordingToOurPeersLocation", true, sortOrder++, true, false,
				"Node.routeAccordingToOurPeersLocation", "Node.routeAccordingToOurPeersLocation",
				new BooleanCallback() {

					@Override
					public Boolean get() {
						return Node.this.routeAccordingToOurPeersLocation;
					}

					@Override
					public void set(Boolean val) {
						Node.this.routeAccordingToOurPeersLocation = val;
					}
				});
		this.routeAccordingToOurPeersLocation = nodeConfig.getBoolean("routeAccordingToOurPeersLocation");

		nodeConfig.register("enableSwapQueueing", true, sortOrder++, true, false, "Node.enableSwapQueueing",
				"Node.enableSwapQueueingLong", new BooleanCallback() {
					@Override
					public Boolean get() {
						return Node.this.enableSwapQueueing;
					}

					@Override
					public void set(Boolean val) {
						Node.this.enableSwapQueueing = val;
					}

				});
		this.enableSwapQueueing = nodeConfig.getBoolean("enableSwapQueueing");

		nodeConfig.register("enablePacketCoalescing", true, sortOrder++, true, false, "Node.enablePacketCoalescing",
				"Node.enablePacketCoalescingLong", new BooleanCallback() {
					@Override
					public Boolean get() {
						return Node.this.enablePacketCoalescing;
					}

					@Override
					public void set(Boolean val) {
						Node.this.enablePacketCoalescing = val;
					}

				});
		this.enablePacketCoalescing = nodeConfig.getBoolean("enablePacketCoalescing");

		// Determine the port number
		// @see #191
		if (oldConfig != null && "-1".equals(oldConfig.get("node.listenPort"))) {
			throw new NodeInitException(NodeInitException.EXIT_COULD_NOT_BIND_USM,
					"Your freenet.ini file is corrupted! 'listenPort=-1'");
		}
		NodeCryptoConfig darknetConfig = new NodeCryptoConfig(nodeConfig, sortOrder++, false, this.securityLevels);
		sortOrder += NodeCryptoConfig.OPTION_COUNT;

		this.darknetCrypto = new NodeCrypto(this, false, darknetConfig, this.startupTime, this.enableARKs);

		// Must be created after darknetCrypto
		this.dnsr = new DNSRequester(this);
		this.ps = new PacketSender(this);
		this.ticker = new PrioritizedTicker(executor, this.getDarknetPortNumber());
		if (executor instanceof PooledExecutor) {
			((PooledExecutor) executor).setTicker(this.ticker);
		}

		Logger.normal(Node.class, "Creating node...");

		this.shutdownHook.addEarlyJob(new Thread(() -> {
			if (Node.this.opennet != null) {
				Node.this.opennet.stop(false);
			}
		}));

		this.shutdownHook.addEarlyJob(new Thread(() -> Node.this.darknetCrypto.stop()));

		// Bandwidth limit

		nodeConfig.register("outputBandwidthLimit", "15K", sortOrder++, false, true, "Node.outBWLimit",
				"Node.outBWLimitLong", new IntCallback() {
					@Override
					public Integer get() {
						// return BlockTransmitter.getHardBandwidthLimit();
						return Node.this.outputBandwidthLimit;
					}

					@Override
					public void set(Integer obwLimit) throws InvalidConfigValueException {
						BandwidthManager.checkOutputBandwidthLimit(obwLimit);
						try {
							Node.this.outputThrottle.changeNanosAndBucketSize(TimeUnit.SECONDS.toNanos(1) / obwLimit,
									obwLimit / 2);
						}
						catch (IllegalArgumentException ex) {
							throw new InvalidConfigValueException(ex);
						}
						synchronized (Node.this) {
							Node.this.outputBandwidthLimit = obwLimit;
						}
					}
				});

		int obwLimit = nodeConfig.getInt("outputBandwidthLimit");
		if (obwLimit < minimumBandwidth) {
			obwLimit = minimumBandwidth; // upgrade slow nodes automatically
			Logger.normal(Node.class,
					"Output bandwidth was lower than minimum bandwidth. Increased to minimum bandwidth.");
		}

		this.outputBandwidthLimit = obwLimit;
		try {
			BandwidthManager.checkOutputBandwidthLimit(this.outputBandwidthLimit);
		}
		catch (InvalidConfigValueException ex) {
			throw new NodeInitException(NodeInitException.EXIT_BAD_BWLIMIT, ex.getMessage());
		}

		// Bucket size of 0.5 seconds' worth of bytes.
		// Add them at a rate determined by the obwLimit.
		// Maximum forced bytes 80%, in other words, 20% of the bandwidth is reserved for
		// block transfers, so we will use that 20% for block transfers even if more than
		// 80% of the limit is used for non-limited data (resends etc).
		int bucketSize = obwLimit / 2;
		// Must have at least space for ONE PACKET.
		// FIXME: make compatible with alternate transports.
		bucketSize = Math.max(bucketSize, 2048);
		try {
			this.outputThrottle = new TokenBucket(bucketSize, TimeUnit.SECONDS.toNanos(1) / obwLimit, obwLimit / 2);
		}
		catch (IllegalArgumentException ex) {
			throw new NodeInitException(NodeInitException.EXIT_BAD_BWLIMIT, ex.getMessage());
		}

		nodeConfig.register("inputBandwidthLimit", "-1", sortOrder++, false, true, "Node.inBWLimit",
				"Node.inBWLimitLong", new IntCallback() {
					@Override
					public Integer get() {
						if (Node.this.inputLimitDefault) {
							return -1;
						}
						return Node.this.inputBandwidthLimit;
					}

					@Override
					public void set(Integer ibwLimit) throws InvalidConfigValueException {
						synchronized (Node.this) {
							BandwidthManager.checkInputBandwidthLimit(ibwLimit);

							if (ibwLimit == -1) {
								Node.this.inputLimitDefault = true;
								ibwLimit = Node.this.outputBandwidthLimit * 4;
							}
							else {
								Node.this.inputLimitDefault = false;
							}

							Node.this.inputBandwidthLimit = ibwLimit;
						}
					}
				});

		int ibwLimit = nodeConfig.getInt("inputBandwidthLimit");
		if (ibwLimit == -1) {
			this.inputLimitDefault = true;
			ibwLimit = obwLimit * 4;
		}
		else if (ibwLimit < minimumBandwidth) {
			ibwLimit = minimumBandwidth; // upgrade slow nodes automatically
			Logger.normal(Node.class,
					"Input bandwidth was lower than minimum bandwidth. Increased to minimum bandwidth.");
		}
		this.inputBandwidthLimit = ibwLimit;
		try {
			BandwidthManager.checkInputBandwidthLimit(this.inputBandwidthLimit);
		}
		catch (InvalidConfigValueException ex) {
			throw new NodeInitException(NodeInitException.EXIT_BAD_BWLIMIT, ex.getMessage());
		}

		nodeConfig.register("amountOfDataToCheckCompressionRatio", "8MiB", sortOrder++, true, true,
				"Node.amountOfDataToCheckCompressionRatio", "Node.amountOfDataToCheckCompressionRatioLong",
				new LongCallback() {
					@Override
					public Long get() {
						return Node.this.amountOfDataToCheckCompressionRatio;
					}

					@Override
					public void set(Long amountOfDataToCheckCompressionRatio) {
						synchronized (Node.this) {
							Node.this.amountOfDataToCheckCompressionRatio = amountOfDataToCheckCompressionRatio;
						}
					}
				}, true);

		this.amountOfDataToCheckCompressionRatio = nodeConfig.getLong("amountOfDataToCheckCompressionRatio");

		nodeConfig.register("minimumCompressionPercentage", "10", sortOrder++, true, true,
				"Node.minimumCompressionPercentage", "Node.minimumCompressionPercentageLong", new IntCallback() {
					@Override
					public Integer get() {
						return Node.this.minimumCompressionPercentage;
					}

					@Override
					public void set(Integer minimumCompressionPercentage) {
						synchronized (Node.this) {
							if (minimumCompressionPercentage < 0 || minimumCompressionPercentage > 100) {
								Logger.normal(Node.class,
										"Wrong minimum compression percentage" + minimumCompressionPercentage);
								return;
							}

							Node.this.minimumCompressionPercentage = minimumCompressionPercentage;
						}
					}
				}, Dimension.NOT);

		this.minimumCompressionPercentage = nodeConfig.getInt("minimumCompressionPercentage");

		nodeConfig.register("maxTimeForSingleCompressor", "20m", sortOrder++, true, true,
				"Node.maxTimeForSingleCompressor", "Node.maxTimeForSingleCompressorLong", new IntCallback() {
					@Override
					public Integer get() {
						return Node.this.maxTimeForSingleCompressor;
					}

					@Override
					public void set(Integer maxTimeForSingleCompressor) {
						synchronized (Node.this) {
							Node.this.maxTimeForSingleCompressor = maxTimeForSingleCompressor;
						}
					}
				}, Dimension.DURATION);

		this.maxTimeForSingleCompressor = nodeConfig.getInt("maxTimeForSingleCompressor");

		nodeConfig.register("connectionSpeedDetection", true, sortOrder++, true, true, "Node.connectionSpeedDetection",
				"Node.connectionSpeedDetectionLong", new BooleanCallback() {
					@Override
					public Boolean get() {
						return Node.this.connectionSpeedDetection;
					}

					@Override
					public void set(Boolean connectionSpeedDetection) {
						synchronized (Node.this) {
							Node.this.connectionSpeedDetection = connectionSpeedDetection;
						}
					}
				});

		this.connectionSpeedDetection = nodeConfig.getBoolean("connectionSpeedDetection");

		nodeConfig.register("throttleLocalTraffic", false, sortOrder++, true, false, "Node.throttleLocalTraffic",
				"Node.throttleLocalTrafficLong", new BooleanCallback() {

					@Override
					public Boolean get() {
						return Node.this.throttleLocalData;
					}

					@Override
					public void set(Boolean val) {
						Node.this.throttleLocalData = val;
					}

				});

		this.throttleLocalData = nodeConfig.getBoolean("throttleLocalTraffic");

		String s = """
				Testnet mode DISABLED. You may have some level of anonymity. :)
				Note that this version of Freenet is still a very early alpha, and may well have numerous bugs and design flaws.
				In particular: YOU ARE WIDE OPEN TO YOUR IMMEDIATE PEERS! They can eavesdrop on your requests with relatively little difficulty at present (correlation attacks etc).""";
		Logger.normal(this, s);
		System.err.println(s);

		File nodeFile = this.nodeDir.file("node-" + this.getDarknetPortNumber());
		File nodeFileBackup = this.nodeDir.file("node-" + this.getDarknetPortNumber() + ".bak");
		// After we have set up testnet and IP address, load the node file
		try {
			// FIXME should take file directly?
			this.readNodeFile(nodeFile.getPath());
		}
		catch (IOException ex) {
			try {
				System.err.println("Trying to read node file backup ...");
				this.readNodeFile(nodeFileBackup.getPath());
			}
			catch (IOException e1) {
				if (nodeFile.exists() || nodeFileBackup.exists()) {
					System.err.println("No node file or cannot read, (re)initialising crypto etc");
					System.err.println(e1);
					e1.printStackTrace();
					System.err.println("After:");
					System.err.println(ex);
					ex.printStackTrace();
				}
				else {
					System.err.println("Creating new cryptographic keys...");
				}
				this.initNodeFileSettings();
			}
		}

		// Then read the peers
		this.peers = new PeerManager(this, this.shutdownHook);

		this.tracker = new RequestTracker(this.peers, this.ticker);

		this.dispatcher = new NodeDispatcher(this);
		this.usm.setDispatcher(this.dispatcher);

		this.uptime = new UptimeEstimator(this.runDir, this.ticker, this.darknetCrypto.identityHash);

		// ULPRs

		this.failureTable = new FailureTable(this);

		this.nodeStats = new NodeStats(this, sortOrder, config.createSubConfig("node.load"), obwLimit, ibwLimit,
				this.lastVersion);

		// clientCore needs new load management and other settings from stats.
		this.clientCore = new NodeClientCore(this, config, nodeConfig, installConfig, this.getDarknetPortNumber(),
				sortOrder, oldConfig, fproxyConfig, toadlets, this.databaseKey, persistentSecret);
		toadlets.setCore(this.clientCore);

		if (JVMVersion.isEOL()) {
			this.clientCore.alerts.register(new JVMVersionAlert());
		}

		if (this.showFriendsVisibilityAlert) {
			this.registerFriendsVisibilityAlert();
		}

		// Node updater support

		System.out.println("Initializing Node Updater");
		try {
			this.nodeUpdater = NodeUpdateManager.maybeCreate(this, config);
		}
		catch (InvalidConfigValueException ex) {
			ex.printStackTrace();
			throw new NodeInitException(NodeInitException.EXIT_COULD_NOT_START_UPDATER,
					"Could not create Updater: " + ex);
		}

		// Opennet

		final SubConfig opennetConfig = config.createSubConfig("node.opennet");
		opennetConfig.register("connectToSeednodes", true, 0, true, false, "Node.withAnnouncement",
				"Node.withAnnouncementLong", new BooleanCallback() {
					@Override
					public Boolean get() {
						return Node.this.isAllowedToConnectToSeednodes;
					}

					@Override
					public void set(Boolean val) throws NodeNeedRestartException {
						if (this.get().equals(val)) {
							return;
						}
						synchronized (Node.this) {
							Node.this.isAllowedToConnectToSeednodes = val;
							if (Node.this.opennet != null) {
								throw new NodeNeedRestartException(
										Node.this.l10n("connectToSeednodesCannotBeChangedMustDisableOpennetOrReboot"));
							}
						}
					}
				});
		this.isAllowedToConnectToSeednodes = opennetConfig.getBoolean("connectToSeednodes");

		// Can be enabled on the fly
		opennetConfig.register("enabled", false, 0, true, true, "Node.opennetEnabled", "Node.opennetEnabledLong",
				new BooleanCallback() {
					@Override
					public Boolean get() {
						synchronized (Node.this) {
							return Node.this.opennet != null;
						}
					}

					@Override
					public void set(Boolean val) throws InvalidConfigValueException {
						OpennetManager o;
						synchronized (Node.this) {
							if (val == (Node.this.opennet != null)) {
								return;
							}
							if (val) {
								try {
									Node.this.opennet = new OpennetManager(Node.this, Node.this.opennetCryptoConfig,
											System.currentTimeMillis(), Node.this.isAllowedToConnectToSeednodes);
									o = Node.this.opennet;
								}
								catch (NodeInitException ex) {
									Node.this.opennet = null;
									throw new InvalidConfigValueException(ex.getMessage());
								}
							}
							else {
								o = Node.this.opennet;
								Node.this.opennet = null;
							}
						}
						if (val) {
							o.start();
						}
						else {
							o.stop(true);
						}
						Node.this.ipDetector.ipDetectorManager.notifyPortChange(Node.this.getPublicInterfacePorts());
					}
				});
		boolean opennetEnabled = opennetConfig.getBoolean("enabled");

		opennetConfig.register("maxOpennetPeers", OpennetManager.MAX_PEERS_FOR_SCALING, 1, true, false,
				"Node.maxOpennetPeers", "Node.maxOpennetPeersLong", new IntCallback() {
					@Override
					public Integer get() {
						return Node.this.maxOpennetPeers;
					}

					@Override
					public void set(Integer inputMaxOpennetPeers) throws InvalidConfigValueException {
						if (inputMaxOpennetPeers < 0) {
							throw new InvalidConfigValueException(Node.this.l10n("mustBePositive"));
						}
						if (inputMaxOpennetPeers > OpennetManager.MAX_PEERS_FOR_SCALING) {
							throw new InvalidConfigValueException(Node.this.l10n("maxOpennetPeersMustBeTwentyOrLess",
									"maxpeers", Integer.toString(OpennetManager.MAX_PEERS_FOR_SCALING)));
						}
						Node.this.maxOpennetPeers = inputMaxOpennetPeers;
					}
				}, false);

		this.maxOpennetPeers = opennetConfig.getInt("maxOpennetPeers");
		if (this.maxOpennetPeers > OpennetManager.MAX_PEERS_FOR_SCALING) {
			Logger.error(this, "maxOpennetPeers may not be over " + OpennetManager.MAX_PEERS_FOR_SCALING);
			this.maxOpennetPeers = OpennetManager.MAX_PEERS_FOR_SCALING;
		}

		this.opennetCryptoConfig = new NodeCryptoConfig(opennetConfig, 2 /* 0 = enabled */, true, this.securityLevels);

		if (opennetEnabled) {
			this.opennet = new OpennetManager(this, this.opennetCryptoConfig, System.currentTimeMillis(),
					this.isAllowedToConnectToSeednodes);
			// Will be started later
		}
		else {
			this.opennet = null;
		}

		this.securityLevels.addNetworkThreatLevelListener(new SecurityLevelListener<>() {

			@Override
			public void onChange(NETWORK_THREAT_LEVEL oldLevel, NETWORK_THREAT_LEVEL newLevel) {
				if (newLevel == NETWORK_THREAT_LEVEL.HIGH || newLevel == NETWORK_THREAT_LEVEL.MAXIMUM) {
					OpennetManager om;
					synchronized (Node.this) {
						om = Node.this.opennet;
						if (om != null) {
							Node.this.opennet = null;
						}
					}
					if (om != null) {
						om.stop(true);
						Node.this.ipDetector.ipDetectorManager.notifyPortChange(Node.this.getPublicInterfacePorts());
					}
				}
				else if (newLevel == NETWORK_THREAT_LEVEL.NORMAL || newLevel == NETWORK_THREAT_LEVEL.LOW) {
					OpennetManager o = null;
					synchronized (Node.this) {
						if (Node.this.opennet == null) {
							try {
								Node.this.opennet = new OpennetManager(Node.this, Node.this.opennetCryptoConfig,
										System.currentTimeMillis(), Node.this.isAllowedToConnectToSeednodes);
								o = Node.this.opennet;
							}
							catch (NodeInitException ex) {
								Node.this.opennet = null;
								Logger.error(this, "UNABLE TO ENABLE OPENNET: " + ex, ex);
								Node.this.clientCore.alerts.register(new SimpleUserAlert(false,
										Node.this.l10n("enableOpennetFailedTitle"),
										Node.this.l10n("enableOpennetFailed", "message", ex.getLocalizedMessage()),
										Node.this.l10n("enableOpennetFailed", "message", ex.getLocalizedMessage()),
										FCPUserAlert.ERROR));
							}
						}
					}
					if (o != null) {
						o.start();
						Node.this.ipDetector.ipDetectorManager.notifyPortChange(Node.this.getPublicInterfacePorts());
					}
				}
				Node.this.config.store();
			}

		});

		opennetConfig.register("acceptSeedConnections", false, 2, true, true, "Node.acceptSeedConnectionsShort",
				"Node.acceptSeedConnections", new BooleanCallback() {

					@Override
					public Boolean get() {
						return Node.this.acceptSeedConnections;
					}

					@Override
					public void set(Boolean val) {
						Node.this.acceptSeedConnections = val;
					}

				});

		this.acceptSeedConnections = opennetConfig.getBoolean("acceptSeedConnections");

		if (this.acceptSeedConnections && this.opennet != null) {
			this.opennet.crypto.socket.getAddressTracker().setHugeTracker();
		}

		opennetConfig.finishedInitialization();

		nodeConfig.register("passOpennetPeersThroughDarknet", true, sortOrder++, true, false,
				"Node.passOpennetPeersThroughDarknet", "Node.passOpennetPeersThroughDarknetLong",
				new BooleanCallback() {

					@Override
					public Boolean get() {
						synchronized (Node.this) {
							return Node.this.passOpennetRefsThroughDarknet;
						}
					}

					@Override
					public void set(Boolean val) {
						synchronized (Node.this) {
							Node.this.passOpennetRefsThroughDarknet = val;
						}
					}

				});

		this.passOpennetRefsThroughDarknet = nodeConfig.getBoolean("passOpennetPeersThroughDarknet");

		this.extraPeerDataDir = this.userDir.file("extra-peer-data-" + this.getDarknetPortNumber());
		if (!((this.extraPeerDataDir.exists() && this.extraPeerDataDir.isDirectory())
				|| (this.extraPeerDataDir.mkdir()))) {
			String msg = "Could not find or create extra peer data directory";
			throw new NodeInitException(NodeInitException.EXIT_BAD_DIR, msg);
		}

		// Name
		nodeConfig.register("name", this.myName, sortOrder++, false, true, "Node.nodeName", "Node.nodeNameLong",
				new NodeNameCallback());
		this.myName = nodeConfig.getString("name");

		// Datastore
		nodeConfig.register("storeForceBigShrinks", false, sortOrder++, true, false, "Node.forceBigShrink",
				"Node.forceBigShrinkLong", new BooleanCallback() {

					@Override
					public Boolean get() {
						synchronized (Node.this) {
							return Node.this.storeForceBigShrinks;
						}
					}

					@Override
					public void set(Boolean val) {
						synchronized (Node.this) {
							Node.this.storeForceBigShrinks = val;
						}
					}

				});

		// Datastore

		nodeConfig.register("storeType", "ram", sortOrder++, true, true, "Node.storeType", "Node.storeTypeLong",
				new StoreTypeCallback());

		this.storeType = nodeConfig.getString("storeType");

		/*
		 * Very small initial store size, since the node will preallocate it when starting
		 * up for the first time, BLOCKING STARTUP, and since everyone goes through the
		 * wizard anyway...
		 */
		nodeConfig.register("storeSize", DEFAULT_STORE_SIZE, sortOrder++, false, true, "Node.storeSize",
				"Node.storeSizeLong", new LongCallback() {

					@Override
					public Long get() {
						return Node.this.maxTotalDatastoreSize;
					}

					@Override
					public void set(Long storeSize) throws InvalidConfigValueException {
						if (storeSize < MIN_STORE_SIZE) {
							throw new InvalidConfigValueException(Node.this.l10n("invalidStoreSize"));
						}
						long newMaxStoreKeys = storeSize / sizePerKey;
						if (newMaxStoreKeys == Node.this.maxTotalKeys) {
							return;
						}
						// Update each datastore
						synchronized (Node.this) {
							Node.this.maxTotalDatastoreSize = storeSize;
							Node.this.maxTotalKeys = newMaxStoreKeys;
							Node.this.maxStoreKeys = Node.this.maxTotalKeys / 2;
							Node.this.maxCacheKeys = Node.this.maxTotalKeys - Node.this.maxStoreKeys;
						}
						try {
							Node.this.chkDatastore.setMaxKeys(Node.this.maxStoreKeys, Node.this.storeForceBigShrinks);
							Node.this.chkDatacache.setMaxKeys(Node.this.maxCacheKeys, Node.this.storeForceBigShrinks);
							Node.this.pubKeyDatastore.setMaxKeys(Node.this.maxStoreKeys,
									Node.this.storeForceBigShrinks);
							Node.this.pubKeyDatacache.setMaxKeys(Node.this.maxCacheKeys,
									Node.this.storeForceBigShrinks);
							Node.this.sskDatastore.setMaxKeys(Node.this.maxStoreKeys, Node.this.storeForceBigShrinks);
							Node.this.sskDatacache.setMaxKeys(Node.this.maxCacheKeys, Node.this.storeForceBigShrinks);
						}
						catch (IOException ex) {
							// FIXME we need to be able to tell the user.
							Logger.error(this, "Caught " + ex + " resizing the datastore", ex);
							System.err.println("Caught " + ex + " resizing the datastore");
							ex.printStackTrace();
						}
						// Perhaps a bit hackish...? Seems like this should be near it's
						// definition in NodeStats.
						Node.this.nodeStats.avgStoreCHKLocation.changeMaxReports((int) Node.this.maxStoreKeys);
						Node.this.nodeStats.avgCacheCHKLocation.changeMaxReports((int) Node.this.maxCacheKeys);
						Node.this.nodeStats.avgSlashdotCacheCHKLocation.changeMaxReports((int) Node.this.maxCacheKeys);
						Node.this.nodeStats.avgClientCacheCHKLocation.changeMaxReports((int) Node.this.maxCacheKeys);

						Node.this.nodeStats.avgStoreSSKLocation.changeMaxReports((int) Node.this.maxStoreKeys);
						Node.this.nodeStats.avgCacheSSKLocation.changeMaxReports((int) Node.this.maxCacheKeys);
						Node.this.nodeStats.avgSlashdotCacheSSKLocation.changeMaxReports((int) Node.this.maxCacheKeys);
						Node.this.nodeStats.avgClientCacheSSKLocation.changeMaxReports((int) Node.this.maxCacheKeys);
					}
				}, true);

		this.maxTotalDatastoreSize = nodeConfig.getLong("storeSize");

		if (this.maxTotalDatastoreSize < MIN_STORE_SIZE && !this.storeType.equals("ram")) { // totally
			// arbitrary
			// minimum!
			throw new NodeInitException(NodeInitException.EXIT_INVALID_STORE_SIZE, "Store size too small");
		}

		this.maxTotalKeys = this.maxTotalDatastoreSize / sizePerKey;

		nodeConfig.register("storeUseSlotFilters", true, sortOrder++, true, false, "Node.storeUseSlotFilters",
				"Node.storeUseSlotFiltersLong", new BooleanCallback() {

					public Boolean get() {
						synchronized (Node.this) {
							return Node.this.storeUseSlotFilters;
						}
					}

					public void set(Boolean val) throws NodeNeedRestartException {
						synchronized (Node.this) {
							Node.this.storeUseSlotFilters = val;
						}

						// FIXME l10n
						throw new NodeNeedRestartException("Need to restart to change storeUseSlotFilters");
					}

				});

		this.storeUseSlotFilters = nodeConfig.getBoolean("storeUseSlotFilters");

		nodeConfig.register("storeSaltHashSlotFilterPersistenceTime",
				ResizablePersistentIntBuffer.DEFAULT_PERSISTENCE_TIME, sortOrder++, true, false,
				"Node.storeSaltHashSlotFilterPersistenceTime", "Node.storeSaltHashSlotFilterPersistenceTimeLong",
				new IntCallback() {

					@Override
					public Integer get() {
						return Node.this.storeSaltHashSlotFilterPersistenceTime;
					}

					@Override
					public void set(Integer val) throws InvalidConfigValueException {
						if (val >= -1) {
							ResizablePersistentIntBuffer.setPersistenceTime(val);
							Node.this.storeSaltHashSlotFilterPersistenceTime = val;
						}
						else {
							throw new InvalidConfigValueException(Node.this.l10n("slotFilterPersistenceTimeError"));
						}
					}

				}, false);
		this.storeSaltHashSlotFilterPersistenceTime = nodeConfig.getInt("storeSaltHashSlotFilterPersistenceTime");

		nodeConfig.register("storeSaltHashResizeOnStart", false, sortOrder++, true, false,
				"Node.storeSaltHashResizeOnStart", "Node.storeSaltHashResizeOnStartLong", new BooleanCallback() {
					@Override
					public Boolean get() {
						return Node.this.storeSaltHashResizeOnStart;
					}

					@Override
					public void set(Boolean val) {
						Node.this.storeSaltHashResizeOnStart = val;
					}
				});
		this.storeSaltHashResizeOnStart = nodeConfig.getBoolean("storeSaltHashResizeOnStart");

		this.storeDir = this.setupProgramDir(installConfig, "storeDir", this.userDir().file("datastore").getPath(),
				"Node.storeDirectory", "Node.storeDirectoryLong", nodeConfig);
		installConfig.finishedInitialization();

		final String suffix = this.getStoreSuffix();

		this.maxStoreKeys = this.maxTotalKeys / 2;
		this.maxCacheKeys = this.maxTotalKeys - this.maxStoreKeys;

		/*
		 * On Windows, setting the file length normally involves writing lots of zeros. So
		 * it's an uninterruptible system call that takes a loooong time. On OS/X,
		 * presumably the same is true. If the RNG is fast enough, this means that setting
		 * the length and writing random data take exactly the same amount of time. On
		 * most versions of Unix, holes can be created. However on all systems,
		 * predictable disk usage is a good thing. So lets turn it on by default for now,
		 * on all systems. The datastore can be read but mostly not written while the
		 * random data is being written.
		 */
		nodeConfig.register("storePreallocate", true, sortOrder++, true, true, "Node.storePreallocate",
				"Node.storePreallocateLong", new BooleanCallback() {
					@Override
					public Boolean get() {
						return Node.this.storePreallocate;
					}

					@Override
					public void set(Boolean val) {
						Node.this.storePreallocate = val;
						if (Node.this.storeType.equals("salt-hash")) {
							this.setPreallocate(Node.this.chkDatastore, val);
							this.setPreallocate(Node.this.chkDatacache, val);
							this.setPreallocate(Node.this.pubKeyDatastore, val);
							this.setPreallocate(Node.this.pubKeyDatacache, val);
							this.setPreallocate(Node.this.sskDatastore, val);
							this.setPreallocate(Node.this.sskDatacache, val);
						}
					}

					private void setPreallocate(StoreCallback<?> datastore, boolean val) {
						// Avoid race conditions by checking first.
						FreenetStore<?> store = datastore.getStore();
						if (store instanceof SaltedHashFreenetStore) {
							((SaltedHashFreenetStore<?>) store).setPreallocate(val);
						}
					}
				});
		this.storePreallocate = nodeConfig.getBoolean("storePreallocate");

		if (File.separatorChar == '/' && !System.getProperty("os.name").toLowerCase().contains("mac os")) {
			this.securityLevels.addPhysicalThreatLevelListener((oldLevel, newLevel) -> {
				try {
					nodeConfig.set("storePreallocate", newLevel != PHYSICAL_THREAT_LEVEL.LOW);
				}
				catch (NodeNeedRestartException | InvalidConfigValueException ignored) {
					// Ignore
				}
			});
		}

		this.securityLevels.addPhysicalThreatLevelListener(new SecurityLevelListener<>() {

			@Override
			public void onChange(PHYSICAL_THREAT_LEVEL oldLevel, PHYSICAL_THREAT_LEVEL newLevel) {
				if (newLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM) {
					synchronized (this) {
						Node.this.clientCacheAwaitingPassword = false;
						Node.this.databaseAwaitingPassword = false;
					}
					try {
						Node.this.killMasterKeysFile();
						Node.this.clientCore.clientLayerPersister.disableWrite();
						Node.this.clientCore.clientLayerPersister.waitForNotWriting();
						Node.this.clientCore.clientLayerPersister.deleteAllFiles();
					}
					catch (IOException ignored) {
						Node.this.masterKeysFile.delete();
						Logger.error(this, "Unable to securely delete " + Node.this.masterKeysFile);
						System.err.println(NodeL10n.getBase().getString("SecurityLevels.cantDeletePasswordFile",
								"filename", Node.this.masterKeysFile.getAbsolutePath()));
						Node.this.clientCore.alerts.register(new SimpleUserAlert(true,
								NodeL10n.getBase().getString("SecurityLevels.cantDeletePasswordFileTitle"),
								NodeL10n.getBase().getString("SecurityLevels.cantDeletePasswordFile"),
								NodeL10n.getBase().getString("SecurityLevels.cantDeletePasswordFileTitle"),
								FCPUserAlert.CRITICAL_ERROR));
					}
				}

				if (oldLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM && newLevel != PHYSICAL_THREAT_LEVEL.HIGH) {
					// Not passworded.
					// Create the master.keys.
					// Keys must exist.
					try {
						MasterKeys masterKeys;
						synchronized (this) {
							masterKeys = Node.this.keys;
						}
						masterKeys.changePassword(Node.this.masterKeysFile, "", Node.this.secureRandom);
					}
					catch (IOException ex) {
						Logger.error(this,
								"Unable to create encryption keys file: " + Node.this.masterKeysFile + " : " + ex, ex);
						System.err.println(
								"Unable to create encryption keys file: " + Node.this.masterKeysFile + " : " + ex);
						ex.printStackTrace();
					}
				}
			}

		});

		if (this.securityLevels.physicalThreatLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM) {
			try {
				this.killMasterKeysFile();
			}
			catch (IOException ignored) {
				String msg = "Unable to securely delete old master.keys file when switching to MAXIMUM seclevel!!";
				System.err.println(msg);
				throw new NodeInitException(NodeInitException.EXIT_CANT_WRITE_MASTER_KEYS, msg);
			}
		}

		long defaultCacheSize;
		long memoryLimit = NodeStarter.getMemoryLimitBytes();
		// This is tricky because systems with low memory probably also have slow disks,
		// but using
		// up too much memory can be catastrophic...
		// Total alchemy, FIXME!
		if (memoryLimit == Long.MAX_VALUE || memoryLimit < 0) {
			defaultCacheSize = 1024 * 1024;
		}
		else if (memoryLimit <= 128 * 1024 * 1024) {
			defaultCacheSize = 0; // Turn off completely for very small memory.
		}
		else {
			// 9 stores, total should be 5% of memory, up to maximum of 1MB per store at
			// 308MB+
			defaultCacheSize = Math.min(1024 * 1024, (memoryLimit - 128 * 1024 * 1024) / (20 * 9));
		}

		nodeConfig.register("cachingFreenetStoreMaxSize", defaultCacheSize, sortOrder++, true, false,
				"Node.cachingFreenetStoreMaxSize", "Node.cachingFreenetStoreMaxSizeLong", new LongCallback() {
					@Override
					public Long get() {
						synchronized (Node.this) {
							return Node.this.cachingFreenetStoreMaxSize;
						}
					}

					@Override
					public void set(Long val) throws InvalidConfigValueException, NodeNeedRestartException {
						if (val < 0) {
							throw new InvalidConfigValueException(Node.this.l10n("invalidMemoryCacheSize"));
						}
						// Any positive value is legal. In particular, e.g. 1200 bytes
						// would cause us to cache SSKs but not CHKs.
						synchronized (Node.this) {
							Node.this.cachingFreenetStoreMaxSize = val;
						}
						throw new NodeNeedRestartException("Caching Maximum Size cannot be changed on the fly");
					}
				}, true);

		this.cachingFreenetStoreMaxSize = nodeConfig.getLong("cachingFreenetStoreMaxSize");
		if (this.cachingFreenetStoreMaxSize < 0) {
			throw new NodeInitException(NodeInitException.EXIT_BAD_CONFIG, this.l10n("invalidMemoryCacheSize"));
		}

		nodeConfig.register("cachingFreenetStorePeriod", "300k", sortOrder++, true, false,
				"Node.cachingFreenetStorePeriod", "Node.cachingFreenetStorePeriod", new LongCallback() {
					@Override
					public Long get() {
						synchronized (Node.this) {
							return Node.this.cachingFreenetStorePeriod;
						}
					}

					@Override
					public void set(Long val) throws NodeNeedRestartException {
						synchronized (Node.this) {
							Node.this.cachingFreenetStorePeriod = val;
						}
						throw new NodeNeedRestartException("Caching Period cannot be changed on the fly");
					}
				}, true);

		this.cachingFreenetStorePeriod = nodeConfig.getLong("cachingFreenetStorePeriod");

		if (this.cachingFreenetStoreMaxSize > 0 && this.cachingFreenetStorePeriod > 0) {
			this.cachingFreenetStoreTracker = new CachingFreenetStoreTracker(this.cachingFreenetStoreMaxSize,
					this.cachingFreenetStorePeriod, this.ticker);
		}

		boolean shouldWriteConfig = false;

		if (this.storeType.equals("bdb-index")) {
			System.err.println("Old format Berkeley DB datastore detected.");
			System.err.println("This datastore format is no longer supported.");
			System.err.println("The old datastore will be securely deleted.");
			this.storeType = "salt-hash";
			shouldWriteConfig = true;
			this.deleteOldBDBIndexStoreFiles();
		}
		if (this.storeType.equals("salt-hash")) {
			this.initRAMFS();
			this.initSaltHashFS(suffix, false, null);
		}
		else {
			this.initRAMFS();
		}

		if (this.databaseAwaitingPassword) {
			this.createPasswordUserAlert();
		}

		// Client cache

		// Default is 10MB, in memory only. The wizard will change this.

		nodeConfig.register("clientCacheType", "ram", sortOrder++, true, true, "Node.clientCacheType",
				"Node.clientCacheTypeLong", new ClientCacheTypeCallback());

		this.clientCacheType = nodeConfig.getString("clientCacheType");

		nodeConfig.register("clientCacheSize", DEFAULT_CLIENT_CACHE_SIZE, sortOrder++, false, true,
				"Node.clientCacheSize", "Node.clientCacheSizeLong", new LongCallback() {

					@Override
					public Long get() {
						return Node.this.maxTotalClientCacheSize;
					}

					@Override
					public void set(Long storeSize) throws InvalidConfigValueException {
						if (storeSize < MIN_CLIENT_CACHE_SIZE) {
							throw new InvalidConfigValueException(Node.this.l10n("invalidStoreSize"));
						}
						long newMaxStoreKeys = storeSize / sizePerKey;
						if (newMaxStoreKeys == Node.this.maxClientCacheKeys) {
							return;
						}
						// Update each datastore
						synchronized (Node.this) {
							Node.this.maxTotalClientCacheSize = storeSize;
							Node.this.maxClientCacheKeys = newMaxStoreKeys;
						}
						try {
							Node.this.chkClientcache.setMaxKeys(Node.this.maxClientCacheKeys,
									Node.this.storeForceBigShrinks);
							Node.this.pubKeyClientcache.setMaxKeys(Node.this.maxClientCacheKeys,
									Node.this.storeForceBigShrinks);
							Node.this.sskClientcache.setMaxKeys(Node.this.maxClientCacheKeys,
									Node.this.storeForceBigShrinks);
						}
						catch (IOException ex) {
							// FIXME we need to be able to tell the user.
							Logger.error(this, "Caught " + ex + " resizing the clientcache", ex);
							System.err.println("Caught " + ex + " resizing the clientcache");
							ex.printStackTrace();
						}
					}
				}, true);

		this.maxTotalClientCacheSize = nodeConfig.getLong("clientCacheSize");

		if (this.maxTotalClientCacheSize < MIN_CLIENT_CACHE_SIZE) {
			throw new NodeInitException(NodeInitException.EXIT_INVALID_STORE_SIZE, "Client cache size too small");
		}

		this.maxClientCacheKeys = this.maxTotalClientCacheSize / sizePerKey;

		boolean startedClientCache = false;

		if (this.clientCacheType.equals("salt-hash")) {
			if (clientCacheKey == null) {
				System.err.println("Cannot open client-cache, it is passworded");
				this.setClientCacheAwaitingPassword();
			}
			else {
				this.initSaltHashClientCacheFS(suffix, false, clientCacheKey);
				startedClientCache = true;
			}
		}
		else if (this.clientCacheType.equals("none")) {
			this.initNoClientCacheFS();
			startedClientCache = true;
		}
		else { // ram
			this.initRAMClientCacheFS();
			startedClientCache = true;
		}

		if (!startedClientCache) {
			this.initRAMClientCacheFS();
		}

		if (!this.clientCore.loadedDatabase() && this.databaseKey != null) {
			try {
				this.lateSetupDatabase(this.databaseKey);
			}
			catch (MasterKeysWrongPasswordException | MasterKeysFileSizeException e2) {
				System.err.println("Impossible: " + e2);
				e2.printStackTrace();
			}
			catch (IOException e2) {
				System.err.println("Unable to load database: " + e2);
				e2.printStackTrace();
			}
		}

		nodeConfig.register("useSlashdotCache", true, sortOrder++, true, false, "Node.useSlashdotCache",
				"Node.useSlashdotCacheLong", new BooleanCallback() {

					@Override
					public Boolean get() {
						return Node.this.useSlashdotCache;
					}

					@Override
					public void set(Boolean val) {
						Node.this.useSlashdotCache = val;
					}

				});
		this.useSlashdotCache = nodeConfig.getBoolean("useSlashdotCache");

		nodeConfig.register("writeLocalToDatastore", false, sortOrder++, true, false, "Node.writeLocalToDatastore",
				"Node.writeLocalToDatastoreLong", new BooleanCallback() {

					@Override
					public Boolean get() {
						return Node.this.writeLocalToDatastore;
					}

					@Override
					public void set(Boolean val) {
						Node.this.writeLocalToDatastore = val;
					}

				});

		this.writeLocalToDatastore = nodeConfig.getBoolean("writeLocalToDatastore");

		// LOW network *and* physical seclevel = writeLocalToDatastore

		this.securityLevels.addNetworkThreatLevelListener(
				(oldLevel, newLevel) -> Node.this.writeLocalToDatastore = newLevel == NETWORK_THREAT_LEVEL.LOW
						&& Node.this.securityLevels.getPhysicalThreatLevel() == PHYSICAL_THREAT_LEVEL.LOW);

		this.securityLevels.addPhysicalThreatLevelListener(
				(oldLevel, newLevel) -> Node.this.writeLocalToDatastore = newLevel == PHYSICAL_THREAT_LEVEL.LOW
						&& Node.this.securityLevels.getNetworkThreatLevel() == NETWORK_THREAT_LEVEL.LOW);

		nodeConfig.register("slashdotCacheLifetime", TimeUnit.MINUTES.toMillis(30), sortOrder++, true, false,
				"Node.slashdotCacheLifetime", "Node.slashdotCacheLifetimeLong", new LongCallback() {

					@Override
					public Long get() {
						return Node.this.chkSlashdotcacheStore.getLifetime();
					}

					@Override
					public void set(Long val) throws InvalidConfigValueException {
						if (val < 0) {
							throw new InvalidConfigValueException("Must be positive!");
						}
						Node.this.chkSlashdotcacheStore.setLifetime(val);
						Node.this.pubKeySlashdotcacheStore.setLifetime(val);
						Node.this.sskSlashdotcacheStore.setLifetime(val);
					}

				}, false);

		long slashdotCacheLifetime = nodeConfig.getLong("slashdotCacheLifetime");

		nodeConfig.register("slashdotCacheSize", DEFAULT_SLASHDOT_CACHE_SIZE, sortOrder++, false, true,
				"Node.slashdotCacheSize", "Node.slashdotCacheSizeLong", new LongCallback() {

					@Override
					public Long get() {
						return Node.this.maxSlashdotCacheSize;
					}

					@Override
					public void set(Long storeSize) throws InvalidConfigValueException {
						if (storeSize < MIN_SLASHDOT_CACHE_SIZE) {
							throw new InvalidConfigValueException(Node.this.l10n("invalidStoreSize"));
						}
						int newMaxStoreKeys = (int) Math.min(storeSize / sizePerKey, Integer.MAX_VALUE);
						if (newMaxStoreKeys == Node.this.maxSlashdotCacheKeys) {
							return;
						}
						// Update each datastore
						synchronized (Node.this) {
							Node.this.maxSlashdotCacheSize = storeSize;
							Node.this.maxSlashdotCacheKeys = newMaxStoreKeys;
						}
						try {
							Node.this.chkSlashdotcache.setMaxKeys(Node.this.maxSlashdotCacheKeys,
									Node.this.storeForceBigShrinks);
							Node.this.pubKeySlashdotcache.setMaxKeys(Node.this.maxSlashdotCacheKeys,
									Node.this.storeForceBigShrinks);
							Node.this.sskSlashdotcache.setMaxKeys(Node.this.maxSlashdotCacheKeys,
									Node.this.storeForceBigShrinks);
						}
						catch (IOException ex) {
							// FIXME we need to be able to tell the user.
							Logger.error(this, "Caught " + ex + " resizing the slashdotcache", ex);
							System.err.println("Caught " + ex + " resizing the slashdotcache");
							ex.printStackTrace();
						}
					}
				}, true);

		this.maxSlashdotCacheSize = nodeConfig.getLong("slashdotCacheSize");

		if (this.maxSlashdotCacheSize < MIN_SLASHDOT_CACHE_SIZE) {
			throw new NodeInitException(NodeInitException.EXIT_INVALID_STORE_SIZE, "Slashdot cache size too small");
		}

		this.maxSlashdotCacheKeys = (int) Math.min(this.maxSlashdotCacheSize / sizePerKey, Integer.MAX_VALUE);

		this.chkSlashdotcache = new CHKStore();
		this.chkSlashdotcacheStore = new SlashdotStore<>(this.chkSlashdotcache, this.maxSlashdotCacheKeys,
				slashdotCacheLifetime, PURGE_INTERVAL, this.ticker, this.clientCore.tempBucketFactory);
		this.pubKeySlashdotcache = new PubkeyStore();
		this.pubKeySlashdotcacheStore = new SlashdotStore<>(this.pubKeySlashdotcache, this.maxSlashdotCacheKeys,
				slashdotCacheLifetime, PURGE_INTERVAL, this.ticker, this.clientCore.tempBucketFactory);
		this.getPubKey.setLocalSlashdotcache(this.pubKeySlashdotcache);
		this.sskSlashdotcache = new SSKStore(this.getPubKey);
		this.sskSlashdotcacheStore = new SlashdotStore<>(this.sskSlashdotcache, this.maxSlashdotCacheKeys,
				slashdotCacheLifetime, PURGE_INTERVAL, this.ticker, this.clientCore.tempBucketFactory);

		// MAXIMUM seclevel = no slashdot cache.

		this.securityLevels.addNetworkThreatLevelListener((oldLevel, newLevel) -> {
			if (newLevel == NETWORK_THREAT_LEVEL.MAXIMUM) {
				Node.this.useSlashdotCache = false;
			}
			else if (oldLevel == NETWORK_THREAT_LEVEL.MAXIMUM) {
				Node.this.useSlashdotCache = true;
			}
		});

		nodeConfig.register("skipWrapperWarning", false, sortOrder++, true, false, "Node.skipWrapperWarning",
				"Node.skipWrapperWarningLong", new BooleanCallback() {

					@Override
					public void set(Boolean value) {
						Node.this.skipWrapperWarning = value;
					}

					@Override
					public Boolean get() {
						return Node.this.skipWrapperWarning;
					}
				});

		this.skipWrapperWarning = nodeConfig.getBoolean("skipWrapperWarning");

		nodeConfig.register("maxPacketSize", 1280, sortOrder++, true, true, "Node.maxPacketSize",
				"Node.maxPacketSizeLong", new IntCallback() {

					@Override
					public Integer get() {
						synchronized (Node.this) {
							return Node.this.maxPacketSize;
						}
					}

					@Override
					public void set(Integer val) throws InvalidConfigValueException {
						synchronized (Node.this) {
							if (val == Node.this.maxPacketSize) {
								return;
							}
							if (val < UdpSocketHandler.MIN_MTU) {
								throw new InvalidConfigValueException("Must be over 576");
							}
							if (val > 1492) {
								throw new InvalidConfigValueException(
										"Larger than ethernet frame size unlikely to work!");
							}
							Node.this.maxPacketSize = val;
						}
						Node.this.updateMTU();
					}

				}, true);

		this.maxPacketSize = nodeConfig.getInt("maxPacketSize");

		nodeConfig.register("enableRoutedPing", false, sortOrder++, true, false, "Node.enableRoutedPing",
				"Node.enableRoutedPingLong", new BooleanCallback() {

					@Override
					public Boolean get() {
						synchronized (Node.this) {
							return Node.this.enableRoutedPing;
						}
					}

					@Override
					public void set(Boolean val) {
						synchronized (Node.this) {
							Node.this.enableRoutedPing = val;
						}
					}

				});
		this.enableRoutedPing = nodeConfig.getBoolean("enableRoutedPing");

		nodeConfig.register("enableNodeDiagnostics", false, sortOrder++, true, false, "Node.enableDiagnostics",
				"Node.enableDiagnosticsLong", new BooleanCallback() {
					@Override
					public Boolean get() {
						synchronized (Node.this) {
							return Node.this.enableNodeDiagnostics;
						}
					}

					@Override
					public void set(Boolean val) {
						synchronized (Node.this) {
							Node.this.enableNodeDiagnostics = val;
							Node.this.nodeDiagnostics.stop();

							if (Node.this.enableNodeDiagnostics) {
								Node.this.nodeDiagnostics.start();
							}
						}
					}
				});
		this.enableNodeDiagnostics = nodeConfig.getBoolean("enableNodeDiagnostics");

		this.updateMTU();

		// peers-offers/*.fref files
		this.peersOffersFrefFilesConfiguration(nodeConfig, sortOrder++);
		if (!this.peersOffersDismissed && this.checkPeersOffersFrefFiles()) {
			PeersOffersUserAlert.createAlert(this);
		}

		/*
		 * Take care that no configuration options are registered after this point; they
		 * will not persist between restarts.
		 */
		nodeConfig.finishedInitialization();
		if (shouldWriteConfig) {
			config.store();
		}
		this.writeNodeFile();

		// Initialize the plugin manager
		Logger.normal(this, "Initializing Plugin Manager");
		System.out.println("Initializing Plugin Manager");
		this.pluginManager = new PluginManager(this, this.lastVersion);

		this.shutdownHook.addEarlyJob(new NativeThread("Shutdown plugins", NativeThread.HIGH_PRIORITY, true) {
			@Override
			public void realRun() {
				Node.this.pluginManager.stop(TimeUnit.SECONDS.toMillis(30)); // FIXME make
																				// it
				// configurable??
			}
		});

		// FIXME
		// Short timeouts and JVM timeouts with nothing more said than the above have been
		// seen...
		// I don't know why... need a stack dump...
		// For now just give it an extra 2 minutes. If it doesn't start in that time,
		// it's likely (on reports so far) that a restart will fix it.
		// And we have to get a build out because ALL plugins are now failing to load,
		// including the absolutely essential (for most nodes) JSTUN and UPnP.
		WrapperManager.signalStarting((int) TimeUnit.MINUTES.toMillis(2));

		FetchContext ctx = this.clientCore.makeClient((short) 0, true, false).getFetchContext();

		ctx.allowSplitfiles = false;
		ctx.dontEnterImplicitArchives = true;
		ctx.maxArchiveRestarts = 0;
		ctx.maxMetadataSize = 256;
		ctx.maxNonSplitfileRetries = 10;
		ctx.maxOutputLength = 4096;
		ctx.maxRecursionLevel = 2;
		ctx.maxTempLength = 4096;

		this.arkFetcherContext = ctx;

		// Keep track of the fileNumber so we can potentially delete the extra peer
		// data file later, the file is authoritative
		// Shouldn't happen
		NodeToNodeMessageListener fproxyN2NMListener = new NodeToNodeMessageListener() {

			@Override
			public void handleMessage(byte[] data, boolean fromDarknet, PeerNode src, int type) {
				if (!fromDarknet) {
					Logger.error(this, "Got N2NTM from non-darknet node ?!?!?!: from " + src);
					return;
				}
				DarknetPeerNode darkSource = (DarknetPeerNode) src;
				Logger.normal(this, "Received N2NTM from '" + darkSource.getPeer() + "'");
				SimpleFieldSet fs = null;
				try {
					fs = new SimpleFieldSet(new String(data, StandardCharsets.UTF_8), false, true, false);
				}
				catch (UnsupportedEncodingException ex) {
					throw new Error("Impossible: JVM doesn't support UTF-8: " + ex, ex);
				}
				catch (IOException ex) {
					Logger.error(this, "IOException while parsing node to node message data", ex);
					return;
				}
				fs.putOverwrite("n2nType", Integer.toString(type));
				fs.putOverwrite("receivedTime", Long.toString(System.currentTimeMillis()));
				fs.putOverwrite("receivedAs", "nodeToNodeMessage");
				int fileNumber = darkSource.writeNewExtraPeerDataFile(fs, EXTRA_PEER_DATA_TYPE_N2NTM);
				if (fileNumber == -1) {
					Logger.error(this,
							"Failed to write N2NTM to extra peer data file for peer " + darkSource.getPeer());
				}
				// Keep track of the fileNumber so we can potentially delete the extra
				// peer
				// data file later, the file is authoritative
				try {
					Node.this.handleNodeToNodeTextMessageSimpleFieldSet(fs, darkSource, fileNumber);
				}
				catch (FSParseException ex) {
					// Shouldn't happen
					throw new Error(ex);
				}
			}

		};
		this.registerNodeToNodeMessageListener(N2N_MESSAGE_TYPE_FPROXY, fproxyN2NMListener);
		NodeToNodeMessageListener diffNoderefListener = new NodeToNodeMessageListener() {

			@Override
			public void handleMessage(byte[] data, boolean fromDarknet, PeerNode src, int type) {
				Logger.normal(this, "Received differential node reference node to node message from " + src.getPeer());
				SimpleFieldSet fs = null;
				try {
					fs = new SimpleFieldSet(new String(data, StandardCharsets.UTF_8), false, true, false);
				}
				catch (IOException ex) {
					Logger.error(this, "IOException while parsing node to node message data", ex);
					return;
				}
				if (fs.get("n2nType") != null) {
					fs.removeValue("n2nType");
				}
				try {
					src.processDiffNoderef(fs);
				}
				catch (FSParseException ex) {
					Logger.error(this, "FSParseException while parsing node to node message data", ex);
					return;
				}
			}

		};
		this.registerNodeToNodeMessageListener(Node.N2N_MESSAGE_TYPE_DIFFNODEREF, diffNoderefListener);

		// FIXME this is a hack
		// toadlet server should start after all initialized
		// see NodeClientCore line 437
		if (toadlets.isEnabled()) {
			toadlets.finishStart();
			toadlets.createFproxy();
			toadlets.removeStartupToadlet();
		}

		Logger.normal(this, "Node constructor completed");
		System.out.println("Node constructor completed");

		new BandwidthManager(this).start();

		this.nodeDiagnostics = new DefaultNodeDiagnostics(this.nodeStats, this.ticker);
	}

	private void peersOffersFrefFilesConfiguration(SubConfig nodeConfig, int configOptionSortOrder) {
		final Node node = this;
		nodeConfig.register("peersOffersDismissed", false, configOptionSortOrder, true, true,
				"Node.peersOffersDismissed", "Node.peersOffersDismissedLong", new BooleanCallback() {

					@Override
					public Boolean get() {
						return Node.this.peersOffersDismissed;
					}

					@Override
					public void set(Boolean val) {
						if (val) {
							for (FCPUserAlert alert : Node.this.clientCore.alerts.getAlerts()) {
								if (alert instanceof PeersOffersUserAlert) {
									Node.this.clientCore.alerts.unregister(alert);
								}
							}
						}
						else {
							PeersOffersUserAlert.createAlert(node);
						}
						Node.this.peersOffersDismissed = val;
					}
				});
		this.peersOffersDismissed = nodeConfig.getBoolean("peersOffersDismissed");
	}

	private boolean checkPeersOffersFrefFiles() {
		File[] files = this.runDir.file("peers-offers").listFiles();
		if (files != null && files.length > 0) {
			for (File file : files) {
				if (file.isFile()) {
					String filename = file.getName();
					if (filename.endsWith(".fref")) {
						return true;
					}
				}
			}
		}
		return false;
	}

	/** Delete files from old BDB-index datastore. */
	private void deleteOldBDBIndexStoreFiles() {
		File dbDir = this.storeDir.file("database-" + this.getDarknetPortNumber());
		FileUtil.removeAll(dbDir);
		File dir = this.storeDir.dir();
		File[] list = dir.listFiles();
		assert list != null;
		for (File f : list) {
			String name = f.getName();
			if (f.isFile() && name.toLowerCase()
					.matches("((chk)|(ssk)|(pubkey))-\\d*\\.((store)|(cache))(\\.((keys)|(lru)))?")) {
				System.out.println("Deleting old datastore file \"" + f + "\"");
				try {
					FileUtil.secureDelete(f);
				}
				catch (IOException ex) {
					System.err.println("Failed to delete old datastore file \"" + f + "\": " + ex);
					ex.printStackTrace();
				}
			}
		}
	}

	private void fixCertsFiles() {
		// Hack to update certificates file to fix update.cmd
		// startssl.pem: Might be useful for old versions of update.sh too?
		File certs = new File(PluginDownLoaderOfficialHTTPS.certfileOld);
		this.fixCertsFile(certs);
		if (FileUtil.detectedOS.isWindows) {
			// updater\startssl.pem: Needed for Windows update.cmd.
			certs = new File("updater", PluginDownLoaderOfficialHTTPS.certfileOld);
			this.fixCertsFile(certs);
		}
	}

	private void fixCertsFile(File certs) {
		long oldLength = certs.exists() ? certs.length() : -1;
		try {
			File tmpFile = File.createTempFile(PluginDownLoaderOfficialHTTPS.certfileOld, ".tmp", new File("."));
			PluginDownLoaderOfficialHTTPS.writeCertsTo(tmpFile);
			if (FileUtil.renameTo(tmpFile, certs)) {
				long newLength = certs.length();
				if (newLength != oldLength) {
					System.err.println("Updated " + certs + " so that update scripts will work");
				}
			}
			else {
				if (certs.length() != tmpFile.length()) {
					System.err.println("Cannot update " + certs
							+ " : last-resort update scripts (in particular update.cmd on Windows) may not work");
					File manual = new File(PluginDownLoaderOfficialHTTPS.certfileOld + ".new");
					manual.delete();
					if (tmpFile.renameTo(manual)) {
						System.err.println("Please delete " + certs + " and rename " + manual + " over it");
					}
					else {
						tmpFile.delete();
					}
				}
			}
		}
		catch (IOException ignored) {
		}
	}

	/**
	 ** Sets up a program directory using the config value defined by the given parameters.
	 */
	public ProgramDirectory setupProgramDir(SubConfig installConfig, String cfgKey, String defaultValue,
			String shortdesc, String longdesc, String moveErrMsg, SubConfig oldConfig) throws NodeInitException {
		ProgramDirectory dir = new ProgramDirectory(moveErrMsg);
		int sortOrder = ProgramDirectory.nextOrder();
		// forceWrite=true because currently it can't be changed on the fly, also for
		// packages
		installConfig.register(cfgKey, defaultValue, sortOrder, true, true, shortdesc, longdesc,
				dir.getStringCallback());
		String dirName = installConfig.getString(cfgKey);
		try {
			dir.move(dirName);
		}
		catch (IOException ex) {
			throw new NodeInitException(NodeInitException.EXIT_BAD_DIR,
					"could not set up directory: " + longdesc + " (" + dirName + ")");
		}
		return dir;
	}

	protected ProgramDirectory setupProgramDir(SubConfig installConfig, String cfgKey, String defaultValue,
			String shortdesc, String longdesc, SubConfig oldConfig) throws NodeInitException {
		return this.setupProgramDir(installConfig, cfgKey, defaultValue, shortdesc, longdesc, null, oldConfig);
	}

	public void lateSetupDatabase(DatabaseKey databaseKey)
			throws MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException {
		if (this.clientCore.loadedDatabase()) {
			return;
		}
		System.out.println("Starting late database initialisation");

		try {
			if (!this.clientCore.lateInitDatabase(databaseKey)) {
				this.failLateInitDatabase();
			}
		}
		catch (NodeInitException ignored) {
			this.failLateInitDatabase();
		}
	}

	private void failLateInitDatabase() {
		System.err.println("Failed late initialisation of database, closing...");
	}

	public void killMasterKeysFile() throws IOException {
		MasterKeys.killMasterKeys(this.masterKeysFile);
	}

	private void setClientCacheAwaitingPassword() {
		this.createPasswordUserAlert();
		synchronized (this) {
			this.clientCacheAwaitingPassword = true;
		}
	}

	/** Called when the client layer needs the decryption password. */
	void setDatabaseAwaitingPassword() {
		synchronized (this) {
			this.databaseAwaitingPassword = true;
		}
	}

	private final FCPUserAlert masterPasswordUserAlert = new FCPUserAlert() {

		final long creationTime = System.currentTimeMillis();

		@Override
		public String anchor() {
			return "password";
		}

		@Override
		public String dismissButtonText() {
			return null;
		}

		@Override
		public long getUpdatedTime() {
			return this.creationTime;
		}

		@Override
		public FCPMessage getFCPMessage() {
			return new FeedMessage(this.getTitle(), this.getShortText(), this.getText(), this.getPriorityClass(),
					this.getUpdatedTime());
		}

		@Override
		public HTMLNode getHTMLText() {
			HTMLNode content = new HTMLNode("div");
			SecurityLevelsToadlet.generatePasswordFormPage(false, Node.this.clientCore.getToadletContainer(), content,
					false, false, false, null, null);
			return content;
		}

		@Override
		public short getPriorityClass() {
			return FCPUserAlert.ERROR;
		}

		@Override
		public String getShortText() {
			return NodeL10n.getBase().getString("SecurityLevels.enterPassword");
		}

		@Override
		public String getText() {
			return NodeL10n.getBase().getString("SecurityLevels.enterPassword");
		}

		@Override
		public String getTitle() {
			return NodeL10n.getBase().getString("SecurityLevels.enterPassword");
		}

		@Override
		public boolean isEventNotification() {
			return false;
		}

		@Override
		public boolean isValid() {
			synchronized (Node.this) {
				return Node.this.clientCacheAwaitingPassword || Node.this.databaseAwaitingPassword;
			}
		}

		@Override
		public void isValid(boolean validity) {
			// Ignore
		}

		@Override
		public void onDismiss() {
			// Ignore
		}

		@Override
		public boolean shouldUnregisterOnDismiss() {
			return false;
		}

		@Override
		public boolean userCanDismiss() {
			return false;
		}

	};

	private void createPasswordUserAlert() {
		this.clientCore.alerts.register(this.masterPasswordUserAlert);
	}

	private void initRAMClientCacheFS() {
		this.chkClientcache = new CHKStore();
		new RAMFreenetStore<>(this.chkClientcache, (int) Math.min(Integer.MAX_VALUE, this.maxClientCacheKeys));
		this.pubKeyClientcache = new PubkeyStore();
		new RAMFreenetStore<>(this.pubKeyClientcache, (int) Math.min(Integer.MAX_VALUE, this.maxClientCacheKeys));
		this.sskClientcache = new SSKStore(this.getPubKey);
		new RAMFreenetStore<>(this.sskClientcache, (int) Math.min(Integer.MAX_VALUE, this.maxClientCacheKeys));
	}

	private void initNoClientCacheFS() {
		this.chkClientcache = new CHKStore();
		new NullFreenetStore<>(this.chkClientcache);
		this.pubKeyClientcache = new PubkeyStore();
		new NullFreenetStore<>(this.pubKeyClientcache);
		this.sskClientcache = new SSKStore(this.getPubKey);
		new NullFreenetStore<>(this.sskClientcache);
	}

	private String getStoreSuffix() {
		return "-" + this.getDarknetPortNumber();
	}

	private void finishInitSaltHashFS(final String suffix, NodeClientCore clientCore) {
		if (clientCore.alerts == null) {
			throw new NullPointerException();
		}
		this.chkDatastore.getStore().setUserAlertRegister(clientCore.alerts);
		this.chkDatacache.getStore().setUserAlertRegister(clientCore.alerts);
		this.pubKeyDatastore.getStore().setUserAlertRegister(clientCore.alerts);
		this.pubKeyDatacache.getStore().setUserAlertRegister(clientCore.alerts);
		this.sskDatastore.getStore().setUserAlertRegister(clientCore.alerts);
		this.sskDatacache.getStore().setUserAlertRegister(clientCore.alerts);
	}

	private void initRAMFS() {
		this.chkDatastore = new CHKStore();
		new RAMFreenetStore<>(this.chkDatastore, (int) Math.min(Integer.MAX_VALUE, this.maxStoreKeys));
		this.chkDatacache = new CHKStore();
		new RAMFreenetStore<>(this.chkDatacache, (int) Math.min(Integer.MAX_VALUE, this.maxCacheKeys));
		this.pubKeyDatastore = new PubkeyStore();
		new RAMFreenetStore<>(this.pubKeyDatastore, (int) Math.min(Integer.MAX_VALUE, this.maxStoreKeys));
		this.pubKeyDatacache = new PubkeyStore();
		this.getPubKey.setDataStore(this.pubKeyDatastore, this.pubKeyDatacache);
		new RAMFreenetStore<>(this.pubKeyDatacache, (int) Math.min(Integer.MAX_VALUE, this.maxCacheKeys));
		this.sskDatastore = new SSKStore(this.getPubKey);
		new RAMFreenetStore<>(this.sskDatastore, (int) Math.min(Integer.MAX_VALUE, this.maxStoreKeys));
		this.sskDatacache = new SSKStore(this.getPubKey);
		new RAMFreenetStore<>(this.sskDatacache, (int) Math.min(Integer.MAX_VALUE, this.maxCacheKeys));
	}

	private long cachingFreenetStoreMaxSize;

	private long cachingFreenetStorePeriod;

	private CachingFreenetStoreTracker cachingFreenetStoreTracker;

	private void initSaltHashFS(final String suffix, boolean dontResizeOnStart, byte[] masterKey)
			throws NodeInitException {
		try {
			final CHKStore chkDatastore = new CHKStore();
			final FreenetStore<CHKBlock> chkDataFS = this.makeStore("CHK", true, chkDatastore, dontResizeOnStart,
					masterKey);
			final CHKStore chkDatacache = new CHKStore();
			final FreenetStore<CHKBlock> chkCacheFS = this.makeStore("CHK", false, chkDatacache, dontResizeOnStart,
					masterKey);
			((SaltedHashFreenetStore<CHKBlock>) chkCacheFS.getUnderlyingStore())
					.setAltStore(((SaltedHashFreenetStore<CHKBlock>) chkDataFS.getUnderlyingStore()));
			final PubkeyStore pubKeyDatastore = new PubkeyStore();
			final FreenetStore<StoreDSAPublicKey> pubkeyDataFS = this.makeStore("PUBKEY", true, pubKeyDatastore,
					dontResizeOnStart, masterKey);
			final PubkeyStore pubKeyDatacache = new PubkeyStore();
			final FreenetStore<StoreDSAPublicKey> pubkeyCacheFS = this.makeStore("PUBKEY", false, pubKeyDatacache,
					dontResizeOnStart, masterKey);
			((SaltedHashFreenetStore<StoreDSAPublicKey>) pubkeyCacheFS.getUnderlyingStore())
					.setAltStore(((SaltedHashFreenetStore<StoreDSAPublicKey>) pubkeyDataFS.getUnderlyingStore()));
			final SSKStore sskDatastore = new SSKStore(this.getPubKey);
			final FreenetStore<SSKBlock> sskDataFS = this.makeStore("SSK", true, sskDatastore, dontResizeOnStart,
					masterKey);
			final SSKStore sskDatacache = new SSKStore(this.getPubKey);
			final FreenetStore<SSKBlock> sskCacheFS = this.makeStore("SSK", false, sskDatacache, dontResizeOnStart,
					masterKey);
			((SaltedHashFreenetStore<SSKBlock>) sskCacheFS.getUnderlyingStore())
					.setAltStore(((SaltedHashFreenetStore<SSKBlock>) sskDataFS.getUnderlyingStore()));

			boolean delay = chkDataFS.start(this.ticker, false) | chkCacheFS.start(this.ticker, false)
					| pubkeyDataFS.start(this.ticker, false) | pubkeyCacheFS.start(this.ticker, false)
					| sskDataFS.start(this.ticker, false) | sskCacheFS.start(this.ticker, false);

			if (delay) {

				System.err.println("Delayed init of datastore");

				this.initRAMFS();

				final Runnable migrate = new MigrateOldStoreData(false);

				this.getTicker().queueTimedJob(new Runnable() {

					@Override
					public void run() {
						System.err.println("Starting delayed init of datastore");
						try {
							chkDataFS.start(Node.this.ticker, true);
							chkCacheFS.start(Node.this.ticker, true);
							pubkeyDataFS.start(Node.this.ticker, true);
							pubkeyCacheFS.start(Node.this.ticker, true);
							sskDataFS.start(Node.this.ticker, true);
							sskCacheFS.start(Node.this.ticker, true);
						}
						catch (IOException ex) {
							Logger.error(this, "Failed to start datastore: " + ex, ex);
							System.err.println("Failed to start datastore: " + ex);
							ex.printStackTrace();
							return;
						}

						Node.this.chkDatastore = chkDatastore;
						Node.this.chkDatacache = chkDatacache;
						Node.this.pubKeyDatastore = pubKeyDatastore;
						Node.this.pubKeyDatacache = pubKeyDatacache;
						Node.this.getPubKey.setDataStore(pubKeyDatastore, pubKeyDatacache);
						Node.this.sskDatastore = sskDatastore;
						Node.this.sskDatacache = sskDatacache;

						Node.this.finishInitSaltHashFS(suffix, Node.this.clientCore);

						System.err.println("Finishing delayed init of datastore");
						migrate.run();
					}

				}, "Start store", 0, true, false); // Use Ticker to guarantee that this
													// runs *after* constructors have
													// completed.

			}
			else {

				Node.this.chkDatastore = chkDatastore;
				Node.this.chkDatacache = chkDatacache;
				Node.this.pubKeyDatastore = pubKeyDatastore;
				Node.this.pubKeyDatacache = pubKeyDatacache;
				this.getPubKey.setDataStore(pubKeyDatastore, pubKeyDatacache);
				Node.this.sskDatastore = sskDatastore;
				Node.this.sskDatacache = sskDatacache;

				this.getTicker().queueTimedJob(new Runnable() {

					@Override
					public void run() {
						Node.this.chkDatastore = chkDatastore;
						Node.this.chkDatacache = chkDatacache;
						Node.this.pubKeyDatastore = pubKeyDatastore;
						Node.this.pubKeyDatacache = pubKeyDatacache;
						Node.this.getPubKey.setDataStore(pubKeyDatastore, pubKeyDatacache);
						Node.this.sskDatastore = sskDatastore;
						Node.this.sskDatacache = sskDatacache;

						Node.this.finishInitSaltHashFS(suffix, Node.this.clientCore);
					}

				}, "Start store", 0, true, false);
			}

		}
		catch (IOException ex) {
			System.err.println("Could not open store: " + ex);
			ex.printStackTrace();
			throw new NodeInitException(NodeInitException.EXIT_STORE_OTHER, ex.getMessage());
		}
	}

	private void initSaltHashClientCacheFS(final String suffix, boolean dontResizeOnStart, byte[] clientCacheMasterKey)
			throws NodeInitException {

		try {
			final CHKStore chkClientcache = new CHKStore();
			final FreenetStore<CHKBlock> chkDataFS = this.makeClientcache("CHK", true, chkClientcache,
					dontResizeOnStart, clientCacheMasterKey);
			final PubkeyStore pubKeyClientcache = new PubkeyStore();
			final FreenetStore<StoreDSAPublicKey> pubkeyDataFS = this.makeClientcache("PUBKEY", true, pubKeyClientcache,
					dontResizeOnStart, clientCacheMasterKey);
			final SSKStore sskClientcache = new SSKStore(this.getPubKey);
			final FreenetStore<SSKBlock> sskDataFS = this.makeClientcache("SSK", true, sskClientcache,
					dontResizeOnStart, clientCacheMasterKey);

			boolean delay = chkDataFS.start(this.ticker, false) | pubkeyDataFS.start(this.ticker, false)
					| sskDataFS.start(this.ticker, false);

			if (delay) {

				System.err.println("Delayed init of client-cache");

				this.initRAMClientCacheFS();

				final Runnable migrate = new MigrateOldStoreData(true);

				this.getTicker().queueTimedJob(new Runnable() {

					@Override
					public void run() {
						System.err.println("Starting delayed init of client-cache");
						try {
							chkDataFS.start(Node.this.ticker, true);
							pubkeyDataFS.start(Node.this.ticker, true);
							sskDataFS.start(Node.this.ticker, true);
						}
						catch (IOException ex) {
							Logger.error(this, "Failed to start client-cache: " + ex, ex);
							System.err.println("Failed to start client-cache: " + ex);
							ex.printStackTrace();
							return;
						}
						Node.this.chkClientcache = chkClientcache;
						Node.this.pubKeyClientcache = pubKeyClientcache;
						Node.this.getPubKey.setLocalDataStore(pubKeyClientcache);
						Node.this.sskClientcache = sskClientcache;

						System.err.println("Finishing delayed init of client-cache");
						migrate.run();
					}
				}, "Migrate store", 0, true, false);
			}
			else {
				Node.this.chkClientcache = chkClientcache;
				Node.this.pubKeyClientcache = pubKeyClientcache;
				this.getPubKey.setLocalDataStore(pubKeyClientcache);
				Node.this.sskClientcache = sskClientcache;
			}

		}
		catch (IOException ex) {
			System.err.println("Could not open store: " + ex);
			ex.printStackTrace();
			throw new NodeInitException(NodeInitException.EXIT_STORE_OTHER, ex.getMessage());
		}
	}

	private <T extends StorableBlock> FreenetStore<T> makeClientcache(String type, boolean isStore, StoreCallback<T> cb,
			boolean dontResizeOnStart, byte[] clientCacheMasterKey) throws IOException {
		return this.makeStore(type, "clientcache", this.maxClientCacheKeys, cb, dontResizeOnStart,
				clientCacheMasterKey);
	}

	private <T extends StorableBlock> FreenetStore<T> makeStore(String type, boolean isStore, StoreCallback<T> cb,
			boolean dontResizeOnStart, byte[] clientCacheMasterKey) throws IOException {
		String store = isStore ? "store" : "cache";
		long maxKeys = isStore ? this.maxStoreKeys : this.maxCacheKeys;
		return this.makeStore(type, store, maxKeys, cb, dontResizeOnStart, clientCacheMasterKey);
	}

	private <T extends StorableBlock> FreenetStore<T> makeStore(String type, String store, long maxKeys,
			StoreCallback<T> cb, boolean lateStart, byte[] clientCacheMasterKey) throws IOException {
		Logger.normal(this, "Initializing " + type + " Data" + store);
		System.out.println("Initializing " + type + " Data" + store + " (" + this.maxStoreKeys + " keys)");

		SaltedHashFreenetStore<T> fs = SaltedHashFreenetStore.construct(this.getStoreDir(), type + "-" + store, cb,
				this.random, maxKeys, this.storeUseSlotFilters, this.shutdownHook, this.storePreallocate,
				this.storeSaltHashResizeOnStart && !lateStart, lateStart ? this.ticker : null, clientCacheMasterKey);
		cb.setStore(fs);
		if (this.cachingFreenetStoreMaxSize > 0) {
			return new CachingFreenetStore<>(cb, fs, this.cachingFreenetStoreTracker);
		}
		else {
			return fs;
		}
	}

	public void start(boolean noSwaps) throws NodeInitException {

		// IMPORTANT: Read the peers only after we have finished initializing Node.
		// Peer constructors are complex and can call methods on Node.
		this.peers.tryReadPeers(this.nodeDir.file("peers-" + this.getDarknetPortNumber()).getPath(), this.darknetCrypto,
				null, false, false);
		this.peers.updatePMUserAlert();

		this.dispatcher.start(this.nodeStats); // must be before usm
		this.dnsr.start();
		this.peers.start(); // must be before usm
		this.nodeStats.start();
		this.uptime.start();
		this.failureTable.start();

		this.darknetCrypto.start();
		if (this.opennet != null) {
			this.opennet.start();
		}
		this.ps.start(this.nodeStats);
		this.ticker.start();
		this.scheduleVersionTransition();
		this.usm.start(this.ticker);

		if (this.isUsingWrapper()) {
			Logger.normal(this, "Using wrapper correctly: " + nodeStarter);
			System.out.println("Using wrapper correctly: " + nodeStarter);
		}
		else {
			Logger.error(this,
					"NOT using wrapper (at least not correctly).  Your freenet-ext.jar <http://downloads.freenetproject.org/alpha/freenet-ext.jar> and/or wrapper.conf <https://emu.freenetproject.org/svn/trunk/apps/installer/installclasspath/config/wrapper.conf> need to be updated.");
			System.out.println(
					"NOT using wrapper (at least not correctly).  Your freenet-ext.jar <http://downloads.freenetproject.org/alpha/freenet-ext.jar> and/or wrapper.conf <https://emu.freenetproject.org/svn/trunk/apps/installer/installclasspath/config/wrapper.conf> need to be updated.");
		}
		Logger.normal(this, "Freenet 0.7.5 Build #" + Version.buildNumber() + " r" + Version.cvsRevision());
		System.out.println("Freenet 0.7.5 Build #" + Version.buildNumber() + " r" + Version.cvsRevision());
		Logger.normal(this, "FNP port is on " + this.darknetCrypto.getBindTo() + ':' + this.getDarknetPortNumber());
		System.out.println("FNP port is on " + this.darknetCrypto.getBindTo() + ':' + this.getDarknetPortNumber());
		// Start services

		// SubConfig pluginManagerConfig = new SubConfig("pluginmanager3", config);
		// pluginManager3 = new freenet.plugin_new.PluginManager(pluginManagerConfig);

		this.ipDetector.start();

		// Start sending swaps
		this.lm.start();

		// Node Updater
		try {
			Logger.normal(this, "Starting the node updater");
			this.nodeUpdater.start();
		}
		catch (Exception ex) {
			ex.printStackTrace();
			throw new NodeInitException(NodeInitException.EXIT_COULD_NOT_START_UPDATER,
					"Could not start Updater: " + ex);
		}

		/*
		 * TODO: Make sure that this is called BEFORE any instances of HTTPFilter are
		 * created. HTTPFilter uses checkForGCJCharConversionBug() which returns the value
		 * of the static variable jvmHasGCJCharConversionBug - and this is initialized in
		 * the following function. If this is not possible then create a separate function
		 * to check for the GCJ bug and call this function earlier.
		 */
		this.checkForEvilJVMBugs();

		if (!NativeThread.HAS_ENOUGH_NICE_LEVELS) {
			this.clientCore.alerts.register(new NotEnoughNiceLevelsUserAlert());
		}

		this.clientCore.start(this.config);

		this.tracker.startDeadUIDChecker();

		// After everything has been created, write the config file back to disk.
		if (this.config instanceof FreenetFilePersistentConfig cfg) {
			cfg.finishedInit(this.ticker);
			cfg.setHasNodeStarted();
		}
		this.config.store();

		// Process any data in the extra peer data directory
		this.peers.readExtraPeerData();

		if (this.enableNodeDiagnostics) {
			this.nodeDiagnostics.start();
		}

		Logger.normal(this, "Started node");

		this.hasStarted = true;
	}

	private void scheduleVersionTransition() {
		long now = System.currentTimeMillis();
		long transition = Version.transitionTime();
		if (now < transition) {
			this.ticker.queueTimedJob(new Runnable() {

				@Override
				public void run() {
					freenet.support.Logger.OSThread.logPID(this);
					for (PeerNode pn : Node.this.peers.myPeers()) {
						pn.updateVersionRoutablity();
					}
				}
			}, transition - now);
		}
	}

	private static boolean jvmHasGCJCharConversionBug = false;

	private void checkForEvilJVMBugs() {
		// Now check whether we are likely to get the EvilJVMBug.
		// If we are running a Sun/Oracle or Blackdown JVM, on Linux, and LD_ASSUME_KERNEL
		// is not set, then we are.

		String jvmVendor = System.getProperty("java.vm.vendor");
		String jvmSpecVendor = System.getProperty("java.specification.vendor", "");
		String javaVersion = System.getProperty("java.version");
		String jvmName = System.getProperty("java.vm.name");
		String osName = System.getProperty("os.name");
		String osVersion = System.getProperty("os.version");

		boolean isOpenJDK = false;
		// boolean isOracle = false;

		if (logMINOR) {
			Logger.minor(this, "JVM vendor: " + jvmVendor + ", JVM name: " + jvmName + ", JVM version: " + javaVersion
					+ ", OS name: " + osName + ", OS version: " + osVersion);
		}

		if (jvmName.startsWith("OpenJDK ")) {
			isOpenJDK = true;
		}

		// Add some checks for "Oracle" to futureproof against them renaming from "Sun".
		// Should have no effect because if a user has downloaded a new enough file for
		// Oracle to have changed the name these bugs shouldn't apply.
		// Still, one never knows and this code might be extended to cover future bugs.
		if ((!isOpenJDK) && (jvmVendor.startsWith("Sun ") || jvmVendor.startsWith("Oracle "))
				|| (jvmVendor.startsWith("The FreeBSD Foundation")
						&& (jvmSpecVendor.startsWith("Sun ") || jvmSpecVendor.startsWith("Oracle ")))
				|| (jvmVendor.startsWith("Apple "))) {
			// isOracle = true;
			// Sun/Oracle bugs

			// Spurious OOMs
			// http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=4855795
			// http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=2138757
			// http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=2138759
			// Fixed in 1.5.0_10 and 1.4.2_13

			boolean is150 = javaVersion.startsWith("1.5.0_");
			boolean is160 = javaVersion.startsWith("1.6.0_");

			if (is150 || is160) {
				String[] split = javaVersion.split("_");
				String secondPart = split[1];
				if (secondPart.contains("-")) {
					split = secondPart.split("-");
					secondPart = split[0];
				}
				int subver = Integer.parseInt(secondPart);

				Logger.minor(this, "JVM version: " + javaVersion + " subver: " + subver + " from " + secondPart);

			}

		}
		else if (jvmVendor.startsWith("Apple ") || jvmVendor.startsWith("\"Apple ")) {
			// Note that Sun/Oracle does not produce VMs for the Macintosh operating
			// system, dont ask the user to find one...
		}
		else if (!isOpenJDK) {
			if (jvmVendor.startsWith("Free Software Foundation")) {
				// GCJ/GIJ.
				try {
					javaVersion = System.getProperty("java.version").split(" ")[0].replaceAll("[.]", "");
					int jvmVersionInt = Integer.parseInt(javaVersion);

					// make sure that no bogus values cause true
					if (jvmVersionInt <= 422 && jvmVersionInt >= 100) {
						jvmHasGCJCharConversionBug = true;
					}
				}

				catch (Throwable ex) {
					Logger.error(this, "GCJ version check is broken!", ex);
				}
				this.clientCore.alerts.register(new SimpleUserAlert(true, this.l10n("usingGCJTitle"),
						this.l10n("usingGCJ"), this.l10n("usingGCJTitle"), FCPUserAlert.WARNING));
			}
		}

		if (!this.isUsingWrapper() && !this.skipWrapperWarning) {
			this.clientCore.alerts.register(new SimpleUserAlert(true, this.l10n("notUsingWrapperTitle"),
					this.l10n("notUsingWrapper"), this.l10n("notUsingWrapperShort"), FCPUserAlert.WARNING));
		}

		// Unfortunately debian's version of OpenJDK appears to have segfaulting issues.
		// Which presumably are exploitable.
		// So we can't recommend people switch just yet. :(

		// if(isOracle && Rijndael.AesCtrProvider == null) {
		// if(!(FileUtil.detectedOS == FileUtil.OperatingSystem.Windows ||
		// FileUtil.detectedOS == FileUtil.OperatingSystem.MacOS))
		// clientCore.alerts.register(new SimpleUserAlert(true, l10n("usingOracleTitle"),
		// l10n("usingOracle"), l10n("usingOracleTitle"), UserAlert.WARNING));
		// }
	}

	public static boolean checkForGCJCharConversionBug() {
		return jvmHasGCJCharConversionBug; // should be initialized on early startup
	}

	private String l10n(String key) {
		return NodeL10n.getBase().getString("Node." + key);
	}

	private String l10n(String key, String pattern, String value) {
		return NodeL10n.getBase().getString("Node." + key, pattern, value);
	}

	private String l10n(String key, String[] pattern, String[] value) {
		return NodeL10n.getBase().getString("Node." + key, pattern, value);
	}

	/**
	 * Export volatile data about the node as a SimpleFieldSet
	 */
	public SimpleFieldSet exportVolatileFieldSet() {
		return this.nodeStats.exportVolatileFieldSet();
	}

	/**
	 * Do a routed ping of another node on the network by its location.
	 * @param loc2 The location of the other node to ping. It must match exactly.
	 * @param pubKeyHash The hash of the pubkey of the target node. We match by location;
	 * this is just a shortcut if we get close.
	 * @return The number of hops it took to find the node, if it was found. Otherwise -1.
	 */
	public int routedPing(double loc2, byte[] pubKeyHash) {
		long uid = this.random.nextLong();
		int initialX = this.random.nextInt();
		Message m = DMT.createFNPRoutedPing(uid, loc2, this.maxHTL, initialX, pubKeyHash);
		Logger.normal(this, "Message: " + m);

		this.dispatcher.handleRouted(m, null);
		// FIXME: might be rejected
		MessageFilter mf1 = MessageFilter.create().setField(DMT.UID, uid).setType(DMT.FNPRoutedPong).setTimeout(5000);
		try {
			// MessageFilter mf2 = MessageFilter.create().setField(DMT.UID,
			// uid).setType(DMT.FNPRoutedRejected).setTimeout(5000);
			// Ignore Rejected - let it be retried on other peers
			m = this.usm.waitFor(mf1/* .or(mf2) */, null);
		}
		catch (DisconnectedException ignored) {
			Logger.normal(this, "Disconnected in waiting for pong");
			return -1;
		}
		if (m == null) {
			return -1;
		}
		if (m.getSpec() == DMT.FNPRoutedRejected) {
			return -1;
		}
		return m.getInt(DMT.COUNTER) - initialX;
	}

	/**
	 * Look for a block in the datastore, as part of a request.
	 * @param key The key to fetch.
	 * @param uid The UID of the request (for logging only).
	 * @param canReadClientCache If the request is local, we can read the client cache.
	 * @param canWriteClientCache If the request is local, and the client hasn't turned
	 * off writing to the client cache, we can write to the client cache.
	 * @param canWriteDatastore If the request HTL is too high, including if it is local,
	 * we cannot write to the datastore.
	 * @return A KeyBlock for the key requested or null.
	 */
	private KeyBlock makeRequestLocal(Key key, long uid, boolean canReadClientCache, boolean canWriteClientCache,
			boolean canWriteDatastore, boolean offersOnly) {
		KeyBlock kb = null;

		if (key instanceof NodeCHK) {
			kb = this.fetch(key, false, canReadClientCache, canWriteClientCache, canWriteDatastore, null);
		}
		else if (key instanceof NodeSSK sskKey) {
			DSAPublicKey pubKey = sskKey.getPubKey();
			if (pubKey == null) {
				pubKey = this.getPubKey.getKey(sskKey.getPubKeyHash(), canReadClientCache, offersOnly, null);
				if (logMINOR) {
					Logger.minor(this, "Fetched pubkey: " + pubKey);
				}
				try {
					sskKey.setPubKey(pubKey);
				}
				catch (SSKVerifyException ex) {
					Logger.error(this, "Error setting pubkey: " + ex, ex);
				}
			}
			if (pubKey != null) {
				if (logMINOR) {
					Logger.minor(this, "Got pubkey: " + pubKey);
				}
				kb = this.fetch(sskKey, canReadClientCache, canWriteClientCache, canWriteDatastore, false, null);
			}
			else {
				if (logMINOR) {
					Logger.minor(this, "Not found because no pubkey: " + uid);
				}
			}
		}
		else {
			throw new IllegalStateException("Unknown key type: " + key.getClass());
		}

		if (kb != null) {
			// Probably somebody waiting for it. Trip it.
			if (this.clientCore != null && this.clientCore.requestStarters != null) {
				if (kb instanceof CHKBlock) {
					this.clientCore.requestStarters.chkFetchSchedulerBulk.tripPendingKey(kb);
					this.clientCore.requestStarters.chkFetchSchedulerRT.tripPendingKey(kb);
				}
				else {
					this.clientCore.requestStarters.sskFetchSchedulerBulk.tripPendingKey(kb);
					this.clientCore.requestStarters.sskFetchSchedulerRT.tripPendingKey(kb);
				}
			}
			this.failureTable.onFound(kb);
			return kb;
		}

		return null;
	}

	/**
	 * Check the datastore, then if the key is not in the store, check whether another
	 * node is requesting the same key at the same HTL, and if all else fails, create a
	 * new RequestSender for the key/htl.
	 * @param localOnly If true, only check the datastore.
	 * @return A KeyBlock if the data is in the store, otherwise a RequestSender, unless
	 * the HTL is 0, in which case NULL. RequestSender.
	 */
	public Object makeRequestSender(Key key, short htl, long uid, RequestTag tag, PeerNode source, boolean localOnly,
			boolean ignoreStore, boolean offersOnly, boolean canReadClientCache, boolean canWriteClientCache,
			boolean realTimeFlag) {
		boolean canWriteDatastore = this.canWriteDatastoreRequest(htl);
		if (logMINOR) {
			Logger.minor(this, "makeRequestSender(" + key + ',' + htl + ',' + uid + ',' + source + ") on "
					+ this.getDarknetPortNumber());
		}
		// In store?
		if (!ignoreStore) {
			KeyBlock kb = this.makeRequestLocal(key, uid, canReadClientCache, canWriteClientCache, canWriteDatastore,
					offersOnly);
			if (kb != null) {
				return kb;
			}
		}
		if (localOnly) {
			return null;
		}
		if (logMINOR) {
			Logger.minor(this, "Not in store locally");
		}

		// Transfer coalescing - match key only as HTL irrelevant
		RequestSender sender = (key instanceof NodeCHK)
				? this.tracker.getTransferringRequestSenderByKey((NodeCHK) key, realTimeFlag) : null;
		if (sender != null) {
			if (logMINOR) {
				Logger.minor(this, "Data already being transferred: " + sender);
			}
			sender.setTransferCoalesced();
			tag.setSender(sender, true);
			return sender;
		}

		// HTL == 0 => Don't search further
		if (htl == 0) {
			if (logMINOR) {
				Logger.minor(this, "No HTL");
			}
			return null;
		}

		sender = new RequestSender(key, null, htl, uid, tag, this, source, offersOnly, canWriteClientCache,
				canWriteDatastore, realTimeFlag);
		tag.setSender(sender, false);
		sender.start();
		if (logMINOR) {
			Logger.minor(this, "Created new sender: " + sender);
		}
		return sender;
	}

	/**
	 * Can we write to the datastore for a given request? We do not write to the datastore
	 * until 2 hops below maximum. This is an average of 4 hops from the originator. Thus,
	 * data returned from local requests is never cached, finally solving The Register's
	 * attack, Bloom filter sharing doesn't give away your local requests and inserts, and
	 * *anything starting at high HTL* is not cached, including stuff from other nodes
	 * which hasn't been decremented far enough yet, so it's not ONLY local requests that
	 * don't get cached.
	 */
	boolean canWriteDatastoreRequest(short htl) {
		return htl <= (this.maxHTL - 2);
	}

	/**
	 * Can we write to the datastore for a given insert? We do not write to the datastore
	 * until 3 hops below maximum. This is an average of 5 hops from the originator. Thus,
	 * data sent by local inserts is never cached, finally solving The Register's attack,
	 * Bloom filter sharing doesn't give away your local requests and inserts, and
	 * *anything starting at high HTL* is not cached, including stuff from other nodes
	 * which hasn't been decremented far enough yet, so it's not ONLY local inserts that
	 * don't get cached.
	 */
	boolean canWriteDatastoreInsert(short htl) {
		return htl <= (this.maxHTL - 3);
	}

	/**
	 * Fetch a block from the datastore.
	 * @param key
	 * @param canReadClientCache
	 * @param canWriteClientCache
	 * @param canWriteDatastore
	 * @param forULPR
	 */
	public KeyBlock fetch(Key key, boolean canReadClientCache, boolean canWriteClientCache, boolean canWriteDatastore,
			boolean forULPR, BlockMetadata meta) {
		if (key instanceof NodeSSK) {
			return this.fetch((NodeSSK) key, false, canReadClientCache, canWriteClientCache, canWriteDatastore, forULPR,
					meta);
		}
		else if (key instanceof NodeCHK) {
			return this.fetch((NodeCHK) key, false, canReadClientCache, canWriteClientCache, canWriteDatastore, forULPR,
					meta);
		}
		else {
			throw new IllegalArgumentException();
		}
	}

	public SSKBlock fetch(NodeSSK key, boolean dontPromote, boolean canReadClientCache, boolean canWriteClientCache,
			boolean canWriteDatastore, boolean forULPR, BlockMetadata meta) {
		double loc = key.toNormalizedDouble();
		double dist = Location.distance(this.lm.getLocation(), loc);
		if (canReadClientCache) {
			try {
				SSKBlock block = this.sskClientcache.fetch(key, dontPromote || !canWriteClientCache, canReadClientCache,
						forULPR, false, meta);
				if (block != null) {
					this.nodeStats.avgClientCacheSSKSuccess.report(loc);
					if (dist > this.nodeStats.furthestClientCacheSSKSuccess) {
						this.nodeStats.furthestClientCacheSSKSuccess = dist;
					}
					if (logDEBUG) {
						Logger.debug(this, "Found key " + key + " in client-cache");
					}
					return block;
				}
			}
			catch (IOException ex) {
				Logger.error(this, "Could not read from client cache: " + ex, ex);
			}
		}
		if (forULPR || this.useSlashdotCache || canReadClientCache) {
			try {
				SSKBlock block = this.sskSlashdotcache.fetch(key, dontPromote, canReadClientCache, forULPR, false,
						meta);
				if (block != null) {
					this.nodeStats.avgSlashdotCacheSSKSuccess.report(loc);
					if (dist > this.nodeStats.furthestSlashdotCacheSSKSuccess) {
						this.nodeStats.furthestSlashdotCacheSSKSuccess = dist;
					}
					if (logDEBUG) {
						Logger.debug(this, "Found key " + key + " in slashdot-cache");
					}
					return block;
				}
			}
			catch (IOException ex) {
				Logger.error(this, "Could not read from slashdot/ULPR cache: " + ex, ex);
			}
		}
		boolean ignoreOldBlocks = !this.writeLocalToDatastore;
		if (canReadClientCache) {
			ignoreOldBlocks = false;
		}
		if (logMINOR) {
			this.dumpStoreHits();
		}
		try {

			this.nodeStats.avgRequestLocation.report(loc);
			SSKBlock block = this.sskDatastore.fetch(key, dontPromote || !canWriteDatastore, canReadClientCache,
					forULPR, ignoreOldBlocks, meta);
			if (block == null) {
				SSKStore store = this.oldSSK;
				if (store != null) {
					block = store.fetch(key, dontPromote || !canWriteDatastore, canReadClientCache, forULPR,
							ignoreOldBlocks, meta);
				}
			}
			if (block != null) {
				this.nodeStats.avgStoreSSKSuccess.report(loc);
				if (dist > this.nodeStats.furthestStoreSSKSuccess) {
					this.nodeStats.furthestStoreSSKSuccess = dist;
				}
				if (logDEBUG) {
					Logger.debug(this, "Found key " + key + " in store");
				}
				return block;
			}
			block = this.sskDatacache.fetch(key, dontPromote || !canWriteDatastore, canReadClientCache, forULPR,
					ignoreOldBlocks, meta);
			if (block == null) {
				SSKStore store = this.oldSSKCache;
				if (store != null) {
					block = store.fetch(key, dontPromote || !canWriteDatastore, canReadClientCache, forULPR,
							ignoreOldBlocks, meta);
				}
			}
			if (block != null) {
				this.nodeStats.avgCacheSSKSuccess.report(loc);
				if (dist > this.nodeStats.furthestCacheSSKSuccess) {
					this.nodeStats.furthestCacheSSKSuccess = dist;
				}
				if (logDEBUG) {
					Logger.debug(this, "Found key " + key + " in cache");
				}
			}
			return block;
		}
		catch (IOException ex) {
			Logger.error(this, "Cannot fetch data: " + ex, ex);
			return null;
		}
	}

	public CHKBlock fetch(NodeCHK key, boolean dontPromote, boolean canReadClientCache, boolean canWriteClientCache,
			boolean canWriteDatastore, boolean forULPR, BlockMetadata meta) {
		double loc = key.toNormalizedDouble();
		double dist = Location.distance(this.lm.getLocation(), loc);
		if (canReadClientCache) {
			try {
				CHKBlock block = this.chkClientcache.fetch(key, dontPromote || !canWriteClientCache, false, meta);
				if (block != null) {
					this.nodeStats.avgClientCacheCHKSuccess.report(loc);
					if (dist > this.nodeStats.furthestClientCacheCHKSuccess) {
						this.nodeStats.furthestClientCacheCHKSuccess = dist;
					}
					return block;
				}
			}
			catch (IOException ex) {
				Logger.error(this, "Could not read from client cache: " + ex, ex);
			}
		}
		if (forULPR || this.useSlashdotCache || canReadClientCache) {
			try {
				CHKBlock block = this.chkSlashdotcache.fetch(key, dontPromote, false, meta);
				if (block != null) {
					this.nodeStats.avgSlashdotCacheCHKSucess.report(loc);
					if (dist > this.nodeStats.furthestSlashdotCacheCHKSuccess) {
						this.nodeStats.furthestSlashdotCacheCHKSuccess = dist;
					}
					return block;
				}
			}
			catch (IOException ex) {
				Logger.error(this, "Could not read from slashdot/ULPR cache: " + ex, ex);
			}
		}
		boolean ignoreOldBlocks = !this.writeLocalToDatastore;
		if (canReadClientCache) {
			ignoreOldBlocks = false;
		}
		if (logMINOR) {
			this.dumpStoreHits();
		}
		try {
			this.nodeStats.avgRequestLocation.report(loc);
			CHKBlock block = this.chkDatastore.fetch(key, dontPromote || !canWriteDatastore, ignoreOldBlocks, meta);
			if (block == null) {
				CHKStore store = this.oldCHK;
				if (store != null) {
					block = store.fetch(key, dontPromote || !canWriteDatastore, ignoreOldBlocks, meta);
				}
			}
			if (block != null) {
				this.nodeStats.avgStoreCHKSuccess.report(loc);
				if (dist > this.nodeStats.furthestStoreCHKSuccess) {
					this.nodeStats.furthestStoreCHKSuccess = dist;
				}
				return block;
			}
			block = this.chkDatacache.fetch(key, dontPromote || !canWriteDatastore, ignoreOldBlocks, meta);
			if (block == null) {
				CHKStore store = this.oldCHKCache;
				if (store != null) {
					block = store.fetch(key, dontPromote || !canWriteDatastore, ignoreOldBlocks, meta);
				}
			}
			if (block != null) {
				this.nodeStats.avgCacheCHKSuccess.report(loc);
				if (dist > this.nodeStats.furthestCacheCHKSuccess) {
					this.nodeStats.furthestCacheCHKSuccess = dist;
				}
			}
			return block;
		}
		catch (IOException ex) {
			Logger.error(this, "Cannot fetch data: " + ex, ex);
			return null;
		}
	}

	CHKStore getChkDatacache() {
		return this.chkDatacache;
	}

	CHKStore getChkDatastore() {
		return this.chkDatastore;
	}

	SSKStore getSskDatacache() {
		return this.sskDatacache;
	}

	SSKStore getSskDatastore() {
		return this.sskDatastore;
	}

	CHKStore getChkSlashdotCache() {
		return this.chkSlashdotcache;
	}

	CHKStore getChkClientCache() {
		return this.chkClientcache;
	}

	SSKStore getSskSlashdotCache() {
		return this.sskSlashdotcache;
	}

	SSKStore getSskClientCache() {
		return this.sskClientcache;
	}

	/**
	 * This method returns all statistics info for our data store stats table
	 * @return map that has an entry for each data store instance type and corresponding
	 * stats
	 */
	public Map<DataStoreInstanceType, DataStoreStats> getDataStoreStats() {
		Map<DataStoreInstanceType, DataStoreStats> map = new LinkedHashMap<>();

		map.put(new DataStoreInstanceType(DataStoreKeyType.CHK, DataStoreType.STORE),
				new StoreCallbackStats(this.chkDatastore, this.nodeStats.chkStoreStats()));
		map.put(new DataStoreInstanceType(DataStoreKeyType.CHK, DataStoreType.CACHE),
				new StoreCallbackStats(this.chkDatacache, this.nodeStats.chkCacheStats()));
		map.put(new DataStoreInstanceType(DataStoreKeyType.CHK, DataStoreType.SLASHDOT),
				new StoreCallbackStats(this.chkSlashdotcache, this.nodeStats.chkSlashDotCacheStats()));
		map.put(new DataStoreInstanceType(DataStoreKeyType.CHK, DataStoreType.CLIENT),
				new StoreCallbackStats(this.chkClientcache, this.nodeStats.chkClientCacheStats()));

		map.put(new DataStoreInstanceType(DataStoreKeyType.SSK, DataStoreType.STORE),
				new StoreCallbackStats(this.sskDatastore, this.nodeStats.sskStoreStats()));
		map.put(new DataStoreInstanceType(DataStoreKeyType.SSK, DataStoreType.CACHE),
				new StoreCallbackStats(this.sskDatacache, this.nodeStats.sskCacheStats()));
		map.put(new DataStoreInstanceType(DataStoreKeyType.SSK, DataStoreType.SLASHDOT),
				new StoreCallbackStats(this.sskSlashdotcache, this.nodeStats.sskSlashDotCacheStats()));
		map.put(new DataStoreInstanceType(DataStoreKeyType.SSK, DataStoreType.CLIENT),
				new StoreCallbackStats(this.sskClientcache, this.nodeStats.sskClientCacheStats()));

		map.put(new DataStoreInstanceType(DataStoreKeyType.PUB_KEY, DataStoreType.STORE),
				new StoreCallbackStats(this.pubKeyDatastore, new NotAvailNodeStoreStats()));
		map.put(new DataStoreInstanceType(DataStoreKeyType.PUB_KEY, DataStoreType.CACHE),
				new StoreCallbackStats(this.pubKeyDatacache, new NotAvailNodeStoreStats()));
		map.put(new DataStoreInstanceType(DataStoreKeyType.PUB_KEY, DataStoreType.SLASHDOT),
				new StoreCallbackStats(this.pubKeySlashdotcache, new NotAvailNodeStoreStats()));
		map.put(new DataStoreInstanceType(DataStoreKeyType.PUB_KEY, DataStoreType.CLIENT),
				new StoreCallbackStats(this.pubKeyClientcache, new NotAvailNodeStoreStats()));

		return map;
	}

	public long getMaxTotalKeys() {
		return this.maxTotalKeys;
	}

	long timeLastDumpedHits;

	public void dumpStoreHits() {
		long now = System.currentTimeMillis();
		if (now - this.timeLastDumpedHits > 5000) {
			this.timeLastDumpedHits = now;
		}
		else {
			return;
		}
		Logger.minor(this,
				"Distribution of hits and misses over stores:\n" + "CHK Datastore: " + this.chkDatastore.hits() + '/'
						+ (this.chkDatastore.hits() + this.chkDatastore.misses()) + '/' + this.chkDatastore.keyCount()
						+ "\nCHK Datacache: " + this.chkDatacache.hits() + '/'
						+ (this.chkDatacache.hits() + this.chkDatacache.misses()) + '/' + this.chkDatacache.keyCount()
						+ "\nSSK Datastore: " + this.sskDatastore.hits() + '/'
						+ (this.sskDatastore.hits() + this.sskDatastore.misses()) + '/' + this.sskDatastore.keyCount()
						+ "\nSSK Datacache: " + this.sskDatacache.hits() + '/'
						+ (this.sskDatacache.hits() + this.sskDatacache.misses()) + '/' + this.sskDatacache.keyCount());
	}

	public void storeShallow(CHKBlock block, boolean canWriteClientCache, boolean canWriteDatastore, boolean forULPR) {
		this.store(block, false, canWriteClientCache, canWriteDatastore, forULPR);
	}

	/**
	 * Store a datum.
	 * @param block a KeyBlock
	 * @param deep If true, insert to the store as well as the cache. Do not set this to
	 * true unless the store results from an insert, and this node is the closest node to
	 * the target; see the description of chkDatastore.
	 */
	public void store(KeyBlock block, boolean deep, boolean canWriteClientCache, boolean canWriteDatastore,
			boolean forULPR) throws KeyCollisionException {
		if (block instanceof CHKBlock) {
			this.store((CHKBlock) block, deep, canWriteClientCache, canWriteDatastore, forULPR);
		}
		else if (block instanceof SSKBlock) {
			this.store((SSKBlock) block, deep, false, canWriteClientCache, canWriteDatastore, forULPR);
		}
		else {
			throw new IllegalArgumentException("Unknown keytype ");
		}
	}

	private void store(CHKBlock block, boolean deep, boolean canWriteClientCache, boolean canWriteDatastore,
			boolean forULPR) {
		try {
			double loc = block.getKey().toNormalizedDouble();
			if (canWriteClientCache) {
				this.chkClientcache.put(block, false);
				this.nodeStats.avgClientCacheCHKLocation.report(loc);
			}

			if ((forULPR || this.useSlashdotCache) && !(canWriteDatastore || this.writeLocalToDatastore)) {
				this.chkSlashdotcache.put(block, false);
				this.nodeStats.avgSlashdotCacheCHKLocation.report(loc);
			}
			if (canWriteDatastore || this.writeLocalToDatastore) {

				if (deep) {
					this.chkDatastore.put(block, !canWriteDatastore);
					this.nodeStats.avgStoreCHKLocation.report(loc);

				}
				this.chkDatacache.put(block, !canWriteDatastore);
				this.nodeStats.avgCacheCHKLocation.report(loc);
			}
			if (canWriteDatastore || forULPR || this.useSlashdotCache) {
				this.failureTable.onFound(block);
			}
		}
		catch (IOException ex) {
			Logger.error(this, "Cannot store data: " + ex, ex);
		}
		catch (Throwable ex) {
			System.err.println(ex);
			ex.printStackTrace();
			Logger.error(this, "Caught " + ex + " storing data", ex);
		}
		if (this.clientCore != null && this.clientCore.requestStarters != null) {
			this.clientCore.requestStarters.chkFetchSchedulerBulk.tripPendingKey(block);
			this.clientCore.requestStarters.chkFetchSchedulerRT.tripPendingKey(block);
		}
	}

	/** Store the block if this is a sink. Call for inserts. */
	public void storeInsert(SSKBlock block, boolean deep, boolean overwrite, boolean canWriteClientCache,
			boolean canWriteDatastore) throws KeyCollisionException {
		this.store(block, deep, overwrite, canWriteClientCache, canWriteDatastore, false);
	}

	/**
	 * Store only to the cache, and not the store. Called by requests, as only inserts
	 * cause data to be added to the store.
	 */
	public void storeShallow(SSKBlock block, boolean canWriteClientCache, boolean canWriteDatastore, boolean fromULPR)
			throws KeyCollisionException {
		this.store(block, false, canWriteClientCache, canWriteDatastore, fromULPR);
	}

	public void store(SSKBlock block, boolean deep, boolean overwrite, boolean canWriteClientCache,
			boolean canWriteDatastore, boolean forULPR) throws KeyCollisionException {
		try {
			// Store the pubkey before storing the data, otherwise we can get a race
			// condition and
			// end up deleting the SSK data.
			double loc = block.getKey().toNormalizedDouble();
			this.getPubKey.cacheKey((block.getKey()).getPubKeyHash(), (block.getKey()).getPubKey(), deep,
					canWriteClientCache, canWriteDatastore, forULPR || this.useSlashdotCache,
					this.writeLocalToDatastore);
			if (canWriteClientCache) {
				this.sskClientcache.put(block, overwrite, false);
				this.nodeStats.avgClientCacheSSKLocation.report(loc);
			}
			if ((forULPR || this.useSlashdotCache) && !(canWriteDatastore || this.writeLocalToDatastore)) {
				this.sskSlashdotcache.put(block, overwrite, false);
				this.nodeStats.avgSlashdotCacheSSKLocation.report(loc);
			}
			if (canWriteDatastore || this.writeLocalToDatastore) {
				if (deep) {
					this.sskDatastore.put(block, overwrite, !canWriteDatastore);
					this.nodeStats.avgStoreSSKLocation.report(loc);
				}
				this.sskDatacache.put(block, overwrite, !canWriteDatastore);
				this.nodeStats.avgCacheSSKLocation.report(loc);
			}
			if (canWriteDatastore || forULPR || this.useSlashdotCache) {
				this.failureTable.onFound(block);
			}
		}
		catch (IOException ex) {
			Logger.error(this, "Cannot store data: " + ex, ex);
		}
		catch (KeyCollisionException ex) {
			throw ex;
		}
		catch (Throwable ex) {
			System.err.println(ex);
			ex.printStackTrace();
			Logger.error(this, "Caught " + ex + " storing data", ex);
		}
		if (this.clientCore != null && this.clientCore.requestStarters != null) {
			this.clientCore.requestStarters.sskFetchSchedulerBulk.tripPendingKey(block);
			this.clientCore.requestStarters.sskFetchSchedulerRT.tripPendingKey(block);
		}
	}

	final boolean decrementAtMax;

	final boolean decrementAtMin;

	/**
	 * Decrement the HTL according to the policy of the given NodePeer if it is non-null,
	 * or do something else if it is null.
	 */
	public short decrementHTL(PeerNode source, short htl) {
		if (source != null) {
			return source.decrementHTL(htl);
		}
		// Otherwise...
		if (htl >= this.maxHTL) {
			htl = this.maxHTL;
		}
		if (htl <= 0) {
			return 0;
		}
		if (htl == this.maxHTL) {
			if (this.decrementAtMax || this.disableProbabilisticHTLs) {
				htl--;
			}
			return htl;
		}
		if (htl == 1) {
			if (this.decrementAtMin || this.disableProbabilisticHTLs) {
				htl--;
			}
			return htl;
		}
		return --htl;
	}

	/**
	 * Fetch or create an CHKInsertSender for a given key/htl.
	 * @param key The key to be inserted.
	 * @param htl The current HTL. We can't coalesce inserts across HTL's.
	 * @param uid The UID of the caller's request chain, or a new one. This is obviously
	 * not used if there is already an CHKInsertSender running.
	 * @param source The node that sent the InsertRequest, or null if it originated
	 * locally.
	 * @param ignoreLowBackoff
	 * @param preferInsert
	 */
	public CHKInsertSender makeInsertSender(NodeCHK key, short htl, long uid, InsertTag tag, PeerNode source,
			byte[] headers, PartiallyReceivedBlock prb, boolean fromStore, boolean canWriteClientCache,
			boolean forkOnCacheable, boolean preferInsert, boolean ignoreLowBackoff, boolean realTimeFlag) {
		if (logMINOR) {
			Logger.minor(this, "makeInsertSender(" + key + ',' + htl + ',' + uid + ',' + source + ",...," + fromStore);
		}
		CHKInsertSender is = new CHKInsertSender(key, uid, tag, headers, htl, source, this, prb, fromStore,
				canWriteClientCache, forkOnCacheable, preferInsert, ignoreLowBackoff, realTimeFlag);
		is.start();
		// CHKInsertSender adds itself to insertSenders
		return is;
	}

	/**
	 * Fetch or create an SSKInsertSender for a given key/htl.
	 * @param block The SSKBlock to be inserted.
	 * @param htl The current HTL. We can't coalesce inserts across HTL's.
	 * @param uid The UID of the caller's request chain, or a new one. This is obviously
	 * not used if there is already an SSKInsertSender running.
	 * @param source The node that sent the InsertRequest, or null if it originated
	 * locally.
	 * @param ignoreLowBackoff
	 * @param preferInsert
	 */
	public SSKInsertSender makeInsertSender(SSKBlock block, short htl, long uid, InsertTag tag, PeerNode source,
			boolean fromStore, boolean canWriteClientCache, boolean canWriteDatastore, boolean forkOnCacheable,
			boolean preferInsert, boolean ignoreLowBackoff, boolean realTimeFlag) {
		NodeSSK key = block.getKey();
		if (key.getPubKey() == null) {
			throw new IllegalArgumentException("No pub key when inserting");
		}

		this.getPubKey.cacheKey(key.getPubKeyHash(), key.getPubKey(), false, canWriteClientCache, canWriteDatastore,
				false, this.writeLocalToDatastore);
		Logger.minor(this, "makeInsertSender(" + key + ',' + htl + ',' + uid + ',' + source + ",...," + fromStore);
		SSKInsertSender is = new SSKInsertSender(block, uid, tag, htl, source, this, fromStore, canWriteClientCache,
				forkOnCacheable, preferInsert, ignoreLowBackoff, realTimeFlag);
		is.start();
		return is;
	}

	/**
	 * @return Some status information.
	 */
	public String getStatus() {
		StringBuilder sb = new StringBuilder();
		if (this.peers != null) {
			sb.append(this.peers.getStatus());
		}
		else {
			sb.append("No peers yet");
		}
		sb.append(this.tracker.getNumTransferringRequestSenders());
		sb.append('\n');
		return sb.toString();
	}

	/**
	 * @return TMCI peer list
	 */
	public String getTMCIPeerList() {
		StringBuilder sb = new StringBuilder();
		if (this.peers != null) {
			sb.append(this.peers.getTMCIPeerList());
		}
		else {
			sb.append("No peers yet");
		}
		return sb.toString();
	}

	/** Length of signature parameters R and S */
	static final int SIGNATURE_PARAMETER_LENGTH = 32;

	public ClientKeyBlock fetchKey(ClientKey key, boolean canReadClientCache, boolean canWriteClientCache,
			boolean canWriteDatastore) throws KeyVerifyException {
		if (key instanceof ClientCHK) {
			return this.fetch((ClientCHK) key, canReadClientCache, canWriteClientCache, canWriteDatastore);
		}
		else if (key instanceof ClientSSK) {
			return this.fetch((ClientSSK) key, canReadClientCache, canWriteClientCache, canWriteDatastore);
		}
		else {
			throw new IllegalStateException("Don't know what to do with " + key);
		}
	}

	public ClientKeyBlock fetch(ClientSSK clientSSK, boolean canReadClientCache, boolean canWriteClientCache,
			boolean canWriteDatastore) throws SSKVerifyException {
		DSAPublicKey key = clientSSK.getPubKey();
		if (key == null) {
			key = this.getPubKey.getKey(clientSSK.pubKeyHash, canReadClientCache, false, null);
		}
		if (key == null) {
			return null;
		}
		clientSSK.setPublicKey(key);
		SSKBlock block = this.fetch((NodeSSK) clientSSK.getNodeKey(true), false, canReadClientCache,
				canWriteClientCache, canWriteDatastore, false, null);
		if (block == null) {
			if (logMINOR) {
				Logger.minor(this, "Could not find key for " + clientSSK);
			}
			return null;
		}
		// Move the pubkey to the top of the LRU, and fix it if it
		// was corrupt.
		this.getPubKey.cacheKey(clientSSK.pubKeyHash, key, false, canWriteClientCache, canWriteDatastore, false,
				this.writeLocalToDatastore);
		return ClientSSKBlock.construct(block, clientSSK);
	}

	private ClientKeyBlock fetch(ClientCHK clientCHK, boolean canReadClientCache, boolean canWriteClientCache,
			boolean canWriteDatastore) throws CHKVerifyException {
		CHKBlock block = this.fetch(clientCHK.getNodeCHK(), false, canReadClientCache, canWriteClientCache,
				canWriteDatastore, false, null);
		if (block == null) {
			return null;
		}
		return new ClientCHKBlock(block, clientCHK);
	}

	public void exit(int reason) {
		try {
			this.park();
			System.out.println("Goodbye.");
			System.out.println(reason);
		}
		catch (Exception ignored) {

		}
		System.exit(reason);
	}

	public void exit(String reason) {
		try {
			this.park();
			System.out.println("Goodbye. from " + this + " (" + reason + ')');
		}
		catch (Exception ignored) {

		}
		System.exit(0);
	}

	/**
	 * Returns true if the node is shutting down. The packet receiver calls this for every
	 * packet, and boolean is atomic, so this method is not synchronized.
	 */
	public boolean isStopping() {
		return this.isStopping;
	}

	/**
	 * Get the node into a state where it can be stopped safely May be called twice - once
	 * in exit (above) and then again from the wrapper triggered by calling System.exit().
	 * Beware!
	 */
	public void park() {
		synchronized (this) {
			if (this.isStopping) {
				return;
			}
			this.isStopping = true;
		}

		try {
			Message msg = DMT.createFNPDisconnect(false, false, -1, new ShortBuffer(new byte[0]));
			this.peers.localBroadcast(msg, true, false, this.peers.ctrDisconn);
		}
		catch (Throwable ex) {
			try {
				// E.g. if we haven't finished startup
				Logger.error(this, "Failed to tell peers we are going down: " + ex, ex);
			}
			catch (Throwable ignored) {
				// Ignore. We don't want to mess up the exit process!
			}
		}

		this.config.store();

		if (this.random instanceof PersistentRandomSource) {
			((PersistentRandomSource) this.random).write_seed(true);
		}
	}

	public NodeUpdateManager getNodeUpdater() {
		return this.nodeUpdater;
	}

	public DarknetPeerNode[] getDarknetConnections() {
		return this.peers.getDarknetPeers();
	}

	public boolean addPeerConnection(PeerNode pn) {
		boolean retval = this.peers.addPeer(pn);
		this.peers.writePeersUrgent(pn.isOpennet());
		return retval;
	}

	public void removePeerConnection(PeerNode pn) {
		this.peers.disconnectAndRemove(pn, true, false, false);
	}

	public void onConnectedPeer() {
		if (logMINOR) {
			Logger.minor(this, "onConnectedPeer()");
		}
		this.ipDetector.onConnectedPeer();
	}

	public int getFNPPort() {
		return this.getDarknetPortNumber();
	}

	public boolean isOudated() {
		return this.peers.isOutdated();
	}

	private final Map<Integer, NodeToNodeMessageListener> n2nmListeners = new HashMap<>();

	public synchronized void registerNodeToNodeMessageListener(int type, NodeToNodeMessageListener listener) {
		this.n2nmListeners.put(type, listener);
	}

	/**
	 * Handle a received node to node message
	 */
	public void receivedNodeToNodeMessage(Message m, PeerNode src) {
		int type = (Integer) m.getObject(DMT.NODE_TO_NODE_MESSAGE_TYPE);
		ShortBuffer messageData = (ShortBuffer) m.getObject(DMT.NODE_TO_NODE_MESSAGE_DATA);
		this.receivedNodeToNodeMessage(src, type, messageData, false);
	}

	public void receivedNodeToNodeMessage(PeerNode src, int type, ShortBuffer messageData, boolean partingMessage) {
		boolean fromDarknet = src instanceof DarknetPeerNode;

		NodeToNodeMessageListener listener;
		synchronized (this) {
			listener = this.n2nmListeners.get(type);
		}

		if (listener == null) {
			Logger.error(this, "Unknown n2nm ID: " + type + " - discarding packet length " + messageData.getLength());
			return;
		}

		listener.handleMessage(messageData.getData(), fromDarknet, src, type);
	}

	/**
	 * Handle a node to node text message SimpleFieldSet
	 * @throws FSParseException
	 */
	public void handleNodeToNodeTextMessageSimpleFieldSet(SimpleFieldSet fs, DarknetPeerNode source, int fileNumber)
			throws FSParseException {
		if (logMINOR) {
			Logger.minor(this, "Got node to node message: \n" + fs);
		}
		int overallType = fs.getInt("n2nType");
		fs.removeValue("n2nType");
		if (overallType == Node.N2N_MESSAGE_TYPE_FPROXY) {
			this.handleFproxyNodeToNodeTextMessageSimpleFieldSet(fs, source, fileNumber);
		}
		else {
			Logger.error(this,
					"Received unknown node to node message type '" + overallType + "' from " + source.getPeer());
		}
	}

	private void handleFproxyNodeToNodeTextMessageSimpleFieldSet(SimpleFieldSet fs, DarknetPeerNode source,
			int fileNumber) throws FSParseException {
		int type = fs.getInt("type");
		if (type == Node.N2N_TEXT_MESSAGE_TYPE_USERALERT) {
			source.handleFproxyN2NTM(fs, fileNumber);
		}
		else if (type == Node.N2N_TEXT_MESSAGE_TYPE_FILE_OFFER) {
			source.handleFproxyFileOffer(fs, fileNumber);
		}
		else if (type == Node.N2N_TEXT_MESSAGE_TYPE_FILE_OFFER_ACCEPTED) {
			source.handleFproxyFileOfferAccepted(fs, fileNumber);
		}
		else if (type == Node.N2N_TEXT_MESSAGE_TYPE_FILE_OFFER_REJECTED) {
			source.handleFproxyFileOfferRejected(fs, fileNumber);
		}
		else if (type == Node.N2N_TEXT_MESSAGE_TYPE_BOOKMARK) {
			source.handleFproxyBookmarkFeed(fs, fileNumber);
		}
		else if (type == Node.N2N_TEXT_MESSAGE_TYPE_DOWNLOAD) {
			source.handleFproxyDownloadFeed(fs, fileNumber);
		}
		else {
			Logger.error(this,
					"Received unknown fproxy node to node message sub-type '" + type + "' from " + source.getPeer());
		}
	}

	public String getMyName() {
		return this.myName;
	}

	public MessageCore getUSM() {
		return this.usm;
	}

	public LocationManager getLocationManager() {
		return this.lm;
	}

	public int getSwaps() {
		return LocationManager.swaps;
	}

	public int getNoSwaps() {
		return LocationManager.noSwaps;
	}

	public int getStartedSwaps() {
		return LocationManager.startedSwaps;
	}

	public int getSwapsRejectedAlreadyLocked() {
		return LocationManager.swapsRejectedAlreadyLocked;
	}

	public int getSwapsRejectedNowhereToGo() {
		return LocationManager.swapsRejectedNowhereToGo;
	}

	public int getSwapsRejectedRateLimit() {
		return LocationManager.swapsRejectedRateLimit;
	}

	public int getSwapsRejectedRecognizedID() {
		return LocationManager.swapsRejectedRecognizedID;
	}

	public PeerNode[] getPeerNodes() {
		return this.peers.myPeers();
	}

	public PeerNode[] getConnectedPeers() {
		return this.peers.connectedPeers();
	}

	/**
	 * Return a peer of the node given its ip and port, name or identity, as a String
	 */
	public PeerNode getPeerNode(String nodeIdentifier) {
		for (PeerNode pn : this.peers.myPeers()) {
			Peer peer = pn.getPeer();
			String nodeIpAndPort = "";
			if (peer != null) {
				nodeIpAndPort = peer.toString();
			}
			String identity = pn.getIdentityString();
			if (pn instanceof DarknetPeerNode dpn) {
				String name = dpn.myName;
				if (identity.equals(nodeIdentifier) || nodeIpAndPort.equals(nodeIdentifier)
						|| name.equals(nodeIdentifier)) {
					return pn;
				}
			}
			else {
				if (identity.equals(nodeIdentifier) || nodeIpAndPort.equals(nodeIdentifier)) {
					return pn;
				}
			}
		}
		return null;
	}

	public boolean isHasStarted() {
		return this.hasStarted;
	}

	public void queueRandomReinsert(KeyBlock block) {
		this.clientCore.queueRandomReinsert(block);
	}

	public String getExtraPeerDataDir() {
		return this.extraPeerDataDir.getPath();
	}

	public boolean noConnectedPeers() {
		return !this.peers.anyConnectedPeers();
	}

	public double getLocation() {
		return this.lm.getLocation();
	}

	public double getLocationChangeSession() {
		return this.lm.getLocChangeSession();
	}

	public int getAverageOutgoingSwapTime() {
		return this.lm.getAverageSwapTime();
	}

	public long getSendSwapInterval() {
		return this.lm.getSendSwapInterval();
	}

	public int getNumberOfRemotePeerLocationsSeenInSwaps() {
		return this.lm.numberOfRemotePeerLocationsSeenInSwaps;
	}

	public boolean isAdvancedModeEnabled() {
		if (this.clientCore == null) {
			return false;
		}
		return this.clientCore.isAdvancedModeEnabled();
	}

	public boolean isFProxyJavascriptEnabled() {
		return this.clientCore.isFProxyJavascriptEnabled();
	}

	// FIXME convert these kind of threads to Checkpointed's and implement a handler
	// using the PacketSender/Ticker. Would save a few threads.

	public int getNumARKFetchers() {
		int x = 0;
		for (PeerNode p : this.peers.myPeers()) {
			if (p.isFetchingARK()) {
				x++;
			}
		}
		return x;
	}

	// FIXME put this somewhere else
	private final Object statsSync = new Object();

	/** The total number of bytes of real data i.e.&nbsp;payload sent by the node */
	private long totalPayloadSent;

	public void sentPayload(int len) {
		synchronized (this.statsSync) {
			this.totalPayloadSent += len;
		}
	}

	/**
	 * Get the total number of bytes of payload (real data) sent by the node
	 * @return Total payload sent in bytes
	 */
	public long getTotalPayloadSent() {
		synchronized (this.statsSync) {
			return this.totalPayloadSent;
		}
	}

	public void setName(String key) throws InvalidConfigValueException, NodeNeedRestartException {
		this.config.get("node").getOption("name").setValue(key);
	}

	public Ticker getTicker() {
		return this.ticker;
	}

	public int getUnclaimedFIFOSize() {
		return this.usm.getUnclaimedFIFOSize();
	}

	/**
	 * Connect this node to another node (for purposes of testing)
	 */
	public void connectToSeednode(SeedServerTestPeerNode node) {
		this.peers.addPeer(node, false, false);
	}

	public void connect(Node node, DarknetPeerNode.FRIEND_TRUST trust, DarknetPeerNode.FRIEND_VISIBILITY visibility)
			throws FSParseException, PeerParseException, ReferenceSignatureVerificationException, PeerTooOldException {
		this.peers.connect(node.darknetCrypto.exportPublicFieldSet(), this.darknetCrypto.packetMangler, trust,
				visibility);
	}

	public short maxHTL() {
		return this.maxHTL;
	}

	public int getDarknetPortNumber() {
		return this.darknetCrypto.portNumber;
	}

	public synchronized int getOutputBandwidthLimit() {
		return this.outputBandwidthLimit;
	}

	public synchronized int getInputBandwidthLimit() {
		if (this.inputLimitDefault) {
			return this.outputBandwidthLimit * 4;
		}
		return this.inputBandwidthLimit;
	}

	/**
	 * @return total datastore size in bytes.
	 */
	public synchronized long getStoreSize() {
		return this.maxTotalDatastoreSize;
	}

	@Override
	public synchronized void setTimeSkewDetectedUserAlert() {
		if (timeSkewDetectedUserAlert == null) {
			timeSkewDetectedUserAlert = new TimeSkewDetectedUserAlert();
			this.clientCore.alerts.register(timeSkewDetectedUserAlert);
		}
	}

	public File getNodeDir() {
		return this.nodeDir.dir();
	}

	public File getCfgDir() {
		return this.cfgDir.dir();
	}

	public File getUserDir() {
		return this.userDir.dir();
	}

	public File getRunDir() {
		return this.runDir.dir();
	}

	public File getStoreDir() {
		return this.storeDir.dir();
	}

	public File getPluginDir() {
		return this.pluginDir.dir();
	}

	public ProgramDirectory nodeDir() {
		return this.nodeDir;
	}

	public ProgramDirectory cfgDir() {
		return this.cfgDir;
	}

	public ProgramDirectory userDir() {
		return this.userDir;
	}

	public ProgramDirectory runDir() {
		return this.runDir;
	}

	public ProgramDirectory storeDir() {
		return this.storeDir;
	}

	public ProgramDirectory pluginDir() {
		return this.pluginDir;
	}

	public DarknetPeerNode createNewDarknetNode(SimpleFieldSet fs, DarknetPeerNode.FRIEND_TRUST trust,
			DarknetPeerNode.FRIEND_VISIBILITY visibility)
			throws FSParseException, PeerParseException, ReferenceSignatureVerificationException, PeerTooOldException {
		return new DarknetPeerNode(fs, this, this.darknetCrypto, false, trust, visibility);
	}

	public OpennetPeerNode createNewOpennetNode(SimpleFieldSet fs) throws FSParseException, OpennetDisabledException,
			PeerParseException, ReferenceSignatureVerificationException, PeerTooOldException {
		if (this.opennet == null) {
			throw new OpennetDisabledException("Opennet is not currently enabled");
		}
		return new OpennetPeerNode(fs, this, this.opennet.crypto, this.opennet, false);
	}

	public SeedServerTestPeerNode createNewSeedServerTestPeerNode(SimpleFieldSet fs) throws FSParseException,
			OpennetDisabledException, PeerParseException, ReferenceSignatureVerificationException, PeerTooOldException {
		if (this.opennet == null) {
			throw new OpennetDisabledException("Opennet is not currently enabled");
		}
		return new SeedServerTestPeerNode(fs, this, this.opennet.crypto, true);
	}

	public OpennetPeerNode addNewOpennetNode(SimpleFieldSet fs, OpennetManager.ConnectionType connectionType)
			throws FSParseException, PeerParseException, ReferenceSignatureVerificationException {
		// FIXME: perhaps this should throw OpennetDisabledExcemption rather than returing
		// false?
		if (this.opennet == null) {
			return null;
		}
		return this.opennet.addNewOpennetNode(fs, connectionType, false);
	}

	public byte[] getOpennetPubKeyHash() {
		return this.opennet.crypto.ecdsaPubKeyHash;
	}

	public byte[] getDarknetPubKeyHash() {
		return this.darknetCrypto.ecdsaPubKeyHash;
	}

	public synchronized boolean isOpennetEnabled() {
		return this.opennet != null;
	}

	public SimpleFieldSet exportDarknetPublicFieldSet() {
		return this.darknetCrypto.exportPublicFieldSet();
	}

	public SimpleFieldSet exportOpennetPublicFieldSet() {
		return this.opennet.crypto.exportPublicFieldSet();
	}

	public SimpleFieldSet exportDarknetPrivateFieldSet() {
		return this.darknetCrypto.exportPrivateFieldSet();
	}

	public SimpleFieldSet exportOpennetPrivateFieldSet() {
		return this.opennet.crypto.exportPrivateFieldSet();
	}

	/**
	 * Should the IP detection code only use the IP address override and the bindTo
	 * information, rather than doing a full detection?
	 */
	public synchronized boolean dontDetect() {
		// Only return true if bindTo is set on all ports which are in use
		if (!this.darknetCrypto.getBindTo().isRealInternetAddress(false, true, false)) {
			return false;
		}
		if (this.opennet != null) {
			return !this.opennet.crypto.getBindTo().isRealInternetAddress(false, true, false);
		}
		return true;
	}

	public int getOpennetFNPPort() {
		if (this.opennet == null) {
			return -1;
		}
		return this.opennet.crypto.portNumber;
	}

	public OpennetManager getOpennet() {
		return this.opennet;
	}

	public synchronized boolean passOpennetRefsThroughDarknet() {
		return this.passOpennetRefsThroughDarknet;
	}

	/**
	 * Get the set of public ports that need to be forwarded. These are internal ports,
	 * not necessarily external - they may be rewritten by the NAT.
	 * @return A Set of ForwardPort's to be fed to port forward plugins.
	 */
	public Set<ForwardPort> getPublicInterfacePorts() {
		HashSet<ForwardPort> set = new HashSet<>();
		// FIXME IPv6 support
		set.add(new ForwardPort("darknet", false, ForwardPort.PROTOCOL_UDP_IPV4, this.darknetCrypto.portNumber));
		if (this.opennet != null) {
			NodeCrypto crypto = this.opennet.crypto;
			if (crypto != null) {
				set.add(new ForwardPort("opennet", false, ForwardPort.PROTOCOL_UDP_IPV4, crypto.portNumber));
			}
		}
		return set;
	}

	@Override
	public long[] getTotalIO() {
		return this.collector.getTotalIO();
	}

	/**
	 * Get the time since the node was started in milliseconds.
	 * @return Uptime in milliseconds
	 */
	public long getUptime() {
		return System.currentTimeMillis() - this.usm.getStartedTime();
	}

	public synchronized UdpSocketHandler[] getPacketSocketHandlers() {
		// FIXME better way to get these!
		if (this.opennet != null) {
			return new UdpSocketHandler[] { this.darknetCrypto.socket, this.opennet.crypto.socket };
			// TODO Auto-generated method stub
		}
		else {
			return new UdpSocketHandler[] { this.darknetCrypto.socket };
		}
	}

	public int getMaxOpennetPeers() {
		return this.maxOpennetPeers;
	}

	public void onAddedValidIP() {
		OpennetManager om;
		synchronized (this) {
			om = this.opennet;
		}
		if (om != null) {
			Announcer announcer = om.announcer;
			if (announcer != null) {
				announcer.maybeSendAnnouncement();
			}
		}
	}

	public boolean isSeednode() {
		return this.acceptSeedConnections;
	}

	/**
	 * Returns true if the packet receiver should try to decode/process packets that are
	 * not from a peer (i.e. from a seed connection) The packet receiver calls this upon
	 * receiving an unrecognized packet.
	 */
	public boolean wantAnonAuth(boolean isOpennet) {
		if (isOpennet) {
			return this.opennet != null && this.acceptSeedConnections;
		}
		else {
			return false;
		}
	}

	// FIXME make this configurable
	// Probably should wait until we have non-opennet anon auth so we can add it to
	// NodeCrypto.
	public boolean wantAnonAuthChangeIP(boolean isOpennet) {
		return !isOpennet;
	}

	public boolean opennetDefinitelyPortForwarded() {
		OpennetManager om;
		synchronized (this) {
			om = this.opennet;
		}
		if (om == null) {
			return false;
		}
		NodeCrypto crypto = om.crypto;
		if (crypto == null) {
			return false;
		}
		return crypto.definitelyPortForwarded();
	}

	public boolean darknetDefinitelyPortForwarded() {
		if (this.darknetCrypto == null) {
			return false;
		}
		return this.darknetCrypto.definitelyPortForwarded();
	}

	public boolean hasKey(Key key, boolean canReadClientCache, boolean forULPR) {
		// FIXME optimise!
		if (key instanceof NodeCHK) {
			return this.fetch((NodeCHK) key, true, canReadClientCache, false, false, forULPR, null) != null;
		}
		else {
			return this.fetch((NodeSSK) key, true, canReadClientCache, false, false, forULPR, null) != null;
		}
	}

	/**
	 * Warning: does not announce change in location!
	 */
	public void setLocation(double loc) {
		this.lm.setLocation(loc);
	}

	public boolean peersWantKey(Key key) {
		return this.failureTable.peersWantKey(key, null);
	}

	public final RequestClient nonPersistentClientBulk = new RequestClientBuilder().build();

	public final RequestClient nonPersistentClientRT = new RequestClientBuilder().realTime().build();

	public void setDispatcherHook(NodeDispatcher.NodeDispatcherCallback cb) {
		this.dispatcher.setHook(cb);
	}

	public boolean shallWePublishOurPeersLocation() {
		return this.publishOurPeersLocation;
	}

	public boolean shallWeRouteAccordingToOurPeersLocation(int htl) {
		return this.routeAccordingToOurPeersLocation && htl > 1;
	}

	/**
	 * Can be called to decrypt client.dat* etc, or can be called when switching from
	 * another security level to HIGH.
	 */
	public void setMasterPassword(String password, boolean inFirstTimeWizard) throws AlreadySetPasswordException,
			MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException {
		MasterKeys k;
		synchronized (this) {
			if (this.keys == null) {
				// Decrypting.
				this.keys = MasterKeys.read(this.masterKeysFile, this.secureRandom, password);
				this.databaseKey = this.keys.createDatabaseKey(this.secureRandom);
			}
			else {
				// Setting password when changing to HIGH from another mode.
				this.keys.changePassword(this.masterKeysFile, password, this.secureRandom);
				return;
			}
			k = this.keys;
		}
		this.setPasswordInner(k, inFirstTimeWizard);
	}

	private void setPasswordInner(MasterKeys keys, boolean inFirstTimeWizard)
			throws MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException {
		MasterSecret secret = keys.getPersistentMasterSecret();
		this.clientCore.setupMasterSecret(secret);
		boolean wantClientCache;
		boolean wantDatabase;
		synchronized (this) {
			wantClientCache = this.clientCacheAwaitingPassword;
			wantDatabase = this.databaseAwaitingPassword;
			this.databaseAwaitingPassword = false;
		}
		if (wantClientCache) {
			this.activatePasswordedClientCache(keys);
		}
		if (wantDatabase) {
			this.lateSetupDatabase(keys.createDatabaseKey(this.secureRandom));
		}
	}

	private void activatePasswordedClientCache(MasterKeys keys) {
		synchronized (this) {
			if (this.clientCacheType.equals("ram")) {
				System.err.println("RAM client cache cannot be passworded!");
				return;
			}
			if (!this.clientCacheType.equals("salt-hash")) {
				System.err.println(
						"Unknown client cache type, cannot activate passworded store: " + this.clientCacheType);
				return;
			}
		}
		Runnable migrate = new MigrateOldStoreData(true);
		String suffix = this.getStoreSuffix();
		try {
			this.initSaltHashClientCacheFS(suffix, true, keys.clientCacheMasterKey);
		}
		catch (NodeInitException ex) {
			Logger.error(this, "Unable to activate passworded client cache", ex);
			System.err.println("Unable to activate passworded client cache: " + ex);
			ex.printStackTrace();
			return;
		}

		synchronized (this) {
			this.clientCacheAwaitingPassword = false;
		}

		this.executor.execute(migrate, "Migrate data from previous store");
	}

	public void changeMasterPassword(String oldPassword, String newPassword, boolean inFirstTimeWizard)
			throws MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException,
			AlreadySetPasswordException {
		if (this.securityLevels.getPhysicalThreatLevel() == PHYSICAL_THREAT_LEVEL.MAXIMUM) {
			Logger.error(this, "Changing password while physical threat level is at MAXIMUM???");
		}
		if (this.masterKeysFile.exists()) {
			this.keys.changePassword(this.masterKeysFile, newPassword, this.secureRandom);
			this.setPasswordInner(this.keys, inFirstTimeWizard);
		}
		else {
			this.setMasterPassword(newPassword, inFirstTimeWizard);
		}
	}

	public synchronized File getMasterPasswordFile() {
		return this.masterKeysFile;
	}

	boolean hasPanicked() {
		return this.hasPanicked;
	}

	public void panic() {
		this.hasPanicked = true;
		this.clientCore.clientLayerPersister.panic();
		this.clientCore.clientLayerPersister.killAndWaitForNotRunning();
		try {
			MasterKeys.killMasterKeys(this.getMasterPasswordFile());
		}
		catch (IOException ignored) {
			System.err.println("Unable to wipe master passwords key file!");
			System.err.println("Please delete " + this.getMasterPasswordFile()
					+ " to ensure that nobody can recover your old downloads.");
		}
		// persistent-temp will be cleaned on restart.
	}

	public void finishPanic() {
		WrapperManager.restart();
		System.exit(0);
	}

	public boolean awaitingPassword() {
		if (this.clientCacheAwaitingPassword) {
			return true;
		}
		return this.databaseAwaitingPassword;
	}

	public boolean wantEncryptedDatabase() {
		return this.securityLevels.getPhysicalThreatLevel() != PHYSICAL_THREAT_LEVEL.LOW;
	}

	public boolean wantNoPersistentDatabase() {
		return this.securityLevels.getPhysicalThreatLevel() == PHYSICAL_THREAT_LEVEL.MAXIMUM;
	}

	public boolean hasDatabase() {
		return !this.clientCore.clientLayerPersister.isKilledOrNotLoaded();
	}

	/**
	 * @return canonical path of the database file in use.
	 */
	public String getDatabasePath() {
		return this.clientCore.clientLayerPersister.getWriteFilename().toString();
	}

	/**
	 * Should we commit the block to the store rather than the cache?
	 *
	 * <p>
	 * We used to check whether we are a sink by checking whether any peer has a closer
	 * location than we do. Then we made low-uptime nodes exempt from this calculation: if
	 * we route to a low uptime node with a closer location, we want to store it anyway
	 * since he may go offline. The problem was that if we routed to a low-uptime node,
	 * and there was another option that wasn't low-uptime but was closer to the target
	 * than we were, then we would not store in the store. Also, routing isn't always by
	 * the closest peer location: FOAF and per-node failure tables change it. So now, we
	 * consider the nodes we have actually routed to:
	 * </p>
	 *
	 * <p>
	 * Store in datastore if our location is closer to the target than:
	 * </p>
	 * <ol>
	 * <li>the source location (if any, and ignoring if low-uptime)</li>
	 * <li>the locations of the nodes we just routed to (ditto)</li>
	 * </ol>
	 * @param key
	 * @param source
	 * @param routedTo
	 * @return
	 */
	public boolean shouldStoreDeep(Key key, PeerNode source, PeerNode[] routedTo) {
		double myLoc = this.getLocation();
		double target = key.toNormalizedDouble();
		double myDist = Location.distance(myLoc, target);

		// First, calculate whether we would have stored it using the old formula.
		if (logMINOR) {
			Logger.minor(this, "Should store for " + key + " ?");
		}
		// Don't sink store if any of the nodes we routed to, or our predecessor, is both
		// high-uptime and closer to the target than we are.
		if (source != null && !source.isLowUptime()) {
			if (Location.distance(source, target) < myDist) {
				if (logMINOR) {
					Logger.minor(this, "Not storing because source is closer to target for " + key + " : " + source);
				}
				return false;
			}
		}
		for (PeerNode pn : routedTo) {
			if (Location.distance(pn, target) < myDist && !pn.isLowUptime()) {
				if (logMINOR) {
					Logger.minor(this, "Not storing because peer " + pn + " is closer to target for " + key
							+ " his loc " + pn.getLocation() + " my loc " + myLoc + " target is " + target);
				}
				return false;
			}
			else {
				if (logMINOR) {
					Logger.minor(this, "Should store maybe, peer " + pn + " loc = " + pn.getLocation() + " my loc is "
							+ myLoc + " target is " + target + " low uptime is " + pn.isLowUptime());
				}
			}
		}
		if (logMINOR) {
			Logger.minor(this, "Should store returning true for " + key + " target=" + target + " myLoc=" + myLoc
					+ " peers: " + routedTo.length);
		}
		return true;
	}

	public boolean getWriteLocalToDatastore() {
		return this.writeLocalToDatastore;
	}

	public boolean getUseSlashdotCache() {
		return this.useSlashdotCache;
	}

	// FIXME remove the visibility alert after a few builds.

	public void createVisibilityAlert() {
		synchronized (this) {
			if (this.showFriendsVisibilityAlert) {
				return;
			}
			this.showFriendsVisibilityAlert = true;
		}
		// Wait until startup completed.
		this.getTicker().queueTimedJob(Node.this.config::store, 0);
		this.registerFriendsVisibilityAlert();
	}

	private final FCPUserAlert visibilityAlert = new SimpleUserAlert(true,
			this.l10n("pleaseSetPeersVisibilityAlertTitle"), this.l10n("pleaseSetPeersVisibilityAlert"),
			this.l10n("pleaseSetPeersVisibilityAlert"), FCPUserAlert.ERROR) {

		@Override
		public void onDismiss() {
			synchronized (Node.this) {
				Node.this.showFriendsVisibilityAlert = false;
			}
			Node.this.config.store();
			Node.this.unregisterFriendsVisibilityAlert();
		}

	};

	private void registerFriendsVisibilityAlert() {
		if (this.clientCore == null || this.clientCore.alerts == null) {
			// Wait until startup completed.
			this.getTicker().queueTimedJob(Node.this::registerFriendsVisibilityAlert, 0);
			return;
		}
		this.clientCore.alerts.register(this.visibilityAlert);
	}

	private void unregisterFriendsVisibilityAlert() {
		this.clientCore.alerts.unregister(this.visibilityAlert);
	}

	public int getMinimumMTU() {
		int mtu;
		synchronized (this) {
			mtu = this.maxPacketSize;
		}
		if (this.ipDetector != null) {
			int detected = this.ipDetector.getMinimumDetectedMTU();
			if (detected < mtu) {
				return detected;
			}
		}
		return mtu;
	}

	public void updateMTU() {
		this.darknetCrypto.socket.calculateMaxPacketSize();
		OpennetManager om = this.opennet;
		if (om != null) {
			om.crypto.socket.calculateMaxPacketSize();
		}
	}

	public static boolean isTestnetEnabled() {
		return false;
	}

	public MersenneTwister createRandom() {
		byte[] buf = new byte[16];
		this.random.nextBytes(buf);
		return new MersenneTwister(buf);
	}

	public boolean enableNewLoadManagement(boolean realTimeFlag) {
		NodeStats stats = this.nodeStats;
		if (stats == null) {
			Logger.error(this, "Calling enableNewLoadManagement before Node constructor completes! FIX THIS!",
					new Exception("error"));
			return false;
		}
		return stats.enableNewLoadManagement(realTimeFlag);
	}

	/** FIXME move to Probe.java? */
	public boolean enableRoutedPing() {
		return this.enableRoutedPing;
	}

	public boolean updateIsUrgent() {
		OpennetManager om = this.getOpennet();
		if (om != null) {
			if (om.announcer != null && om.announcer.isWaitingForUpdater()) {
				return true;
			}
		}
		return this.peers.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_TOO_NEW,
				true) > PeerManager.OUTDATED_MIN_TOO_NEW_DARKNET;
	}

	public byte[] getPluginStoreKey(String storeIdentifier) {
		DatabaseKey key;
		synchronized (this) {
			key = this.databaseKey;
		}
		if (key != null) {
			return key.getPluginStoreKey(storeIdentifier);
		}
		else {
			return null;
		}
	}

	public PluginManager getPluginManager() {
		return this.pluginManager;
	}

	DatabaseKey getDatabaseKey() {
		return this.databaseKey;
	}

	public NodeDiagnostics getNodeDiagnostics() {
		return this.nodeDiagnostics;
	}

	public boolean isNodeDiagnosticsEnabled() {
		return this.enableNodeDiagnostics;
	}

	public static class AlreadySetPasswordException extends Exception {

		@Serial
		private static final long serialVersionUID = -7328456475029374032L;

	}

	public class MigrateOldStoreData implements Runnable {

		private final boolean clientCache;

		public MigrateOldStoreData(boolean clientCache) {
			this.clientCache = clientCache;
			if (clientCache) {
				Node.this.oldCHKClientCache = Node.this.chkClientcache;
				Node.this.oldPKClientCache = Node.this.pubKeyClientcache;
				Node.this.oldSSKClientCache = Node.this.sskClientcache;
			}
			else {
				Node.this.oldCHK = Node.this.chkDatastore;
				Node.this.oldPK = Node.this.pubKeyDatastore;
				Node.this.oldSSK = Node.this.sskDatastore;
				Node.this.oldCHKCache = Node.this.chkDatastore;
				Node.this.oldPKCache = Node.this.pubKeyDatastore;
				Node.this.oldSSKCache = Node.this.sskDatastore;
			}
		}

		@Override
		public void run() {
			System.err.println("Migrating old " + (this.clientCache ? "client cache" : "datastore"));
			if (this.clientCache) {
				Node.this.migrateOldStore(Node.this.oldCHKClientCache, Node.this.chkClientcache, true);
				StoreCallback<? extends StorableBlock> old;
				synchronized (Node.this) {
					old = Node.this.oldCHKClientCache;
					Node.this.oldCHKClientCache = null;
				}
				Node.this.closeOldStore(old);
				Node.this.migrateOldStore(Node.this.oldPKClientCache, Node.this.pubKeyClientcache, true);
				synchronized (Node.this) {
					old = Node.this.oldPKClientCache;
					Node.this.oldPKClientCache = null;
				}
				Node.this.closeOldStore(old);
				Node.this.migrateOldStore(Node.this.oldSSKClientCache, Node.this.sskClientcache, true);
				synchronized (Node.this) {
					old = Node.this.oldSSKClientCache;
					Node.this.oldSSKClientCache = null;
				}
				Node.this.closeOldStore(old);
			}
			else {
				Node.this.migrateOldStore(Node.this.oldCHK, Node.this.chkDatastore, false);
				Node.this.oldCHK = null;
				Node.this.migrateOldStore(Node.this.oldPK, Node.this.pubKeyDatastore, false);
				Node.this.oldPK = null;
				Node.this.migrateOldStore(Node.this.oldSSK, Node.this.sskDatastore, false);
				Node.this.oldSSK = null;
				Node.this.migrateOldStore(Node.this.oldCHKCache, Node.this.chkDatacache, false);
				Node.this.oldCHKCache = null;
				Node.this.migrateOldStore(Node.this.oldPKCache, Node.this.pubKeyDatacache, false);
				Node.this.oldPKCache = null;
				Node.this.migrateOldStore(Node.this.oldSSKCache, Node.this.sskDatacache, false);
				Node.this.oldSSKCache = null;
			}
			System.err.println("Finished migrating old " + (this.clientCache ? "client cache" : "datastore"));
		}

	}

	public class NodeNameCallback extends StringCallback {

		NodeNameCallback() {
		}

		@Override
		public String get() {
			String name;
			synchronized (this) {
				name = Node.this.myName;
			}
			if (name.startsWith("Node id|") || name.equals("MyFirstFreenetNode")
					|| name.startsWith("Freenet node with no name #")) {
				Node.this.clientCore.alerts.register(Node.nodeNameUserAlert);
			}
			else {
				Node.this.clientCore.alerts.unregister(Node.nodeNameUserAlert);
			}
			return name;
		}

		@Override
		public void set(String val) throws InvalidConfigValueException {
			if (this.get().equals(val)) {
				return;
			}
			else if (val.length() > 128) {
				throw new InvalidConfigValueException("The given node name is too long (" + val + ')');
			}
			else if ("".equals(val)) {
				val = "~none~";
			}

			synchronized (this) {
				Node.this.myName = val;
			}

			// We'll broadcast the new name to our connected darknet peers via a
			// differential node reference
			SimpleFieldSet fs = new SimpleFieldSet(true);
			fs.putSingle("myName", Node.this.myName);
			Node.this.peers.locallyBroadcastDiffNodeRef(fs, true, false);
			// We call the callback once again to ensure MeaningfulNodeNameUserAlert
			// has been unregistered ... see #1595
			this.get();
		}

	}

	private class StoreTypeCallback extends StringCallback implements EnumerableOptionCallback {

		@Override
		public String get() {
			synchronized (Node.this) {
				return Node.this.storeType;
			}
		}

		@Override
		public void set(String val) throws InvalidConfigValueException, NodeNeedRestartException {
			boolean found = false;
			for (String p : this.getPossibleValues()) {
				if (p.equals(val)) {
					found = true;
					break;
				}
			}
			if (!found) {
				throw new InvalidConfigValueException("Invalid store type");
			}

			String type;
			synchronized (Node.this) {
				type = Node.this.storeType;
			}
			if (type.equals("ram")) {
				synchronized (this) { // Serialise this part.
					Node.this.makeStore(val);
				}
			}
			else {
				synchronized (Node.this) {
					Node.this.storeType = val;
				}
				throw new NodeNeedRestartException("Store type cannot be changed on the fly");
			}
		}

		@Override
		public String[] getPossibleValues() {
			return new String[] { "salt-hash", "ram" };
		}

	}

	private class ClientCacheTypeCallback extends StringCallback implements EnumerableOptionCallback {

		@Override
		public String get() {
			synchronized (Node.this) {
				return Node.this.clientCacheType;
			}
		}

		@Override
		public void set(String val) throws InvalidConfigValueException, NodeNeedRestartException {
			boolean found = false;
			for (String p : this.getPossibleValues()) {
				if (p.equals(val)) {
					found = true;
					break;
				}
			}
			if (!found) {
				throw new InvalidConfigValueException("Invalid store type");
			}

			synchronized (this) { // Serialise this part.
				String suffix = Node.this.getStoreSuffix();
				if (val.equals("salt-hash")) {
					byte[] key;
					try {
						synchronized (Node.this) {
							if (Node.this.keys == null) {
								throw new MasterKeysWrongPasswordException();
							}
							key = Node.this.keys.clientCacheMasterKey;
							Node.this.clientCacheType = val;
						}
					}
					catch (MasterKeysWrongPasswordException e1) {
						Node.this.setClientCacheAwaitingPassword();
						throw new InvalidConfigValueException("You must enter the password");
					}
					try {
						Node.this.initSaltHashClientCacheFS(suffix, true, key);
					}
					catch (NodeInitException ex) {
						Logger.error(this, "Unable to create new store", ex);
						System.err.println("Unable to create new store: " + ex);
						ex.printStackTrace();
						// FIXME l10n both on the NodeInitException and the wrapper
						// message
						throw new InvalidConfigValueException("Unable to create new store: " + ex);
					}
				}
				else if (val.equals("ram")) {
					Node.this.initRAMClientCacheFS();
				}
				else /* if(val.equals("none")) */ {
					Node.this.initNoClientCacheFS();
				}

				synchronized (Node.this) {
					Node.this.clientCacheType = val;
				}
			}
		}

		@Override
		public String[] getPossibleValues() {
			return new String[] { "salt-hash", "ram", "none" };
		}

	}

	private static class L10nCallback extends StringCallback implements EnumerableOptionCallback {

		@Override
		public String get() {
			return NodeL10n.getBase().getSelectedLanguage().fullName;
		}

		@Override
		public void set(String val) throws InvalidConfigValueException {
			if (val == null || this.get().equalsIgnoreCase(val)) {
				return;
			}
			try {
				NodeL10n.getBase().setLanguage(BaseL10n.LANGUAGE.mapToLanguage(val));
			}
			catch (MissingResourceException ex) {
				throw new InvalidConfigValueException(ex.getLocalizedMessage());
			}
			PluginManager.setLanguage(NodeL10n.getBase().getSelectedLanguage());
		}

		@Override
		public String[] getPossibleValues() {
			return BaseL10n.LANGUAGE.valuesWithFullNames();
		}

	}

}
