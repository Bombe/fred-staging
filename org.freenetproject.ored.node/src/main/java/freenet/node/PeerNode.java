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
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Writer;
import java.lang.ref.WeakReference;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.EnumMap;
import java.util.GregorianCalendar;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import freenet.client.FetchResult;
import freenet.client.async.USKRetriever;
import freenet.client.async.USKRetrieverCallback;
import freenet.client.request.PriorityClasses;
import freenet.crypt.BlockCipher;
import freenet.crypt.DSAPublicKey;
import freenet.crypt.ECDSA;
import freenet.crypt.ECDSA.Curves;
import freenet.crypt.Global;
import freenet.crypt.HMAC;
import freenet.crypt.KeyAgreementSchemeContext;
import freenet.crypt.SHA256;
import freenet.crypt.UnsupportedCipherException;
import freenet.crypt.ciphers.Rijndael;
import freenet.io.AddressTracker;
import freenet.io.comm.AsyncMessageCallback;
import freenet.io.comm.ByteCounter;
import freenet.io.comm.DMT;
import freenet.io.comm.DisconnectedException;
import freenet.io.comm.FreenetInetAddress;
import freenet.io.comm.Message;
import freenet.io.comm.MessageFilter;
import freenet.io.comm.NotConnectedException;
import freenet.io.comm.Peer;
import freenet.io.comm.Peer.LocalAddressException;
import freenet.io.comm.PeerParseException;
import freenet.io.comm.ReferenceSignatureVerificationException;
import freenet.io.comm.SocketHandler;
import freenet.io.xfer.PacketThrottle;
import freenet.keys.ClientSSK;
import freenet.keys.FreenetURI;
import freenet.keys.Key;
import freenet.keys.USK;
import freenet.node.event.DiffNoderefProcessedEvent;
import freenet.node.event.EventBus;
import freenet.node.math.TimeDecayingRunningAverage;
import freenet.nodelogger.Logger;
import freenet.support.Base64;
import freenet.support.BooleanLastTrueTracker;
import freenet.support.Fields;
import freenet.support.HexUtil;
import freenet.support.IllegalBase64Exception;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger.LogLevel;
import freenet.support.SimpleFieldSet;
import freenet.support.TimeUtil;
import freenet.support.WeakHashSet;
import freenet.support.math.MersenneTwister;
import freenet.support.math.RunningAverage;
import freenet.support.math.SimpleRunningAverage;
import freenet.support.node.FSParseException;
import freenet.support.transport.ip.HostnameSyntaxException;
import freenet.support.transport.ip.IPUtil;

/**
 * Represents a peer we are connected to. One of the major issues is that we can rekey, or
 * a node can go down and come back up while we are connected to it, and we want to
 * reinitialize the packet numbers when this happens. Hence, we separate a lot of code
 * into SessionKey, which handles all communications to and from this peer over the
 * duration of a single key.
 *
 * LOCKING: Can hold PeerManager and then lock PeerNode. Cannot hold PeerNode and then
 * lock PeerManager.
 *
 * @author amphibian
 *
 */
public abstract class PeerNode implements USKRetrieverCallback, BasePeerNode, PeerNodeUnlocked {

	private String lastGoodVersion;

	/**
	 * True if this peer has a build number older than our last-known-good build number.
	 * Note that even if this is true, the node can still be 'connected'.
	 */
	protected boolean unroutableOlderVersion;

	/**
	 * True if this peer reports that our build number is before their last-known-good
	 * build number. Note that even if this is true, the node can still be 'connected'.
	 */
	protected boolean unroutableNewerVersion;

	protected boolean disableRouting;

	protected boolean disableRoutingHasBeenSetLocally;

	protected boolean disableRoutingHasBeenSetRemotely;

	/*
	 * Buffer of Ni,Nr,g^i,g^r,ID
	 */
	private byte[] jfkBuffer;

	// TODO: sync ?

	protected byte[] jfkKa;

	protected byte[] incommingKey;

	protected byte[] jfkKe;

	protected byte[] outgoingKey;

	protected byte[] jfkMyRef;

	protected byte[] hmacKey;

	protected byte[] ivKey;

	protected byte[] ivNonce;

	protected int ourInitialSeqNum;

	protected int theirInitialSeqNum;

	protected int ourInitialMsgID;

	protected int theirInitialMsgID;

	// The following is used only if we are the initiator

	protected long jfkContextLifetime = 0;

	/** My low-level address for SocketManager purposes */
	private Peer detectedPeer;

	/**
	 * My OutgoingPacketMangler i.e. the object which encrypts packets sent to this node
	 */
	private final OutgoingPacketMangler outgoingMangler;

	/** Advertised addresses */
	protected List<Peer> nominalPeer;

	/** The PeerNode's report of our IP address */
	private Peer remoteDetectedPeer;

	/** Is this a testnet node? */
	public final boolean testnetEnabled;

	/** Packets sent/received on the current preferred key */
	private SessionKey currentTracker;

	/** Previous key - has a separate packet number space */
	private SessionKey previousTracker;

	/** When did we last rekey (promote the unverified tracker to new) ? */
	private long timeLastRekeyed;

	/** How much data did we send with the current tracker ? */
	private long totalBytesExchangedWithCurrentTracker = 0;

	/** Are we rekeying ? */
	private boolean isRekeying = false;

	/**
	 * Unverified tracker - will be promoted to currentTracker if we receive packets on it
	 */
	private SessionKey unverifiedTracker;

	/** When did we last send a packet? */
	private long timeLastSentPacket;

	/** When did we last receive a packet? */
	private long timeLastReceivedPacket;

	/** When did we last receive a non-auth packet? */
	private long timeLastReceivedDataPacket;

	/** When did we last receive an ack? */
	private long timeLastReceivedAck;

	/** When was isRoutingCompatible() last true? */
	private long timeLastRoutable;

	/** Time added or restarted (reset on startup unlike peerAddedTime) */
	private final long timeAddedOrRestarted;

	private long countSelectionsSinceConnected = 0;

	// 30%; yes it's alchemy too! and probably *way* too high to serve any purpose
	public static final int SELECTION_PERCENTAGE_WARNING = 30;

	// Minimum number of routable peers to have for the selection code to have any effect
	public static final int SELECTION_MIN_PEERS = 5;

	/**
	 * Is the peer connected? If currentTracker == null then we have no way to send
	 * packets (though we may be able to receive them on the other trackers), and are
	 * disconnected. So we MUST set isConnected to false when currentTracker = null, but
	 * the other way around isn't always true. LOCKING: Locks itself, safe to read
	 * atomically, however we should take (this) when setting it.
	 */
	private final BooleanLastTrueTracker isConnected;

	// FIXME use a BooleanLastTrueTracker. Be careful as isRoutable() depends on more than
	// this flag!
	private boolean isRoutable;

	/** Used by maybeOnConnect */
	private boolean wasDisconnected = true;

	/**
	 * Were we removed from the routing table? Used as a cache to avoid accessing
	 * PeerManager if not needed.
	 */
	private boolean removed;

	/**
	 * ARK fetcher.
	 */
	private USKRetriever arkFetcher;

	/**
	 * My ARK SSK public key; edition is the next one, not the current one, so this is
	 * what we want to fetch.
	 */
	private USK myARK;

	/** Number of handshake attempts since last successful connection or ARK fetch */
	private int handshakeCount;

	/** After this many failed handshakes, we start the ARK fetcher. */
	private static final int MAX_HANDSHAKE_COUNT = 2;

	final PeerLocation location;

	/**
	 * Node "identity". This is a random 32 byte block of data, which may be derived from
	 * the node's public key. It cannot be changed, and is only used for the outer keyed
	 * obfuscation on connection setup packets in FNPPacketMangler.
	 */
	final byte[] identity;

	final String identityAsBase64String;

	/** Hash of node identity. Used in setup key. */
	final byte[] identityHash;

	/** Hash of hash of node identity. Used in setup key. */
	final byte[] identityHashHash;

	/**
	 * Semi-unique ID used to help in mapping the network (see the code that uses it).
	 * Note this is for diagnostic purposes only and should be removed along with the code
	 * that uses it eventually - FIXME
	 */
	final long swapIdentifier;

	/** Negotiation types supported */
	int[] negTypes;

	/** Integer hash of the peer's public key. Used as hashCode(). */
	final int hashCode;

	/** The Node we serve */
	final Node node;

	/** The PeerManager we serve */
	final PeerManager peers;

	/**
	 * MessageItem's to send ASAP. LOCKING: Lock on self, always take that lock last.
	 * Sometimes used inside PeerNode.this lock.
	 */
	private final PeerMessageQueue messageQueue;

	/** When did we last receive a SwapRequest? */
	private long timeLastReceivedSwapRequest;

	/** Average interval between SwapRequest's */
	private final RunningAverage swapRequestsInterval;

	/** When did we last receive a probe request? */
	private long timeLastReceivedProbeRequest;

	/** Average interval between probe requests */
	private final RunningAverage probeRequestsInterval;

	/**
	 * Should we decrement HTL when it is at the maximum? This decision is made once per
	 * node to prevent giving away information that can make correlation attacks much
	 * easier.
	 */
	final boolean decrementHTLAtMaximum;

	/** Should we decrement HTL when it is at the minimum (1)? */
	final boolean decrementHTLAtMinimum;

	/** Time at which we should send the next handshake request */
	protected long sendHandshakeTime;

	/** Version of the node */
	private String version;

	/** Total bytes received since startup */
	private long totalInputSinceStartup;

	/** Total bytes sent since startup */
	private long totalOutputSinceStartup;

	/** Peer node public key; changing this means new noderef */
	public final ECPublicKey peerECDSAPubKey;

	/** FIXME: Used by the N2NChat plugin because the getter is protected! */
	public final byte[] peerECDSAPubKeyHash;

	private boolean isSignatureVerificationSuccessfull;

	/**
	 * Incoming setup key. Used to decrypt incoming auth packets. Specifically: K_node XOR
	 * H(setupKey).
	 */
	final byte[] incomingSetupKey;

	/**
	 * Outgoing setup key. Used to encrypt outgoing auth packets. Specifically: setupKey
	 * XOR H(K_node).
	 */
	final byte[] outgoingSetupKey;

	/** Incoming setup cipher (see above) */
	final BlockCipher incomingSetupCipher;

	/** Outgoing setup cipher (see above) */
	final BlockCipher outgoingSetupCipher;

	/**
	 * Anonymous-connect cipher. This is used in link setup if we are trying to get a
	 * connection to this node even though it doesn't know us, e.g. as a seednode.
	 */
	final BlockCipher anonymousInitiatorSetupCipher;

	/** The context object for the currently running negotiation. */
	private KeyAgreementSchemeContext ctx;

	/**
	 * The other side's boot ID. This is a random number generated at startup. LOCKING: It
	 * is far too dangerous to hold the main (this) lock while accessing bootID given that
	 * we ask for it in the messaging code and so on. This is essentially a "the other
	 * side restarted" flag, so there isn't really a consistency issue with the rest of
	 * PeerNode. So it's okay to effectively use a separate lock for it.
	 */
	private final AtomicLong bootID;

	/**
	 * Our boot ID. This is set to a random number on startup, and then reset whenever we
	 * dump the in-flight messages and call disconnected() on their clients, i.e. whenever
	 * we call disconnected(true, ...)
	 */
	private long myBootID;

	/** myBootID at the time of the last successful completed handshake. */
	private long myLastSuccessfulBootID;

	/** If true, this means last time we tried, we got a bogus noderef */
	private boolean bogusNoderef;

	/** The time at which we last completed a connection setup. */
	private long connectedTime;

	/** The status of this peer node in terms of Node.PEER_NODE_STATUS_* */
	public int peerNodeStatus = PeerManager.PEER_NODE_STATUS_DISCONNECTED;

	static final byte[] TEST_AS_BYTES;

	static {
		TEST_AS_BYTES = "test".getBytes(StandardCharsets.UTF_8);
	}

	/**
	 * Holds a String-Long pair that shows which message types (as name) have been send to
	 * this peer.
	 */
	private final Hashtable<String, Long> localNodeSentMessageTypes = new Hashtable<>();

	/**
	 * Holds a String-Long pair that shows which message types (as name) have been
	 * received by this peer.
	 */
	private final Hashtable<String, Long> localNodeReceivedMessageTypes = new Hashtable<>();

	/** Hold collected IP addresses for handshake attempts, populated by DNSRequestor */
	private Peer[] handshakeIPs;

	/** The last time we attempted to update handshakeIPs */
	private long lastAttemptedHandshakeIPUpdateTime;

	/** True if we have never connected to this peer since it was added to this node */
	protected boolean neverConnected;

	/**
	 * When this peer was added to this node. This is used differently by opennet and
	 * darknet nodes. Darknet nodes clear it after connecting but persist it across
	 * restarts, and clear it on restart unless the peer has never connected, or if it is
	 * more than 30 days ago. Opennet nodes clear it after the post-connect grace period
	 * elapses, and don't persist it across restarts.
	 */
	protected long peerAddedTime = 1;

	/** Average proportion of requests which are rejected or timed out */
	private final TimeDecayingRunningAverage pRejected;

	/** Bytes received at/before startup */
	private final long bytesInAtStartup;

	/** Bytes sent at/before startup */
	private final long bytesOutAtStartup;

	/** Times had routable connection when checked */
	private long hadRoutableConnectionCount;

	/** Times checked for routable connection */
	private long routableConnectionCheckCount;

	/**
	 * Delta between our clock and his clock (positive = his clock is fast, negative = our
	 * clock is fast)
	 */
	private long clockDelta;

	/** Percentage uptime of this node, 0 if they haven't said */
	private byte uptime;

	/**
	 * If the clock delta is more than this constant, we don't talk to the node. Reason:
	 * It may not be up to date, it will have difficulty resolving date-based content etc.
	 */
	private static final long MAX_CLOCK_DELTA = TimeUnit.DAYS.toMillis(1);

	/**
	 * 1 hour after the node is disconnected, if it is still disconnected and hasn't
	 * connected in that time, clear the message queue
	 */
	private static final long CLEAR_MESSAGE_QUEUE_AFTER = TimeUnit.HOURS.toMillis(1);

	/**
	 * A WeakReference to this object. Can be taken whenever a node object needs to refer
	 * to this object for a long time, but without preventing it from being GC'ed.
	 */
	final WeakReference<PeerNode> myRef;

	/** The node is being disconnected, but it may take a while. */
	private boolean disconnecting;

	/** When did we last disconnect? Not Disconnected because a discrete event */
	long timeLastDisconnect;

	/** Previous time of disconnection */
	long timePrevDisconnect;

	// Burst-only mode
	/** True if we are currently sending this peer a burst of handshake requests */
	private boolean isBursting;

	/**
	 * Number of handshake attempts (while in ListenOnly mode) since the beginning of this
	 * burst
	 */
	private int listeningHandshakeBurstCount;

	/**
	 * Total number of handshake attempts (while in ListenOnly mode) to be in this burst
	 */
	private int listeningHandshakeBurstSize;

	/**
	 * The set of the listeners that needs to be notified when status changes. It uses
	 * WeakReference, so there is no need to deregister
	 */
	private final Set<PeerManager.PeerStatusChangeListener> listeners = Collections
			.synchronizedSet(new WeakHashSet<>());

	// NodeCrypto for the relevant node reference for this peer's type (Darknet or Opennet
	// at this time))
	protected final NodeCrypto crypto;

	/**
	 * Some alchemy we use in PeerNode.shouldBeExcludedFromPeerList()
	 */
	public static final long BLACK_MAGIC_BACKOFF_PRUNING_TIME = TimeUnit.MINUTES.toMillis(5);

	public static final double BLACK_MAGIC_BACKOFF_PRUNING_PERCENTAGE = 0.9;

	/**
	 * For FNP link setup: The initiator has to ensure that nonces send back by the
	 * responder in message2 match what was chosen in message 1
	 */
	protected final LinkedList<byte[]> jfkNoncesSent = new LinkedList<>();

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

	private PacketFormat packetFormat;

	MersenneTwister paddingGen;

	protected SimpleFieldSet fullFieldSet;

	protected boolean ignoreLastGoodVersion() {
		return false;
	}

	/**
	 * Create a PeerNode from a SimpleFieldSet containing a node reference for one. Does
	 * not add self to PeerManager.
	 * @param fs The node reference to parse.
	 * @param node2 The running Node we are part of.
	 * @param fromLocal True if the noderef was read from the stored peers file and can
	 * contain local metadata, and won't be signed. Otherwise, it is a new node reference
	 * from elsewhere, should not contain metadata, and will be signed.
	 * @throws PeerTooOldException If the peer is so old that it can no longer be parsed,
	 * e.g. because it hasn't been connected since the last major crypto change.
	 */
	public PeerNode(SimpleFieldSet fs, Node node2, NodeCrypto crypto, boolean fromLocal)
			throws FSParseException, PeerParseException, ReferenceSignatureVerificationException, PeerTooOldException {
		boolean noSig = fromLocal || this.fromAnonymousInitiator();
		this.myRef = new WeakReference<>(this);
		this.checkStatusAfterBackoff = new PeerNodeBackoffStatusChecker(this.myRef);
		this.outgoingMangler = crypto.packetMangler;
		this.node = node2;
		this.crypto = crypto;
		assert (crypto.isOpennet == this.isOpennetForNoderef());
		this.peers = this.node.peers;
		this.backedOffPercent = new TimeDecayingRunningAverage(0.0, 180000, 0.0, 1.0, this.node);
		this.backedOffPercentRT = new TimeDecayingRunningAverage(0.0, 180000, 0.0, 1.0, this.node);
		this.backedOffPercentBulk = new TimeDecayingRunningAverage(0.0, 180000, 0.0, 1.0, this.node);
		this.myBootID = node2.bootID;
		this.bootID = new AtomicLong();
		this.version = fs.get("version");
		Version.seenVersion(this.version);
		try {
			this.simpleVersion = Version.getArbitraryBuildNumber(this.version);
		}
		catch (VersionParseException e2) {
			throw new FSParseException("Invalid version " + this.version + " : " + e2);
		}
		String locationString = fs.get("location");

		this.location = new PeerLocation(locationString);

		this.disableRouting = false;
		this.disableRoutingHasBeenSetLocally = false;
		this.disableRoutingHasBeenSetRemotely = false; // Assume so

		this.lastGoodVersion = fs.get("lastGoodVersion");
		this.updateVersionRoutablity();

		this.testnetEnabled = fs.getBoolean("testnet", false);
		if (this.testnetEnabled) {
			String err = "Ignoring incompatible testnet node " + this.detectedPeer;
			Logger.error(this, err);
			throw new PeerParseException(err);
		}

		this.negTypes = fs.getIntArray("auth.negTypes");
		if (this.negTypes == null || this.negTypes.length == 0) {
			if (this.fromAnonymousInitiator()) {
				// Assume compatible. Anonymous initiator = short-lived, and we already
				// connected so we know we are.
				this.negTypes = this.outgoingMangler.supportedNegTypes(false);
			}
			else {
				throw new FSParseException("No negTypes!");
			}
		}

		if (fs.getBoolean("opennet", false) != this.isOpennetForNoderef()) {
			throw new FSParseException(
					"Trying to parse a darknet peer as opennet or an opennet peer as darknet isOpennet="
							+ this.isOpennetForNoderef() + " boolean = " + fs.getBoolean("opennet", false)
							+ " string = \"" + fs.get("opennet") + "\"");
		}

		/* Read the ECDSA key material for the peer */
		SimpleFieldSet sfs = fs.subset("ecdsa.P256");
		if (sfs == null) {
			GregorianCalendar gc = new GregorianCalendar(2013, Calendar.JULY, 20);
			gc.setTimeZone(TimeZone.getTimeZone("GMT"));
			throw new PeerTooOldException("No ECC support", 1449, gc.getTime());
		}
		byte[] pub;
		try {
			pub = Base64.decode(sfs.get("pub"));
		}
		catch (IllegalBase64Exception ex) {
			Logger.error(this, "Caught " + ex + " parsing ECC pubkey", ex);
			throw new FSParseException(ex);
		}
		if (pub.length > ECDSA.Curves.P256.modulusSize) {
			throw new FSParseException("ecdsa.P256.pub is not the right size!");
		}
		ECPublicKey key = ECDSA.getPublicKey(pub, ECDSA.Curves.P256);
		if (key == null) {
			throw new FSParseException("ecdsa.P256.pub is invalid!");
		}
		this.peerECDSAPubKey = key;
		this.peerECDSAPubKeyHash = SHA256.digest(this.peerECDSAPubKey.getEncoded());

		if (noSig || this.verifyReferenceSignature(fs)) {
			this.isSignatureVerificationSuccessfull = true;
		}

		// Identifier

		String identityString = fs.get("identity");
		if (identityString == null && this.isDarknet()) {
			throw new PeerParseException("No identity!");
		}
		try {
			if (identityString != null) {
				this.identity = Base64.decode(identityString);
			}
			else {
				// We might be talking to a pre-1471 node
				// We need to generate it from the DSA key
				sfs = fs.subset("dsaPubKey");
				this.identity = SHA256.digest(DSAPublicKey.create(sfs, Global.DSAgroupBigA).asBytes());
			}
		}
		catch (NumberFormatException | IllegalBase64Exception ex) {
			throw new FSParseException(ex);
		}

		if (this.identity == null) {
			throw new FSParseException("No identity");
		}
		this.identityAsBase64String = Base64.encode(this.identity);
		this.identityHash = SHA256.digest(this.identity);
		this.identityHashHash = SHA256.digest(this.identityHash);
		this.swapIdentifier = Fields.bytesToLong(this.identityHashHash);
		this.hashCode = Fields.hashCode(this.peerECDSAPubKeyHash);

		// Setup incoming and outgoing setup ciphers
		byte[] nodeKey = crypto.identityHash;
		byte[] nodeKeyHash = crypto.identityHashHash;

		int digestLength = SHA256.getDigestLength();
		this.incomingSetupKey = new byte[digestLength];
		for (int i = 0; i < this.incomingSetupKey.length; i++) {
			this.incomingSetupKey[i] = (byte) (nodeKey[i] ^ this.identityHashHash[i]);
		}
		this.outgoingSetupKey = new byte[digestLength];
		for (int i = 0; i < this.outgoingSetupKey.length; i++) {
			this.outgoingSetupKey[i] = (byte) (nodeKeyHash[i] ^ this.identityHash[i]);
		}
		if (logMINOR) {
			Logger.minor(this,
					"Keys:\nIdentity:  " + HexUtil.bytesToHex(crypto.myIdentity) + "\nThisIdent: "
							+ HexUtil.bytesToHex(this.identity) + "\nNode:      " + HexUtil.bytesToHex(nodeKey)
							+ "\nNode hash: " + HexUtil.bytesToHex(nodeKeyHash) + "\nThis:      "
							+ HexUtil.bytesToHex(this.identityHash) + "\nThis hash: "
							+ HexUtil.bytesToHex(this.identityHashHash) + "\nFor:       " + this.getPeer());
		}

		try {
			this.incomingSetupCipher = new Rijndael(256, 256);
			this.incomingSetupCipher.initialize(this.incomingSetupKey);
			this.outgoingSetupCipher = new Rijndael(256, 256);
			this.outgoingSetupCipher.initialize(this.outgoingSetupKey);
			this.anonymousInitiatorSetupCipher = new Rijndael(256, 256);
			this.anonymousInitiatorSetupCipher.initialize(this.identityHash);
		}
		catch (UnsupportedCipherException e1) {
			Logger.error(this, "Caught: " + e1);
			throw new Error(e1);
		}

		this.nominalPeer = new ArrayList<>();
		try {
			String[] physical = fs.getAll("physical.udp");
			if (physical != null) {
				for (String phys : physical) {
					Peer p;
					try {
						p = new Peer(phys, true, true);
					}
					catch (HostnameSyntaxException | PeerParseException | UnknownHostException ignored) {
						if (fromLocal) {
							Logger.error(this,
									"Invalid hostname or IP Address syntax error while parsing peer reference in local peers list: "
											+ phys);
						}
						System.err.println(
								"Invalid hostname or IP Address syntax error while parsing peer reference: " + phys);
						continue;
					}
					if (!this.nominalPeer.contains(p)) {
						this.nominalPeer.add(p);
					}
				}
			}
		}
		catch (Exception e1) {
			throw new FSParseException(e1);
		}
		if (this.nominalPeer.isEmpty()) {
			Logger.normal(this, "No IP addresses found for identity '" + this.identityAsBase64String
					+ "', possibly at location '" + this.location + ": " + this.userToString());
			this.detectedPeer = null;
		}
		else {
			this.detectedPeer = this.nominalPeer.get(0);
		}
		this.updateShortToString();

		// Don't create trackers until we have a key
		this.currentTracker = null;
		this.previousTracker = null;

		this.timeLastSentPacket = -1;
		this.timeLastReceivedPacket = -1;
		this.timeLastReceivedSwapRequest = -1;
		this.timeLastRoutable = -1;
		this.timeAddedOrRestarted = System.currentTimeMillis();

		this.swapRequestsInterval = new SimpleRunningAverage(50, Node.MIN_INTERVAL_BETWEEN_INCOMING_SWAP_REQUESTS);
		this.probeRequestsInterval = new SimpleRunningAverage(50, Node.MIN_INTERVAL_BETWEEN_INCOMING_PROBE_REQUESTS);

		this.messageQueue = new PeerMessageQueue();

		this.decrementHTLAtMaximum = this.node.random.nextFloat() < Node.DECREMENT_AT_MAX_PROB;
		this.decrementHTLAtMinimum = this.node.random.nextFloat() < Node.DECREMENT_AT_MIN_PROB;

		this.pingNumber = this.node.random.nextLong();

		// A SimpleRunningAverage would be a bad choice because it would cause
		// oscillations.
		// So go for a filter.
		this.pingAverage =
				// Short average otherwise we will reject for a *REALLY* long time after
				// any spike.
				new TimeDecayingRunningAverage(1, TimeUnit.SECONDS.toMillis(30), 0, NodePinger.CRAZY_MAX_PING_TIME,
						this.node);

		// TDRA for probability of rejection
		this.pRejected = new TimeDecayingRunningAverage(0, TimeUnit.MINUTES.toMillis(4), 0.0, 1.0, this.node);

		// ARK stuff.

		this.parseARK(fs, true, false);

		// Now for the metadata.
		// The metadata sub-fieldset contains data about the node which is not part of the
		// node reference.
		// It belongs to this node, not to the node being described.
		// Therefore, if we are parsing a remotely supplied ref, ignore it.

		long now = System.currentTimeMillis();
		if (fromLocal) {

			SimpleFieldSet metadata = fs.subset("metadata");

			if (metadata != null) {

				this.location.setPeerLocations(fs.getAll("peersLocation"));

				// Don't be tolerant of nonexistant domains; this should be an IP address.
				Peer p = null;
				try {
					String detectedUDPString = metadata.get("detected.udp");
					if (detectedUDPString != null) {
						p = new Peer(detectedUDPString, false);
					}
				}
				catch (UnknownHostException | PeerParseException ex) {
					Logger.error(this, "detected.udp = " + metadata.get("detected.udp") + " - " + ex, ex);
				}
				if (p != null) {
					this.detectedPeer = p;
				}
				this.updateShortToString();
				this.timeLastReceivedPacket = metadata.getLong("timeLastReceivedPacket", -1);
				long timeLastConnected = metadata.getLong("timeLastConnected", -1);
				this.timeLastRoutable = metadata.getLong("timeLastRoutable", -1);
				if (timeLastConnected < 1 && this.timeLastReceivedPacket > 1) {
					timeLastConnected = this.timeLastReceivedPacket;
				}
				this.isConnected = new BooleanLastTrueTracker(timeLastConnected);
				if (this.timeLastRoutable < 1 && this.timeLastReceivedPacket > 1) {
					this.timeLastRoutable = this.timeLastReceivedPacket;
				}
				this.peerAddedTime = metadata.getLong("peerAddedTime", 0 // missing
				// peerAddedTime is
				// normal: Not only do
				// exported refs not
				// include it, opennet
				// peers don't either.
				);
				this.neverConnected = metadata.getBoolean("neverConnected", false);
				this.maybeClearPeerAddedTimeOnRestart(now);
				this.hadRoutableConnectionCount = metadata.getLong("hadRoutableConnectionCount", 0);
				this.routableConnectionCheckCount = metadata.getLong("routableConnectionCheckCount", 0);
			}
			else {
				this.isConnected = new BooleanLastTrueTracker();
			}
		}
		else {
			this.isConnected = new BooleanLastTrueTracker();
			this.neverConnected = true;
			this.peerAddedTime = now;
		}
		// populate handshakeIPs so handshakes can start ASAP
		this.lastAttemptedHandshakeIPUpdateTime = 0;
		this.maybeUpdateHandshakeIPs(true);

		this.listeningHandshakeBurstCount = 0;
		this.listeningHandshakeBurstSize = Node.MIN_BURSTING_HANDSHAKE_BURST_SIZE
				+ this.node.random.nextInt(Node.RANDOMIZED_BURSTING_HANDSHAKE_BURST_SIZE);

		if (this.isBurstOnly()) {
			Logger.minor(this,
					"First BurstOnly mode handshake in " + (this.sendHandshakeTime - now) + "ms for "
							+ this.shortToString() + " (count: " + this.listeningHandshakeBurstCount + ", size: "
							+ this.listeningHandshakeBurstSize + ')');
		}

		if (fromLocal) {
			this.innerCalcNextHandshake(false, false, now); // Let them connect so we can
		}
		// recognise we are NATed

		else {
			this.sendHandshakeTime = now; // Be sure we're ready to handshake right away
		}

		this.bytesInAtStartup = fs.getLong("totalInput", 0);
		this.bytesOutAtStartup = fs.getLong("totalOutput", 0);

		byte[] buffer = new byte[16];
		this.node.random.nextBytes(buffer);
		this.paddingGen = new MersenneTwister(buffer);

		if (fromLocal) {
			SimpleFieldSet f = fs.subset("full");
			if (this.fullFieldSet == null && f != null) {
				this.fullFieldSet = f;
			}
		}
		// If we got here, odds are we should consider writing to the peer-file
		this.writePeers();

		// status may have changed from PEER_NODE_STATUS_DISCONNECTED to
		// PEER_NODE_STATUS_NEVER_CONNECTED
	}

	/**
	 * @return True if the node has just connected and given us a noderef, and we did not
	 * know it beforehand. This makes it a temporary connection. At the moment this only
	 * happens on seednodes.
	 */
	protected boolean fromAnonymousInitiator() {
		return false;
	}

	abstract boolean dontKeepFullFieldSet();

	protected abstract void maybeClearPeerAddedTimeOnRestart(long now);

	private boolean parseARK(SimpleFieldSet fs, boolean onStartup, boolean forDiffNodeRef) {
		USK ark = null;
		long arkNo;
		try {
			String arkPubKey = fs.get("ark.pubURI");
			arkNo = fs.getLong("ark.number", -1);
			if (arkPubKey == null && arkNo <= -1) {
				// ark.pubURI and ark.number are always optional as a pair
				return false;
			}
			else if (arkPubKey != null && arkNo > -1) {
				if (onStartup) {
					arkNo++;
				}
				// this is the number of the ref we are parsing.
				// we want the number of the next edition.
				// on startup we want to fetch the old edition in case there's been a
				// corruption.
				FreenetURI uri = new FreenetURI(arkPubKey);
				ClientSSK ssk = new ClientSSK(uri);
				ark = new USK(ssk, arkNo);
			}
			else if (forDiffNodeRef && arkPubKey == null && this.myARK != null) {
				// get the ARK URI from the previous ARK and the edition from the SFS
				ark = this.myARK.copy(arkNo);
			}
			else if (forDiffNodeRef && arkPubKey != null && this.myARK != null) {
				// the SFS must contain an edition if it contains a arkPubKey
				Logger.error(this,
						"Got a differential node reference from " + this + " with an arkPubKey but no ARK edition");
				return false;
			}
			else {
				return false;
			}
		}
		catch (MalformedURLException | NumberFormatException ex) {
			Logger.error(this, "Couldn't parse ARK info for " + this + ": " + ex, ex);
		}

		synchronized (this) {
			if (ark != null) {
				if ((this.myARK == null) || ((this.myARK != ark) && !this.myARK.equals(ark))) {
					this.myARK = ark;
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Get my low-level address. This is the address that packets have been received from
	 * from this node.
	 *
	 * Normally this is the address that packets have been received from from this node.
	 * However, if ignoreSourcePort is set, we will search for a similar address with a
	 * different port number in the node reference.
	 */
	@Override
	public synchronized Peer getPeer() {
		return this.detectedPeer;
	}

	/**
	 * Returns an array with the advertised addresses and the detected one
	 */
	protected synchronized Peer[] getHandshakeIPs() {
		return this.handshakeIPs;
	}

	private String handshakeIPsToString() {
		Peer[] localHandshakeIPs;
		synchronized (this) {
			localHandshakeIPs = this.handshakeIPs;
		}
		if (localHandshakeIPs == null) {
			return "null";
		}
		StringBuilder toOutputString = new StringBuilder(1024);
		toOutputString.append("[ ");
		if (localHandshakeIPs.length != 0) {
			for (Peer localHandshakeIP : localHandshakeIPs) {
				if (localHandshakeIP == null) {
					toOutputString.append("null, ");
					continue;
				}
				toOutputString.append('\'');
				// Actually do the DNS request for the member Peer of localHandshakeIPs
				toOutputString.append(localHandshakeIP.getAddress(false));
				toOutputString.append('\'');
				toOutputString.append(", ");
			}
			// assert(toOutputString.length() >= 2) -- always true as
			// localHandshakeIPs.length != 0
			// remove last ", "
			toOutputString.deleteCharAt(toOutputString.length() - 1);
			toOutputString.deleteCharAt(toOutputString.length() - 1);
		}
		toOutputString.append(" ]");
		return toOutputString.toString();
	}

	/**
	 * Do the maybeUpdateHandshakeIPs DNS requests, but only if ignoreHostnames is false
	 * This method should only be called by maybeUpdateHandshakeIPs. Also removes dupes
	 * post-lookup.
	 */
	private Peer[] updateHandshakeIPs(Peer[] localHandshakeIPs, boolean ignoreHostnames) {
		for (Peer localHandshakeIP : localHandshakeIPs) {
			if (ignoreHostnames) {
				// Don't do a DNS request on the first cycle through PeerNodes by
				// DNSRequest
				// upon startup (I suspect the following won't do anything, but just in
				// case)
				if (logMINOR) {
					Logger.debug(this, "updateHandshakeIPs: calling getAddress(false) on Peer '" + localHandshakeIP
							+ "' for " + this.shortToString() + " (" + true + ')');
				}
				localHandshakeIP.getAddress(false);
			}
			else {
				// Actually do the DNS request for the member Peer of localHandshakeIPs
				if (logMINOR) {
					Logger.debug(this, "updateHandshakeIPs: calling getHandshakeAddress() on Peer '" + localHandshakeIP
							+ "' for " + this.shortToString() + " (" + false + ')');
				}
				localHandshakeIP.getHandshakeAddress();
			}
		}
		// De-dupe
		HashSet<Peer> ret = new HashSet<>();
		Collections.addAll(ret, localHandshakeIPs);
		return ret.toArray(new Peer[0]);
	}

	/**
	 * Do occasional DNS requests, but ignoreHostnames should be true on PeerNode
	 * construction
	 */
	public void maybeUpdateHandshakeIPs(boolean ignoreHostnames) {
		long now = System.currentTimeMillis();
		Peer localDetectedPeer;
		synchronized (this) {
			localDetectedPeer = this.detectedPeer;
			if ((now - this.lastAttemptedHandshakeIPUpdateTime) < TimeUnit.MINUTES.toMillis(5)) {
				// Logger.minor(this, "Looked up recently (localDetectedPeer =
				// "+localDetectedPeer + " : "+((localDetectedPeer == null) ? "" :
				// localDetectedPeer.getAddress(false).toString()));
				return;
			}
			// We want to come back right away for DNS requesting if this is our first
			// time through
			if (!ignoreHostnames) {
				this.lastAttemptedHandshakeIPUpdateTime = now;
			}
		}
		if (logMINOR) {
			Logger.minor(this,
					"Updating handshake IPs for peer '" + this.shortToString() + "' (" + ignoreHostnames + ')');
		}
		Peer[] myNominalPeer;

		// Don't synchronize while doing lookups which may take a long time!
		synchronized (this) {
			myNominalPeer = this.nominalPeer.toArray(new Peer[0]);
		}

		Peer[] localHandshakeIPs;
		if (myNominalPeer.length == 0) {
			if (localDetectedPeer == null) {
				synchronized (this) {
					this.handshakeIPs = null;
				}
				if (logMINOR) {
					Logger.minor(this, "1: maybeUpdateHandshakeIPs got a result of: " + this.handshakeIPsToString());
				}
				return;
			}
			localHandshakeIPs = new Peer[] { localDetectedPeer };
			localHandshakeIPs = this.updateHandshakeIPs(localHandshakeIPs, ignoreHostnames);
			synchronized (this) {
				this.handshakeIPs = localHandshakeIPs;
			}
			if (logMINOR) {
				Logger.minor(this, "2: maybeUpdateHandshakeIPs got a result of: " + this.handshakeIPsToString());
			}
			return;
		}

		// Hack for two nodes on the same IP that can't talk over inet for routing reasons
		FreenetInetAddress localhost = this.node.fLocalhostAddress;
		Peer[] nodePeers = this.outgoingMangler.getPrimaryIPAddress();

		List<Peer> localPeers;
		synchronized (this) {
			localPeers = new ArrayList<>(this.nominalPeer);
		}

		boolean addedLocalhost = false;
		Peer detectedDuplicate = null;
		for (Peer p : myNominalPeer) {
			if (p == null) {
				continue;
			}
			if (localDetectedPeer != null) {
				if ((p != localDetectedPeer) && p.equals(localDetectedPeer)) {
					// Equal but not the same object; need to update the copy.
					detectedDuplicate = p;
				}
			}
			FreenetInetAddress addr = p.getFreenetAddress();
			if (addr.equals(localhost)) {
				if (addedLocalhost) {
					continue;
				}
				addedLocalhost = true;
			}
			for (Peer nodePeer : nodePeers) {
				// REDFLAG - Two lines so we can see which variable is null when it NPEs
				FreenetInetAddress myAddr = nodePeer.getFreenetAddress();
				if (myAddr.equals(addr)) {
					if (!addedLocalhost) {
						localPeers.add(new Peer(localhost, p.getPort()));
					}
					addedLocalhost = true;
				}
			}
			if (localPeers.contains(p)) {
				continue;
			}
			localPeers.add(p);
		}

		localHandshakeIPs = localPeers.toArray(new Peer[0]);
		localHandshakeIPs = this.updateHandshakeIPs(localHandshakeIPs, ignoreHostnames);
		synchronized (this) {
			this.handshakeIPs = localHandshakeIPs;
			if ((detectedDuplicate != null) && detectedDuplicate.equals(localDetectedPeer)) {
				localDetectedPeer = detectedDuplicate;
				this.detectedPeer = detectedDuplicate;
			}
			this.updateShortToString();
		}
		if (logMINOR) {
			if (localDetectedPeer != null) {
				Logger.minor(this,
						"3: detectedPeer = " + localDetectedPeer + " (" + localDetectedPeer.getAddress(false) + ')');
			}
			Logger.minor(this, "3: maybeUpdateHandshakeIPs got a result of: " + this.handshakeIPsToString());
		}
	}

	/**
	 * Returns this peer's current keyspace location, or -1 if it is unknown.
	 */
	public double getLocation() {
		return this.location.getLocation();
	}

	public boolean shouldBeExcludedFromPeerList() {
		long now = System.currentTimeMillis();
		synchronized (this) {
			if (BLACK_MAGIC_BACKOFF_PRUNING_PERCENTAGE < this.backedOffPercent.currentValue()) {
				return true;
			}
			else {
				return BLACK_MAGIC_BACKOFF_PRUNING_TIME + now < this.getRoutingBackedOffUntilMax();
			}
		}
	}

	/**
	 * Returns an array copy of locations of this PeerNode's peers, or null if unknown.
	 */
	double[] getPeersLocationArray() {
		return this.location.getPeersLocationArray();
	}

	/**
	 * Finds the closest non-excluded peer.
	 * @param exclude the set of locations to exclude, may be null
	 * @return the closest non-excluded peer's location, or NaN if none is found
	 */
	public double getClosestPeerLocation(double l, Set<Double> exclude) {
		return this.location.getClosestPeerLocation(l, exclude);
	}

	public long getLocSetTime() {
		return this.location.getLocationSetTime();
	}

	/**
	 * Returns a unique node identifier (usefull to compare two peernodes).
	 */
	public int getIdentityHash() {
		return this.hashCode;
	}

	/**
	 * Returns true if the last-known build number for this peer is to old to allow
	 * traffic to be routed to it. This does not give any indication as to the connection
	 * status of the peer.
	 */
	public synchronized boolean isUnroutableOlderVersion() {
		return this.unroutableOlderVersion;
	}

	/**
	 * Returns true if this (or another) peer has reported to us that our build number is
	 * too old for data to be routed to us. In turn, we will not route data to them
	 * either. Does not strictly indicate that the peer is connected.
	 */
	public synchronized boolean isUnroutableNewerVersion() {
		return this.unroutableNewerVersion;
	}

	/**
	 * Returns true if requests can be routed through this peer. True if the peer's
	 * location is known, presently connected, and routing-compatible. That is, ignoring
	 * backoff, the peer's location is known, build number is compatible, and routing has
	 * not been explicitly disabled.
	 *
	 * Note possible deadlocks! PeerManager calls this, we call PeerManager in e.g.
	 * verified.
	 */
	@Override
	public boolean isRoutable() {
		if ((!this.isConnected()) || (!this.isRoutingCompatible())) {
			return false;
		}
		return this.location.isValidLocation();
	}

	synchronized boolean isInMandatoryBackoff(long now, boolean realTime) {
		long mandatoryBackoffUntil = realTime ? this.mandatoryBackoffUntilRT : this.mandatoryBackoffUntilBulk;
		if ((mandatoryBackoffUntil > -1 && now < mandatoryBackoffUntil)) {
			if (logMINOR) {
				Logger.minor(this, "In mandatory backoff");
			}
			return true;
		}
		return false;
	}

	/**
	 * Returns true if (apart from actually knowing the peer's location), it is presumed
	 * that this peer could route requests. True if this peer's build number is not
	 * 'too-old' or 'too-new', actively connected, and not marked as explicity disabled.
	 * Does not reflect any 'backoff' logic.
	 */
	public boolean isRoutingCompatible() {
		long now = System.currentTimeMillis(); // no System.currentTimeMillis in
												// synchronized
		synchronized (this) {
			if (this.isRoutable && !this.disableRouting) {
				this.timeLastRoutable = now;
				return true;
			}
			if (logMINOR) {
				Logger.minor(this, "Not routing compatible");
			}
			return false;
		}
	}

	@Override
	public boolean isConnected() {
		return this.isConnected.isTrue();
	}

	/**
	 * Send a message, off-thread, to this node.
	 * @param msg The message to be sent.
	 * @param cb The callback to be called when the packet has been sent, or null.
	 * @param ctr A callback to tell how many bytes were used to send this message.
	 */
	@Override
	public MessageItem sendAsync(Message msg, AsyncMessageCallback cb, ByteCounter ctr) throws NotConnectedException {
		if (ctr == null) {
			Logger.error(this, "ByteCounter null, so bandwidth usage cannot be logged. Refusing to send.",
					new Exception("debug"));
		}
		if (logMINOR) {
			Logger.minor(this, "Sending async: " + msg + " : " + cb + " on " + this + " for "
					+ this.node.getDarknetPortNumber() + " priority " + msg.getPriority());
		}
		if (!this.isConnected()) {
			if (cb != null) {
				cb.disconnected();
			}
			throw new NotConnectedException();
		}
		if (msg.getSource() != null) {
			Logger.error(this,
					"Messages should NOT be relayed as-is, they should always be re-created to clear any sub-messages etc, see comments in Message.java!: "
							+ msg,
					new Exception("error"));
		}
		this.addToLocalNodeSentMessagesToStatistic(msg);
		MessageItem item = new MessageItem(msg, (cb != null) ? new AsyncMessageCallback[] { cb } : null, ctr);
		long now = System.currentTimeMillis();
		this.reportBackoffStatus(now);
		int maxSize = this.getMaxPacketSize();
		int x = this.messageQueue.queueAndEstimateSize(item, maxSize);
		if (x > maxSize || !this.node.enablePacketCoalescing) {
			// If there is a packet's worth to send, wake up the packetsender.
			this.wakeUpSender();
		}
		// Otherwise we do not need to wake up the PacketSender
		// It will wake up before the maximum coalescing delay (100ms) because
		// it wakes up every 100ms *anyway*.
		return item;
	}

	@Override
	public void wakeUpSender() {
		if (logMINOR) {
			Logger.minor(this, "Waking up PacketSender");
		}
		this.node.ps.wakeUp();
	}

	@Override
	public boolean unqueueMessage(MessageItem message) {
		if (logMINOR) {
			Logger.minor(this, "Unqueueing message on " + this + " : " + message);
		}
		return this.messageQueue.removeMessage(message);
	}

	public long getMessageQueueLengthBytes() {
		return this.messageQueue.getMessageQueueLengthBytes();
	}

	/**
	 * Returns the number of milliseconds that it is estimated to take to transmit the
	 * currently queued packets.
	 */
	public long getProbableSendQueueTime() {
		double bandwidth = (this.getThrottle().getBandwidth() + 1.0);
		if (this.shouldThrottle()) {
			bandwidth = Math.min(bandwidth, ((double) this.node.getOutputBandwidthLimit()) / 2);
		}
		long length = this.getMessageQueueLengthBytes();
		return (long) (1000.0 * length / bandwidth);
	}

	/**
	 * @return The last time we received a packet.
	 */
	public synchronized long lastReceivedPacketTime() {
		return this.timeLastReceivedPacket;
	}

	public synchronized long lastReceivedDataPacketTime() {
		return this.timeLastReceivedDataPacket;
	}

	public synchronized long lastReceivedAckTime() {
		return this.timeLastReceivedAck;
	}

	public long timeLastConnected(long now) {
		return this.isConnected.getTimeLastTrue(now);
	}

	public synchronized long timeLastRoutable() {
		return this.timeLastRoutable;
	}

	@Override
	public void maybeRekey() {
		long now = System.currentTimeMillis();
		boolean shouldDisconnect;
		boolean shouldRekey;
		long timeWhenRekeyingShouldOccur;

		synchronized (this) {
			timeWhenRekeyingShouldOccur = this.timeLastRekeyed + FNPPacketMangler.SESSION_KEY_REKEYING_INTERVAL;
			shouldDisconnect = (timeWhenRekeyingShouldOccur + FNPPacketMangler.MAX_SESSION_KEY_REKEYING_DELAY < now)
					&& this.isRekeying;
			shouldRekey = (timeWhenRekeyingShouldOccur < now);
			if ((!shouldRekey)
					&& this.totalBytesExchangedWithCurrentTracker > FNPPacketMangler.AMOUNT_OF_BYTES_ALLOWED_BEFORE_WE_REKEY) {
				shouldRekey = true;
			}
		}

		if (shouldDisconnect) {
			String time = TimeUtil.formatTime(FNPPacketMangler.MAX_SESSION_KEY_REKEYING_DELAY);
			System.err.println("The peer (" + this + ") has been asked to rekey " + time + " ago... force disconnect.");
			Logger.error(this, "The peer (" + this + ") has been asked to rekey " + time + " ago... force disconnect.");
			this.forceDisconnect();
		}
		else if (shouldRekey) {
			this.startRekeying();
		}
	}

	@Override
	public void startRekeying() {
		long now = System.currentTimeMillis();
		synchronized (this) {
			if (this.isRekeying) {
				return;
			}
			this.isRekeying = true;
			this.sendHandshakeTime = now; // Immediately
			this.ctx = null;
		}
		Logger.normal(this, "We are asking for the key to be renewed (" + this.detectedPeer + ')');
	}

	/**
	 * @return The time this PeerNode was added to the node (persistent across restarts).
	 */
	public synchronized long getPeerAddedTime() {
		return this.peerAddedTime;
	}

	/**
	 * @return The time elapsed since this PeerNode was added to the node, or the node
	 * started up.
	 */
	public synchronized long timeSinceAddedOrRestarted() {
		return System.currentTimeMillis() - this.timeAddedOrRestarted;
	}

	/**
	 * Disconnected e.g. due to not receiving a packet for ages.
	 * @param dumpMessageQueue If true, clear the messages-to-send queue, and change the
	 * bootID so even if we reconnect the other side will know that a disconnect happened.
	 * If false, don't clear the messages yet. They will be cleared after an hour if the
	 * peer is disconnected at that point.
	 * @param dumpTrackers If true, dump the SessionKey's (i.e. dump the cryptographic
	 * data so we don't understand any packets they send us). <br>
	 * Possible arguments:
	 * <ul>
	 * <li>true, true => dump everything, immediate disconnect</li>
	 * <li>true, false => dump messages but keep trackers so we can acknowledge messages
	 * on their end for a while.</li>
	 * <li>false, false => tell the rest of the node that we have disconnected but do not
	 * immediately drop messages, continue to respond to their messages.</li>
	 * <li>false, true => dump crypto but keep messages. DOES NOT MAKE SENSE!!! DO NOT
	 * USE!!!
	 * </ul>
	 * @return True if the node was connected, false if it was not.
	 */
	public boolean disconnected(boolean dumpMessageQueue, boolean dumpTrackers) {
		assert (!((!dumpMessageQueue) && dumpTrackers)); // Invalid combination!
		final long now = System.currentTimeMillis();
		if (this.isRealConnection()) {
			Logger.normal(this, "Disconnected " + this, new Exception("debug"));
		}
		else if (logMINOR) {
			Logger.minor(this, "Disconnected " + this, new Exception("debug"));
		}
		this.node.usm.onDisconnect(this);
		if (dumpMessageQueue) {
			this.node.tracker.onRestartOrDisconnect(this);
		}
		this.node.failureTable.onDisconnect(this);
		this.node.peers.disconnected(this);
		this.node.nodeUpdater.disconnected(this);

		boolean ret;
		SessionKey cur;
		SessionKey prev;
		SessionKey unv;

		MessageItem[] messagesTellDisconnected = null;
		List<MessageItem> moreMessagesTellDisconnected = null;
		PacketFormat oldPacketFormat = null;
		synchronized (this) {
			this.disconnecting = false;
			// Force renegotiation.
			ret = this.isConnected.set(false, now);
			this.isRoutable = false;
			this.isRekeying = false;
			// Prevent sending packets to the node until that happens.
			cur = this.currentTracker;
			prev = this.previousTracker;
			unv = this.unverifiedTracker;
			if (dumpTrackers) {
				this.currentTracker = null;
				this.previousTracker = null;
				this.unverifiedTracker = null;
			}
			// Else DO NOT clear trackers, because hopefully it's a temporary connectivity
			// glitch.
			this.sendHandshakeTime = now;
			this.countFailedRevocationTransfers = 0;
			this.timePrevDisconnect = this.timeLastDisconnect;
			this.timeLastDisconnect = now;
			if (dumpMessageQueue) {
				// Reset the boot ID so that we get different trackers next time.
				this.myBootID = this.node.fastWeakRandom.nextLong();
				messagesTellDisconnected = this.grabQueuedMessageItems();
				oldPacketFormat = this.packetFormat;
				this.packetFormat = null;
			}
		}
		if (oldPacketFormat != null) {
			moreMessagesTellDisconnected = oldPacketFormat.onDisconnect();
		}
		if (messagesTellDisconnected != null) {
			if (logMINOR) {
				Logger.minor(this, "Messages to dump: " + messagesTellDisconnected.length);
			}
			for (MessageItem mi : messagesTellDisconnected) {
				mi.onDisconnect();
			}
		}
		if (moreMessagesTellDisconnected != null) {
			if (logMINOR) {
				Logger.minor(this, "Messages to dump: " + moreMessagesTellDisconnected.size());
			}
			for (MessageItem mi : moreMessagesTellDisconnected) {
				mi.onDisconnect();
			}
		}
		if (cur != null) {
			cur.disconnected();
		}
		if (prev != null) {
			prev.disconnected();
		}
		if (unv != null) {
			unv.disconnected();
		}

		this._lastThrottle.maybeDisconnected();

		this.node.lm.lostOrRestartedNode(this);

		if (this.peers.havePeer(this)) {
			this.setPeerNodeStatus(now);
		}
		if (!dumpMessageQueue) {
			// Wait for a while and then drop the messages if we haven't
			// reconnected.
			this.node.getTicker().queueTimedJob(new Runnable() {
				@Override
				public void run() {
					if ((!PeerNode.this.isConnected()) && PeerNode.this.timeLastDisconnect == now) {
						PacketFormat oldPacketFormat;
						synchronized (this) {
							if (PeerNode.this.isConnected()) {
								return;
							}
							// Reset the boot ID so that we get different trackers next
							// time.
							PeerNode.this.myBootID = PeerNode.this.node.fastWeakRandom.nextLong();
							oldPacketFormat = PeerNode.this.packetFormat;
							PeerNode.this.packetFormat = null;
						}
						MessageItem[] messagesTellDisconnected = PeerNode.this.grabQueuedMessageItems();
						if (messagesTellDisconnected != null) {
							for (MessageItem mi : messagesTellDisconnected) {
								mi.onDisconnect();
							}
						}
						if (oldPacketFormat != null) {
							List<MessageItem> moreMessagesTellDisconnected = oldPacketFormat.onDisconnect();
							if (moreMessagesTellDisconnected != null) {
								if (logMINOR) {
									Logger.minor(this, "Messages to dump: " + moreMessagesTellDisconnected.size());
								}
								for (MessageItem mi : moreMessagesTellDisconnected) {
									mi.onDisconnect();
								}
							}
						}
					}

				}
			}, CLEAR_MESSAGE_QUEUE_AFTER);
		}
		// Tell opennet manager even if this is darknet, because we may need more opennet
		// peers now.
		OpennetManager om = this.node.getOpennet();
		if (om != null) {
			om.onDisconnect(this);
		}
		this.outputLoadTrackerRealTime.failSlotWaiters(true);
		this.outputLoadTrackerBulk.failSlotWaiters(true);
		this.loadSenderRealTime.onDisconnect();
		this.loadSenderBulk.onDisconnect();
		return ret;
	}

	@Override
	public void forceDisconnect() {
		Logger.error(this, "Forcing disconnect on " + this, new Exception("debug"));
		this.disconnected(true, true); // always dump trackers, maybe dump messages
	}

	/**
	 * Grab all queued Message's.
	 * @return Null if no messages are queued, or an array of Message's.
	 */
	public MessageItem[] grabQueuedMessageItems() {
		return this.messageQueue.grabQueuedMessageItems();
	}

	/**
	 * @return The time at which we must send a packet, even if it means it will only
	 * contains ack requests etc., or Long.MAX_VALUE if we have no pending ack
	 * request/acks/etc. Note that if this is less than now, it may not be entirely
	 * accurate i.e. we definitely must send a packet, but don't rely on it to tell you
	 * exactly how overdue we are.
	 */
	public long getNextUrgentTime(long now) {
		long t = Long.MAX_VALUE;
		SessionKey cur;
		SessionKey prev;
		PacketFormat pf;
		synchronized (this) {
			if (!this.isConnected()) {
				return Long.MAX_VALUE;
			}
			cur = this.currentTracker;
			prev = this.previousTracker;
			pf = this.packetFormat;
			if (cur == null && prev == null) {
				return Long.MAX_VALUE;
			}
		}
		if (pf != null) {
			boolean canSend = cur != null && pf.canSend(cur);
			if (canSend) { // New messages are only sent on cur.
				long l = this.messageQueue.getNextUrgentTime(t, 0); // Need an accurate
																	// value
				// even if in the past.
				if (l < now && logMINOR) {
					Logger.minor(this, "Next urgent time from message queue less than now");
				}
				else if (logDEBUG) {
					Logger.debug(this, "Next urgent time is " + (l - now) + "ms on " + this);
				}
				t = l;
			}
			long l = pf.timeNextUrgent(canSend, now);
			if (l < now && logMINOR) {
				Logger.minor(this, "Next urgent time from packet format less than now on " + this);
			}
			t = Math.min(t, l);
		}
		return t;
	}

	/**
	 * @return The time at which we last sent a packet.
	 */
	public long lastSentPacketTime() {
		return this.timeLastSentPacket;
	}

	/**
	 * @return True, if we are disconnected and it has been a sufficient time period since
	 * we last sent a handshake attempt.
	 */
	public boolean shouldSendHandshake() {
		long now = System.currentTimeMillis();
		boolean tempShouldSendHandshake;
		synchronized (this) {
			if (this.disconnecting) {
				return false;
			}
			tempShouldSendHandshake = ((now > this.sendHandshakeTime) && (this.handshakeIPs != null)
					&& (this.isRekeying || !this.isConnected()));
		}
		if (logMINOR) {
			Logger.minor(this, "shouldSendHandshake(): initial = " + tempShouldSendHandshake);
		}
		if (tempShouldSendHandshake && (this.hasLiveHandshake(now))) {
			tempShouldSendHandshake = false;
		}
		if (tempShouldSendHandshake) {
			if (this.isBurstOnly()) {
				synchronized (this) {
					this.isBursting = true;
				}
				this.setPeerNodeStatus(System.currentTimeMillis());
			}
			else {
				return true;
			}
		}
		if (logMINOR) {
			Logger.minor(this, "shouldSendHandshake(): final = " + tempShouldSendHandshake);
		}
		return tempShouldSendHandshake;
	}

	public long timeSendHandshake(long now) {
		if (this.hasLiveHandshake(now)) {
			return Long.MAX_VALUE;
		}
		synchronized (this) {
			if (this.disconnecting) {
				return Long.MAX_VALUE;
			}
			if (this.handshakeIPs == null) {
				return Long.MAX_VALUE;
			}
			if (!(this.isRekeying || !this.isConnected())) {
				return Long.MAX_VALUE;
			}
			return this.sendHandshakeTime;
		}
	}

	/**
	 * Does the node have a live handshake in progress?
	 * @param now The current time.
	 */
	public boolean hasLiveHandshake(long now) {
		KeyAgreementSchemeContext c;
		synchronized (this) {
			c = this.ctx;
		}
		if (c != null && logDEBUG) {
			Logger.minor(this, "Last used (handshake): " + (now - c.lastUsedTime()));
		}
		return !((c == null) || (now - c.lastUsedTime() > Node.HANDSHAKE_TIMEOUT));
	}

	boolean firstHandshake = true;

	/**
	 * Set sendHandshakeTime, and return whether to fetch the ARK.
	 */
	protected boolean innerCalcNextHandshake(boolean successfulHandshakeSend, boolean dontFetchARK, long now) {
		if (this.isBurstOnly()) {
			return this.calcNextHandshakeBurstOnly(now);
		}
		synchronized (this) {
			long delay;
			if (this.unroutableOlderVersion || this.unroutableNewerVersion || this.disableRouting) {
				// Let them know we're here, but have no hope of routing general data to
				// them.
				delay = Node.MIN_TIME_BETWEEN_VERSION_SENDS
						+ this.node.random.nextInt(Node.RANDOMIZED_TIME_BETWEEN_VERSION_SENDS);
			}
			else if (this.invalidVersion() && !this.firstHandshake) {
				delay = Node.MIN_TIME_BETWEEN_VERSION_PROBES
						+ this.node.random.nextInt(Node.RANDOMIZED_TIME_BETWEEN_VERSION_PROBES);
			}
			else {
				delay = Node.MIN_TIME_BETWEEN_HANDSHAKE_SENDS
						+ this.node.random.nextInt(Node.RANDOMIZED_TIME_BETWEEN_HANDSHAKE_SENDS);
			}
			// FIXME proper multi-homing support!
			delay /= ((this.handshakeIPs != null) ? this.handshakeIPs.length : 1);
			if (delay < 3000) {
				delay = 3000;
			}
			this.sendHandshakeTime = now + delay;
			if (logMINOR) {
				Logger.minor(this, "Next handshake in " + delay + " on " + this);
			}

			if (successfulHandshakeSend) {
				this.firstHandshake = false;
			}
			this.handshakeCount++;
			return this.handshakeCount == MAX_HANDSHAKE_COUNT;
		}
	}

	private synchronized boolean calcNextHandshakeBurstOnly(long now) {
		boolean fetchARKFlag = false;
		this.listeningHandshakeBurstCount++;
		if (this.isBurstOnly()) {
			if (this.listeningHandshakeBurstCount >= this.listeningHandshakeBurstSize) {
				this.listeningHandshakeBurstCount = 0;
				fetchARKFlag = true;
			}
		}
		long delay;
		if (this.listeningHandshakeBurstCount == 0) { // 0 only if we just reset it above
			delay = Node.MIN_TIME_BETWEEN_BURSTING_HANDSHAKE_BURSTS
					+ this.node.random.nextInt(Node.RANDOMIZED_TIME_BETWEEN_BURSTING_HANDSHAKE_BURSTS);
			this.listeningHandshakeBurstSize = Node.MIN_BURSTING_HANDSHAKE_BURST_SIZE
					+ this.node.random.nextInt(Node.RANDOMIZED_BURSTING_HANDSHAKE_BURST_SIZE);
			this.isBursting = false;
		}
		else {
			delay = Node.MIN_TIME_BETWEEN_HANDSHAKE_SENDS
					+ this.node.random.nextInt(Node.RANDOMIZED_TIME_BETWEEN_HANDSHAKE_SENDS);
		}
		// FIXME proper multi-homing support!
		delay /= ((this.handshakeIPs != null) ? this.handshakeIPs.length : 1);
		if (delay < 3000) {
			delay = 3000;
		}

		this.sendHandshakeTime = now + delay;
		if (logMINOR) {
			Logger.minor(this,
					"Next BurstOnly mode handshake in " + (this.sendHandshakeTime - now) + "ms for "
							+ this.shortToString() + " (count: " + this.listeningHandshakeBurstCount + ", size: "
							+ this.listeningHandshakeBurstSize + ") on " + this,
					new Exception("double-called debug"));
		}
		return fetchARKFlag;
	}

	protected void calcNextHandshake(boolean successfulHandshakeSend, boolean dontFetchARK, boolean notRegistered) {
		long now = System.currentTimeMillis();
		boolean fetchARKFlag = this.innerCalcNextHandshake(successfulHandshakeSend, dontFetchARK, now);
		if (!notRegistered) {
			this.setPeerNodeStatus(now); // Because of isBursting being set above and it
		}
		// can't
		// hurt others
		// Don't fetch ARKs for peers we have verified (through handshake) to be
		// incompatible with us
		if (fetchARKFlag && !dontFetchARK) {
			long arkFetcherStartTime1 = System.currentTimeMillis();
			this.startARKFetcher();
			long arkFetcherStartTime2 = System.currentTimeMillis();
			if ((arkFetcherStartTime2 - arkFetcherStartTime1) > 500) {
				Logger.normal(this, "arkFetcherStartTime2 is more than half a second after arkFetcherStartTime1 ("
						+ (arkFetcherStartTime2 - arkFetcherStartTime1) + ") working on " + this.shortToString());
			}
		}
	}

	/**
	 * If the outgoingMangler allows bursting, we still don't want to burst *all the
	 * time*, because it may be mistaken in its detection of a port forward. So from time
	 * to time we will aggressively handshake anyway. This flag is set once every
	 * UPDATE_BURST_NOW_PERIOD.
	 */
	private boolean burstNow;

	private long timeSetBurstNow;
	static final long UPDATE_BURST_NOW_PERIOD = TimeUnit.MINUTES.toMillis(5);

	/**
	 * Burst only 19 in 20 times if definitely port forwarded. Save entropy by writing
	 * this as 20 not 0.95.
	 */
	static final int P_BURST_IF_DEFINITELY_FORWARDED = 20;

	public boolean isBurstOnly() {
		AddressTracker.Status status = this.outgoingMangler.getConnectivityStatus();
		if (status == AddressTracker.Status.DONT_KNOW) {
			return false;
		}
		if (status == AddressTracker.Status.DEFINITELY_NATED || status == AddressTracker.Status.MAYBE_NATED) {
			return false;
		}

		// For now. FIXME try it with a lower probability when we're sure that the
		// packet-deltas mechanisms works.
		if (status == AddressTracker.Status.MAYBE_PORT_FORWARDED) {
			return false;
		}
		long now = System.currentTimeMillis();
		if (now - this.timeSetBurstNow > UPDATE_BURST_NOW_PERIOD) {
			this.burstNow = (this.node.random.nextInt(P_BURST_IF_DEFINITELY_FORWARDED) == 0);
			this.timeSetBurstNow = now;
		}
		return this.burstNow;
	}

	/**
	 * Call this method when a handshake request has been sent.
	 */
	public void sentHandshake(boolean notRegistered) {
		if (logMINOR) {
			Logger.minor(this, "sentHandshake(): " + this);
		}
		this.calcNextHandshake(true, false, notRegistered);
	}

	/**
	 * Call this method when a handshake request could not be sent (i.e. no IP address
	 * available) sent.
	 */
	public void couldNotSendHandshake(boolean notRegistered) {
		if (logMINOR) {
			Logger.minor(this, "couldNotSendHandshake(): " + this);
		}
		this.calcNextHandshake(false, false, notRegistered);
	}

	/**
	 * @return The maximum time between received packets.
	 */
	public long maxTimeBetweenReceivedPackets() {
		return Node.MAX_PEER_INACTIVITY;
	}

	/**
	 * @return The maximum time between received packets.
	 */
	public long maxTimeBetweenReceivedAcks() {
		return Node.MAX_PEER_INACTIVITY;
	}

	/**
	 * Low-level ping this node.
	 * @return True if we received a reply inside 2000ms. (If we have heavy packet loss,
	 * it can take that long to resend).
	 */
	public boolean ping(int pingID) throws NotConnectedException {
		Message ping = DMT.createFNPPing(pingID);
		this.node.usm.send(this, ping, this.node.dispatcher.pingCounter);
		Message msg;
		try {
			msg = this.node.usm.waitFor(
					MessageFilter.create().setTimeout(2000).setType(DMT.FNPPong).setField(DMT.PING_SEQNO, pingID),
					null);
		}
		catch (DisconnectedException ignored) {
			throw new NotConnectedException("Disconnected while waiting for pong");
		}
		return msg != null;
	}

	/**
	 * Decrement the HTL (or not), in accordance with our probabilistic HTL rules. Whether
	 * to decrement is determined once for each connection, rather than for every request,
	 * because if we don't we would get a predictable fraction of requests with each HTL -
	 * this pattern could give away a lot of information close to the originator. Although
	 * it's debatable whether it's worth worrying about given all the other information
	 * they have if close by ...
	 * @param htl The old HTL.
	 * @return The new HTL.
	 */
	public short decrementHTL(short htl) {
		short max = this.node.maxHTL();
		if (htl > max) {
			htl = max;
		}
		if (htl <= 0) {
			return 0;
		}
		if (htl == max) {
			if (this.decrementHTLAtMaximum || this.node.disableProbabilisticHTLs) {
				htl--;
			}
			return htl;
		}
		if (htl == 1) {
			if (this.decrementHTLAtMinimum || this.node.disableProbabilisticHTLs) {
				htl--;
			}
			return htl;
		}
		htl--;
		return htl;
	}

	/**
	 * Enqueue a message to be sent to this node and wait up to a minute for it to be
	 * transmitted and acknowledged.
	 */
	public void sendSync(Message req, ByteCounter ctr, boolean realTime)
			throws NotConnectedException, SyncSendWaitedTooLongException {
		SyncMessageCallback cb = new SyncMessageCallback();
		MessageItem item = this.sendAsync(req, cb, ctr);
		cb.waitForSend(TimeUnit.MINUTES.toMillis(1));
		if (!cb.done) {
			Logger.warning(this, "Waited too long for a blocking send for " + req + " to " + PeerNode.this,
					new Exception("error"));
			this.localRejectedOverload("SendSyncTimeout", realTime);
			// Try to unqueue it, since it presumably won't be of any use now.
			if (!this.messageQueue.removeMessage(item)) {
				cb.waitForSend(TimeUnit.SECONDS.toMillis(10));
				if (!cb.done) {
					Logger.error(this, "Waited too long for blocking send and then could not unqueue for " + req
							+ " to " + PeerNode.this, new Exception("error"));
					// Can't cancel yet can't send, something seriously wrong.
					// Treat as fatal timeout as probably their fault.
					// FIXME: We have already waited more than the no-messages timeout,
					// but should we wait that period again???
					this.fatalTimeout();
					// Then throw the error.
				}
				else {
					return;
				}
			}
			throw new SyncSendWaitedTooLongException();
		}
	}

	/**
	 * Determines the degree of the peer via the locations of its peers it provides.
	 * @return The number of peers this peer reports having, or 0 if this peer does not
	 * provide that information.
	 */
	public int getDegree() {
		return this.location.getDegree();
	}

	public void updateLocation(double newLoc, double[] newLocs) {
		boolean anythingChanged = this.location.updateLocation(newLoc, newLocs);
		this.node.peers.updatePMUserAlert();
		if (anythingChanged) {
			this.writePeers();
		}
		this.setPeerNodeStatus(System.currentTimeMillis());
	}

	/** Write the peers list affecting this node. */
	protected abstract void writePeers();

	/**
	 * Should we reject a swap request?
	 */
	public boolean shouldRejectSwapRequest() {
		long now = System.currentTimeMillis();
		synchronized (this) {
			if (this.timeLastReceivedSwapRequest > 0) {
				long timeSinceLastTime = now - this.timeLastReceivedSwapRequest;
				this.swapRequestsInterval.report(timeSinceLastTime);
				double averageInterval = this.swapRequestsInterval.currentValue();
				if (averageInterval >= Node.MIN_INTERVAL_BETWEEN_INCOMING_SWAP_REQUESTS) {
					this.timeLastReceivedSwapRequest = now;
					return false;
				}
				else {
					return true;
				}
			}
			this.timeLastReceivedSwapRequest = now;
		}
		return false;
	}

	/**
	 * Should we reject a swap request?
	 */
	public boolean shouldRejectProbeRequest() {
		long now = System.currentTimeMillis();
		synchronized (this) {
			if (this.timeLastReceivedProbeRequest > 0) {
				long timeSinceLastTime = now - this.timeLastReceivedProbeRequest;
				this.probeRequestsInterval.report(timeSinceLastTime);
				double averageInterval = this.probeRequestsInterval.currentValue();
				if (averageInterval >= Node.MIN_INTERVAL_BETWEEN_INCOMING_PROBE_REQUESTS) {
					this.timeLastReceivedProbeRequest = now;
					return false;
				}
				else {
					return true;
				}
			}
			this.timeLastReceivedProbeRequest = now;
		}
		return false;
	}

	/**
	 * IP on the other side appears to have changed...
	 * @param newPeer The new address of the peer.
	 */
	public void changedIP(Peer newPeer) {
		this.setDetectedPeer(newPeer);
	}

	private void setDetectedPeer(Peer newPeer) {
		// Also, we need to call .equals() to propagate any DNS lookups that have been
		// done if the two have the same domain.
		Peer p = newPeer;
		newPeer = newPeer.dropHostName();
		if (newPeer == null) {
			Logger.error(this, "Impossible: No address for detected peer! " + p + " on " + this);
			return;
		}
		synchronized (this) {
			Peer oldPeer = this.detectedPeer;
			if (oldPeer == null || !oldPeer.equals(newPeer)) {
				this.detectedPeer = newPeer;
				this.updateShortToString();
				// IP has changed, it is worth looking up the DNS address again.
				this.lastAttemptedHandshakeIPUpdateTime = 0;
				if (!this.isConnected()) {
					return;
				}
			}
			else {
				return;
			}
		}
		this.getThrottle().maybeDisconnected();
		this.sendIPAddressMessage();
	}

	/**
	 * @return The current primary SessionKey, or null if we don't have one.
	 */
	@Override
	public synchronized SessionKey getCurrentKeyTracker() {
		return this.currentTracker;
	}

	/**
	 * @return The previous primary SessionKey, or null if we don't have one.
	 */
	@Override
	public synchronized SessionKey getPreviousKeyTracker() {
		return this.previousTracker;
	}

	/**
	 * @return The unverified SessionKey, if any, or null if we don't have one. The caller
	 * MUST call verified(KT) if a decrypt succeeds with this KT.
	 */
	@Override
	public synchronized SessionKey getUnverifiedKeyTracker() {
		return this.unverifiedTracker;
	}

	private String shortToString;

	private void updateShortToString() {
		this.shortToString = super.toString() + '@' + this.detectedPeer + '@'
				+ HexUtil.bytesToHex(this.peerECDSAPubKeyHash);
	}

	/**
	 * @return short version of toString() *** Note that this is not synchronized! It is
	 * used by logging in code paths that will deadlock if it is synchronized! ***
	 */
	@Override
	public String shortToString() {
		return this.shortToString;
	}

	/**
	 * Update timeLastReceivedPacket
	 * @param dontLog If true, don't log an error or throw an exception if we are not
	 * connected. This can be used in handshaking when the connection hasn't been verified
	 * yet.
	 * @param dataPacket If this is a real packet, as opposed to a handshake packet.
	 */
	@Override
	public void receivedPacket(boolean dontLog, boolean dataPacket) {
		synchronized (this) {
			if ((!this.isConnected()) && (!dontLog)) {
				// Don't log if we are disconnecting, because receiving packets during
				// disconnecting is normal.
				// That includes receiving packets after we have technically disconnected
				// already.
				// A race condition involving forceCancelDisconnecting causing a mistaken
				// log message anyway
				// is conceivable, but unlikely...
				if ((this.unverifiedTracker == null) && (this.currentTracker == null) && !this.disconnecting) {
					Logger.error(this, "Received packet while disconnected!: " + this, new Exception("error"));
				}
				else if (logMINOR) {
					Logger.minor(this,
							"Received packet while disconnected on " + this + " - recently disconnected() ?");
				}
			}
			else {
				if (logMINOR) {
					Logger.minor(this, "Received packet on " + this);
				}
			}
		}
		long now = System.currentTimeMillis();
		synchronized (this) {
			this.timeLastReceivedPacket = now;
			if (dataPacket) {
				this.timeLastReceivedDataPacket = now;
			}
		}
	}

	@Override
	public synchronized void receivedAck(long now) {
		if (this.timeLastReceivedAck < now) {
			this.timeLastReceivedAck = now;
		}
	}

	/**
	 * Update timeLastSentPacket
	 */
	@Override
	public void sentPacket() {
		this.timeLastSentPacket = System.currentTimeMillis();
	}

	public synchronized KeyAgreementSchemeContext getKeyAgreementSchemeContext() {
		return this.ctx;
	}

	public synchronized void setKeyAgreementSchemeContext(KeyAgreementSchemeContext ctx2) {
		this.ctx = ctx2;
		if (logMINOR) {
			Logger.minor(this, "setKeyAgreementSchemeContext(" + ctx2 + ") on " + this);
		}
	}

	/**
	 * Called when we have completed a handshake, and have a new session key. Creates a
	 * new tracker and demotes the old one. Deletes the old one if the bootID isn't
	 * recognized, since if the node has restarted we cannot recover old messages. In more
	 * detail:
	 * <ul>
	 * <li>Process the new noderef (check if it's valid, pick up any new information
	 * etc).</li>
	 * <li>Handle version conflicts (if the node is too old, or we are too old, we mark it
	 * as non-routable, but some messages will still be exchanged e.g. Update Over
	 * Mandatory stuff).</li>
	 * <li>Deal with key trackers (if we just got message 4, the new key tracker becomes
	 * current; if we just got message 3, it's possible that our message 4 will be lost in
	 * transit, so we make the new tracker unverified. It will be promoted to current if
	 * we get a packet on it.. if the node has restarted, we dump the old key trackers,
	 * otherwise current becomes previous).</li>
	 * <li>Complete the connection process: update the node's status, send initial
	 * messages, update the last-received-packet timestamp, etc.</li>
	 * </ul>
	 * @param thisBootID The boot ID of the peer we have just connected to. This is simply
	 * a random number regenerated on every startup of the node. We use it to determine
	 * whether the node has restarted since we last saw it.
	 * @param data Byte array from which to read the new noderef.
	 * @param offset Offset to start reading at.
	 * @param length Number of bytes to read.
	 * @param replyTo The IP the handshake came in on.
	 * @param trackerID The tracker ID proposed by the other side. If -1, create a new
	 * tracker. If any other value, check whether we have it, and if we do, return that,
	 * otherwise return the ID of the new tracker.
	 * @param isJFK4 If true, we are processing a JFK(4) and must respect the tracker ID
	 * chosen by the responder. If false, we are processing a JFK(3) and we can either
	 * reuse the suggested tracker ID, which the other side is able to reuse, or we can
	 * create a new tracker ID.
	 * @param jfk4SameAsOld If true, the responder chose to use the tracker ID that we
	 * provided. If we don't have it now the connection fails.
	 * @return The ID of the new PacketTracker. If this is different to the passed-in
	 * trackerID, then it's a new tracker. -1 to indicate failure.
	 */
	public long completedHandshake(long thisBootID, byte[] data, int offset, int length, BlockCipher outgoingCipher,
			byte[] outgoingKey, BlockCipher incommingCipher, byte[] incommingKey, Peer replyTo, boolean unverified,
			int negType, long trackerID, boolean isJFK4, boolean jfk4SameAsOld, byte[] hmacKey, BlockCipher ivCipher,
			byte[] ivNonce, int ourInitialSeqNum, int theirInitialSeqNum, int ourInitialMsgID, int theirInitialMsgID) {
		long now = System.currentTimeMillis();
		if (logMINOR) {
			Logger.minor(this, "Tracker ID " + trackerID + " isJFK4=" + isJFK4 + " jfk4SameAsOld=" + jfk4SameAsOld);
		}
		if (trackerID < 0) {
			trackerID = Math.abs(this.node.random.nextLong());
		}

		// Update sendHandshakeTime; don't send another handshake for a while.
		// If unverified, "a while" determines the timeout; if not, it's just good
		// practice to avoid a race below.
		if (!(this.isSeed() && this instanceof SeedServerPeerNode)) {
			this.calcNextHandshake(true, true, false);
		}
		this.stopARKFetcher();
		try {
			// First, the new noderef
			this.processNewNoderef(data, offset, length);
		}
		catch (FSParseException e1) {
			synchronized (this) {
				this.bogusNoderef = true;
				// Disconnect, something broke
				this.isConnected.set(false, now);
			}
			Logger.error(this, "Failed to parse new noderef for " + this + ": " + e1, e1);
			this.node.peers.disconnected(this);
			return -1;
		}
		boolean routable = true;
		boolean newer = false;
		boolean older = false;

		if (this.isSeed()) {
			routable = false;
			if (logMINOR) {
				Logger.minor(this, "Not routing traffic to " + this + " it's for announcement.");
			}
		}
		else if (this.bogusNoderef) {
			Logger.normal(this, "Not routing traffic to " + this + " - bogus noderef");
			routable = false;
			// FIXME: It looks like bogusNoderef will just be set to false a few lines
			// later...
		}
		else if (this.reverseInvalidVersion()) {
			Logger.normal(this, "Not routing traffic to " + this + " - reverse invalid version "
					+ Version.getVersionString() + " for peer's lastGoodversion: " + this.getLastGoodVersion());
			newer = true;
		}

		if (this.forwardInvalidVersion()) {
			Logger.normal(this, "Not routing traffic to " + this + " - invalid version " + this.getVersion());
			older = true;
			routable = false;
		}
		else if (Math.abs(this.clockDelta) > MAX_CLOCK_DELTA) {
			Logger.normal(this, "Not routing traffic to " + this + " - clock problems");
			routable = false;
		}

		this.changedIP(replyTo);
		boolean bootIDChanged;
		boolean wasARekey = false;
		SessionKey oldPrev = null;
		SessionKey oldCur = null;
		SessionKey newTracker;
		MessageItem[] messagesTellDisconnected = null;
		PacketFormat oldPacketFormat = null;
		synchronized (this) {
			this.disconnecting = false;
			// FIXME this shouldn't happen, does it?
			if (this.currentTracker != null) {
				if (Arrays.equals(outgoingKey, this.currentTracker.outgoingKey)
						&& Arrays.equals(incommingKey, this.currentTracker.incommingKey)) {
					Logger.error(this, "completedHandshake() with identical key to current, maybe replayed JFK(4)?");
					return -1;
				}
			}
			if (this.previousTracker != null) {
				if (Arrays.equals(outgoingKey, this.previousTracker.outgoingKey)
						&& Arrays.equals(incommingKey, this.previousTracker.incommingKey)) {
					Logger.error(this, "completedHandshake() with identical key to previous, maybe replayed JFK(4)?");
					return -1;
				}
			}
			if (this.unverifiedTracker != null) {
				if (Arrays.equals(outgoingKey, this.unverifiedTracker.outgoingKey)
						&& Arrays.equals(incommingKey, this.unverifiedTracker.incommingKey)) {
					Logger.error(this, "completedHandshake() with identical key to unverified, maybe replayed JFK(4)?");
					return -1;
				}
			}
			this.handshakeCount = 0;
			this.bogusNoderef = false;
			// Don't reset the uptime if we rekey
			if (!this.isConnected()) {
				this.connectedTime = now;
				this.countSelectionsSinceConnected = 0;
				this.sentInitialMessages = false;
			}
			else {
				wasARekey = true;
			}
			this.disableRouting = this.disableRoutingHasBeenSetLocally || this.disableRoutingHasBeenSetRemotely;
			this.isRoutable = routable;
			this.unroutableNewerVersion = newer;
			this.unroutableOlderVersion = older;
			long oldBootID;
			oldBootID = this.bootID.getAndSet(thisBootID);
			bootIDChanged = oldBootID != thisBootID;
			if (this.myLastSuccessfulBootID != this.myBootID) {
				// If our own boot ID changed, because we forcibly disconnected,
				// we need to use a new tracker. This is equivalent to us having
				// restarted,
				// from the point of view of the other side, but since we haven't we need
				// to track it here.
				bootIDChanged = true;
				this.myLastSuccessfulBootID = this.myBootID;
			}
			if (bootIDChanged && wasARekey) {
				// This can happen if the other side thought we disconnected but we didn't
				// think they did.
				Logger.normal(this, "Changed boot ID while rekeying! from " + oldBootID + " to " + thisBootID + " for "
						+ this.getPeer());
				wasARekey = false;
				this.connectedTime = now;
				this.countSelectionsSinceConnected = 0;
				this.sentInitialMessages = false;
			}
			else if (bootIDChanged && logMINOR) {
				Logger.minor(this,
						"Changed boot ID from " + oldBootID + " to " + thisBootID + " for " + this.getPeer());
			}

			if (bootIDChanged) {
				oldPrev = this.previousTracker;
				oldCur = this.currentTracker;
				this.previousTracker = null;
				this.currentTracker = null;
				// Messages do not persist across restarts.
				// Generally they would be incomprehensible, anything that isn't should be
				// sent as
				// connection initial messages by maybeOnConnect().
				messagesTellDisconnected = this.grabQueuedMessageItems();
				this.offeredManifestVersion = 0;
				oldPacketFormat = this.packetFormat;
				this.packetFormat = null;
			} // else it's a rekey

			newTracker = new SessionKey(this, outgoingCipher, outgoingKey, incommingCipher, incommingKey, ivCipher,
					ivNonce, hmacKey, new NewPacketFormatKeyContext(ourInitialSeqNum, theirInitialSeqNum), trackerID);
			if (logMINOR) {
				Logger.minor(this, "New key tracker in completedHandshake: " + newTracker + " for "
						+ this.shortToString() + " neg type " + negType);
			}
			if (unverified) {
				if (this.unverifiedTracker != null) {
					// Keep the old unverified tracker if possible.
					if (this.previousTracker == null) {
						this.previousTracker = this.unverifiedTracker;
					}
				}
				this.unverifiedTracker = newTracker;
			}
			else {
				oldPrev = this.previousTracker;
				this.previousTracker = this.currentTracker;
				this.currentTracker = newTracker;
				// Keep the old unverified tracker.
				// In case of a race condition (two setups between A and B complete at the
				// same time),
				// we might want to keep the unverified tracker rather than the previous
				// tracker.
				this.neverConnected = false;
				this.maybeClearPeerAddedTimeOnConnect();
			}
			this.isConnected.set(this.currentTracker != null, now);
			this.ctx = null;
			this.isRekeying = false;
			this.timeLastRekeyed = now - (unverified ? 0 : FNPPacketMangler.MAX_SESSION_KEY_REKEYING_DELAY / 2);
			this.totalBytesExchangedWithCurrentTracker = 0;
			// This has happened in the past, and caused problems, check for it.
			if (this.currentTracker != null && this.previousTracker != null
					&& Arrays.equals(this.currentTracker.outgoingKey, this.previousTracker.outgoingKey)
					&& Arrays.equals(this.currentTracker.incommingKey, this.previousTracker.incommingKey)) {
				Logger.error(this, "currentTracker key equals previousTracker key: cur " + this.currentTracker
						+ " prev " + this.previousTracker);
			}
			if (this.previousTracker != null && this.unverifiedTracker != null
					&& Arrays.equals(this.previousTracker.outgoingKey, this.unverifiedTracker.outgoingKey)
					&& Arrays.equals(this.previousTracker.incommingKey, this.unverifiedTracker.incommingKey)) {
				Logger.error(this, "previousTracker key equals unverifiedTracker key: prev " + this.previousTracker
						+ " unv " + this.unverifiedTracker);
			}
			this.timeLastSentPacket = now;
			if (this.packetFormat == null) {
				this.packetFormat = new NewPacketFormat(this, ourInitialMsgID, theirInitialMsgID);
			}
			// Completed setup counts as received data packet, for purposes of avoiding
			// spurious disconnections.
			this.timeLastReceivedPacket = now;
			this.timeLastReceivedDataPacket = now;
			this.timeLastReceivedAck = now;
		}
		if (messagesTellDisconnected != null) {
			for (MessageItem item : messagesTellDisconnected) {
				item.onDisconnect();
			}
		}

		if (bootIDChanged) {
			this.node.lm.lostOrRestartedNode(this);
			this.node.usm.onRestart(this);
			this.node.tracker.onRestartOrDisconnect(this);
		}
		if (oldPrev != null) {
			oldPrev.disconnected();
		}
		if (oldCur != null) {
			oldCur.disconnected();
		}
		if (oldPacketFormat != null) {
			List<MessageItem> tellDisconnect = oldPacketFormat.onDisconnect();
			if (tellDisconnect != null) {
				for (MessageItem item : tellDisconnect) {
					item.onDisconnect();
				}
			}
		}
		PacketThrottle throttle;
		synchronized (this) {
			throttle = this._lastThrottle;
		}
		throttle.maybeDisconnected();

		Logger.normal(this,
				"Completed handshake with " + this + " on " + replyTo + " - current: " + this.currentTracker + " old: "
						+ this.previousTracker + " unverified: " + this.unverifiedTracker + " bootID: " + thisBootID
						+ (bootIDChanged ? "(changed) " : "") + " for " + this.shortToString());

		this.setPeerNodeStatus(now);

		if (newer || older || !this.isConnected()) {
			this.node.peers.disconnected(this);
		}
		else if (!wasARekey) {
			this.node.peers.addConnectedPeer(this);
			this.maybeOnConnect();
		}

		this.crypto.maybeBootConnection(this, replyTo.getFreenetAddress());

		return trackerID;
	}

	protected abstract void maybeClearPeerAddedTimeOnConnect();

	@Override
	public long getBootID() {
		return this.bootID.get();
	}

	private final Object arkFetcherSync = new Object();

	void startARKFetcher() {
		// FIXME any way to reduce locking here?
		if (!this.node.enableARKs) {
			return;
		}
		synchronized (this.arkFetcherSync) {
			if (this.myARK == null) {
				Logger.minor(this, "No ARK for " + this + " !!!!");
				return;
			}
			if (this.arkFetcher == null) {
				Logger.minor(this, "Starting ARK fetcher for " + this + " : " + this.myARK);
				this.arkFetcher = this.node.clientCore.uskManager.subscribeContent(this.myARK, this, true,
						this.node.arkFetcherContext, PriorityClasses.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
						this.node.nonPersistentClientRT);
			}
		}
	}

	protected void stopARKFetcher() {
		if (!this.node.enableARKs) {
			return;
		}
		Logger.minor(this, "Stopping ARK fetcher for " + this + " : " + this.myARK);
		// FIXME any way to reduce locking here?
		USKRetriever ret;
		synchronized (this.arkFetcherSync) {
			if (this.arkFetcher == null) {
				if (logMINOR) {
					Logger.minor(this, "ARK fetcher not running for " + this);
				}
				return;
			}
			ret = this.arkFetcher;
			this.arkFetcher = null;
		}
		final USKRetriever unsub = ret;
		this.node.executor.execute(
				() -> PeerNode.this.node.clientCore.uskManager.unsubscribeContent(PeerNode.this.myARK, unsub, true));
	}

	// Both at IMMEDIATE_SPLITFILE_PRIORITY_CLASS because we want to compete with FMS, not
	// wipe it out!

	@Override
	public short getPollingPriorityNormal() {
		return PriorityClasses.IMMEDIATE_SPLITFILE_PRIORITY_CLASS;
	}

	@Override
	public short getPollingPriorityProgress() {
		return PriorityClasses.IMMEDIATE_SPLITFILE_PRIORITY_CLASS;
	}

	boolean sentInitialMessages;

	void maybeSendInitialMessages() {
		synchronized (this) {
			if (this.sentInitialMessages) {
				return;
			}
			if (this.currentTracker != null) {
				this.sentInitialMessages = true;
			}
			else {
				return;
			}
		}

		this.sendInitialMessages();
	}

	/**
	 * Send any high level messages that need to be sent on connect.
	 */
	protected void sendInitialMessages() {
		this.loadSender(true).setSendASAP();
		this.loadSender(false).setSendASAP();
		Message locMsg = DMT.createFNPLocChangeNotificationNew(this.node.lm.getLocation(),
				this.node.peers.getPeerLocationDoubles(true));
		Message ipMsg = DMT.createFNPDetectedIPAddress(this.detectedPeer);
		Message timeMsg = DMT.createFNPTime(System.currentTimeMillis());
		Message dRoutingMsg = DMT.createRoutingStatus(!this.disableRoutingHasBeenSetLocally);
		Message uptimeMsg = DMT.createFNPUptime((byte) (int) (100 * this.node.uptime.getUptime()));

		try {
			if (this.isRealConnection()) {
				this.sendAsync(locMsg, null, this.node.nodeStats.initialMessagesCtr);
			}
			this.sendAsync(ipMsg, null, this.node.nodeStats.initialMessagesCtr);
			this.sendAsync(timeMsg, null, this.node.nodeStats.initialMessagesCtr);
			this.sendAsync(dRoutingMsg, null, this.node.nodeStats.initialMessagesCtr);
			this.sendAsync(uptimeMsg, null, this.node.nodeStats.initialMessagesCtr);
		}
		catch (NotConnectedException ex) {
			Logger.error(this, "Completed handshake with " + this.getPeer() + " but disconnected (" + this.isConnected
					+ ':' + this.currentTracker + "!!!: " + ex, ex);
		}

		this.sendConnectedDiffNoderef();
	}

	private void sendIPAddressMessage() {
		Message ipMsg = DMT.createFNPDetectedIPAddress(this.detectedPeer);
		try {
			this.sendAsync(ipMsg, null, this.node.nodeStats.changedIPCtr);
		}
		catch (NotConnectedException ex) {
			Logger.normal(this, "Sending IP change message to " + this + " but disconnected: " + ex, ex);
		}
	}

	/**
	 * Called when a packet is successfully decrypted on a given SessionKey for this node.
	 * Will promote the unverifiedTracker if necessary.
	 */
	@Override
	public void verified(SessionKey tracker) {
		long now = System.currentTimeMillis();
		SessionKey completelyDeprecatedTracker;
		synchronized (this) {
			if (tracker == this.unverifiedTracker) {
				if (logMINOR) {
					Logger.minor(this, "Promoting unverified tracker " + tracker + " for " + this.getPeer());
				}
				completelyDeprecatedTracker = this.previousTracker;
				this.previousTracker = this.currentTracker;
				this.currentTracker = this.unverifiedTracker;
				this.unverifiedTracker = null;
				this.isConnected.set(true, now);
				this.neverConnected = false;
				this.maybeClearPeerAddedTimeOnConnect();
				this.ctx = null;
			}
			else {
				return;
			}
		}
		this.maybeSendInitialMessages();
		this.setPeerNodeStatus(now);
		this.node.peers.addConnectedPeer(this);
		this.maybeOnConnect();
		if (completelyDeprecatedTracker != null) {
			completelyDeprecatedTracker.disconnected();
		}
	}

	private synchronized boolean invalidVersion() {
		return this.bogusNoderef || this.forwardInvalidVersion() || this.reverseInvalidVersion();
	}

	private synchronized boolean forwardInvalidVersion() {
		return !Version.checkGoodVersion(this.version);
	}

	private synchronized boolean reverseInvalidVersion() {
		if (this.ignoreLastGoodVersion()) {
			return false;
		}
		return !Version.checkArbitraryGoodVersion(Version.getVersionString(), this.lastGoodVersion);
	}

	/**
	 * The same as isUnroutableOlderVersion, but not synchronized.
	 */
	public boolean publicInvalidVersion() {
		return this.unroutableOlderVersion;
	}

	/**
	 * The same as inUnroutableNewerVersion.
	 */
	public synchronized boolean publicReverseInvalidVersion() {
		return this.unroutableNewerVersion;
	}

	public synchronized boolean dontRoute() {
		return this.disableRouting;
	}

	/**
	 * Process a differential node reference The identity must not change, or we throw.
	 */
	public void processDiffNoderef(SimpleFieldSet fs) throws FSParseException {
		this.processNewNoderef(fs, false, true, false);
		EventBus.get().post(new DiffNoderefProcessedEvent(this));
	}

	/**
	 * Process a new nodereference, in compressed form. The identity must not change, or
	 * we throw.
	 */
	private void processNewNoderef(byte[] data, int offset, int length) throws FSParseException {
		SimpleFieldSet fs = compressedNoderefToFieldSet(data, offset, length);
		this.processNewNoderef(fs, false, false, false);
	}

	static SimpleFieldSet compressedNoderefToFieldSet(byte[] data, int offset, int length) throws FSParseException {
		if (length <= 5) {
			throw new FSParseException("Too short");
		}
		int firstByte = data[offset];
		offset++;
		length--;
		if ((firstByte & 0x2) == 2) { // DSAcompressed group; legacy
			offset++;
			length--;
		}
		// Is it compressed?
		if ((firstByte & 1) == 1) {
			try {
				// Gzipped
				Inflater i = new Inflater();
				i.setInput(data, offset, length);
				// We shouldn't ever need a 4096 bytes long ref!
				byte[] output = new byte[4096];
				length = i.inflate(output, 0, output.length);
				// Finished
				data = output;
				offset = 0;
				if (logMINOR) {
					Logger.minor(PeerNode.class, "We have decompressed a " + length + " bytes big reference.");
				}
			}
			catch (DataFormatException ignored) {
				throw new FSParseException("Invalid compressed data");
			}
		}
		if (logMINOR) {
			Logger.minor(PeerNode.class, "Reference: " + HexUtil.bytesToHex(data, offset, length) + '(' + length + ')');
		}

		// Now decode it
		ByteArrayInputStream bais = new ByteArrayInputStream(data, offset, length);
		InputStreamReader isr;
		isr = new InputStreamReader(bais, StandardCharsets.UTF_8);
		BufferedReader br = new BufferedReader(isr);
		try {
			return new SimpleFieldSet(br, false, true);
		}
		catch (IOException ex) {
			throw (FSParseException) new FSParseException("Impossible: " + ex).initCause(ex);
		}
	}

	/**
	 * Process a new nodereference, as a SimpleFieldSet.
	 */
	protected void processNewNoderef(SimpleFieldSet fs, boolean forARK, boolean forDiffNodeRef, boolean forFullNodeRef)
			throws FSParseException {
		if (logMINOR) {
			Logger.minor(this, "Parsing: \n" + fs);
		}
		boolean changedAnything = this.innerProcessNewNoderef(fs, forARK, forDiffNodeRef, forFullNodeRef) || forARK;
		if (changedAnything && !this.isSeed()) {
			this.writePeers();
		}
		// FIXME should this be urgent if IPs change? Dunno.
	}

	/**
	 * The synchronized part of processNewNoderef
	 */
	protected synchronized boolean innerProcessNewNoderef(SimpleFieldSet fs, boolean forARK, boolean forDiffNodeRef,
			boolean forFullNodeRef) throws FSParseException {

		boolean shouldUpdatePeerCounts = false;

		if (forFullNodeRef) {
			// Check the signature.
			try {
				if (!this.verifyReferenceSignature(fs)) {
					throw new FSParseException("Invalid signature");
				}
			}
			catch (ReferenceSignatureVerificationException ignored) {
				throw new FSParseException("Invalid signature");
			}
		}

		// Anything may be omitted for a differential node reference
		boolean changedAnything = false;
		if (!forDiffNodeRef && (fs.getBoolean("testnet", false))) {
			String err = "Preventing connection to node " + this.detectedPeer + " - testnet is enabled!";
			Logger.error(this, err);
			throw new FSParseException(err);
		}
		String s = fs.get("opennet");
		if (s == null && forFullNodeRef) {
			throw new FSParseException("No opennet ref");
		}
		else if (s != null) {
			try {
				boolean b = Fields.stringToBool(s);
				if (b != this.isOpennetForNoderef()) {
					throw new FSParseException("Changed opennet status?!?!?!? expected=" + this.isOpennetForNoderef()
							+ " but got " + b + " (" + s + ") on " + this);
				}
			}
			catch (NumberFormatException ex) {
				throw new FSParseException("Cannot parse opennet=\"" + s + "\"", ex);
			}
		}
		String identityString = fs.get("identity");
		if (identityString == null && forFullNodeRef) {
			if (this.isDarknet()) {
				throw new FSParseException("No identity!");
			}
			else if (logMINOR) {
				Logger.minor(this, "didn't send an identity;" + " let's assume it's pre-1471");
			}
		}
		else if (identityString != null) {
			try {
				byte[] id = Base64.decode(identityString);
				if (!Arrays.equals(id, this.identity)) {
					throw new FSParseException("Changing the identity");
				}
			}
			catch (NumberFormatException | IllegalBase64Exception ex) {
				throw new FSParseException(ex);
			}
		}

		String newVersion = fs.get("version");
		if (newVersion == null) {
			// Version may be ommitted for an ARK.
			if (!forARK && !forDiffNodeRef) {
				throw new FSParseException("No version");
			}
		}
		else {
			if (!newVersion.equals(this.version)) {
				changedAnything = true;
			}
			this.version = newVersion;
			try {
				this.simpleVersion = Version.getArbitraryBuildNumber(this.version);
			}
			catch (VersionParseException ex) {
				Logger.error(this, "Bad version: " + this.version + " : " + ex, ex);
			}
			Version.seenVersion(newVersion);
		}
		String newLastGoodVersion = fs.get("lastGoodVersion");
		if (newLastGoodVersion != null) {
			// Can be null if anon auth or if forDiffNodeRef.
			this.lastGoodVersion = newLastGoodVersion;
		}
		else if (forFullNodeRef) {
			throw new FSParseException("No lastGoodVersion");
		}

		this.updateVersionRoutablity();

		String locationString = fs.get("location");
		if (locationString != null) {
			double newLoc = Location.getLocation(locationString);
			if (!Location.isValid(newLoc)) {
				if (logMINOR) {
					Logger.minor(this, "Invalid or null location, waiting for FNPLocChangeNotification: locationString="
							+ locationString);
				}
			}
			else {
				double oldLoc = this.location.setLocation(newLoc);
				if (!Location.equals(oldLoc, newLoc)) {
					if (!Location.isValid(oldLoc)) {
						shouldUpdatePeerCounts = true;
					}
					changedAnything = true;
				}
			}
		}
		try {
			String[] physical = fs.getAll("physical.udp");
			if (physical != null) {
				List<Peer> oldNominalPeer = this.nominalPeer;

				this.nominalPeer = new ArrayList<>(physical.length);

				Peer[] oldPeers = oldNominalPeer.toArray(new Peer[0]);

				for (String phys : physical) {
					Peer p;
					try {
						p = new Peer(phys, true, true);
					}
					catch (HostnameSyntaxException | PeerParseException ignored) {
						Logger.error(this,
								"Invalid hostname or IP Address syntax error while parsing new peer reference: "
										+ phys);
						continue;
					}
					catch (UnknownHostException ignored) {
						// Should be impossible???
						Logger.error(this,
								"Invalid hostname or IP Address syntax error while parsing new peer reference: "
										+ phys);
						continue;
					}
					if (!this.nominalPeer.contains(p)) {
						// if (oldNominalPeer.contains(p)) {
						// Do nothing
						// .contains() will .equals() on each, and equals() will
						// propagate the looked-up IP if necessary.
						// This is obviously O(n^2), but it doesn't matter, there will
						// be very few peers.
						// }
						this.nominalPeer.add(p);
					}
				}
				// XXX should we trigger changedAnything on *any* change, or on just
				// *addition* of new addresses
				if (!Arrays.equals(oldPeers, this.nominalPeer.toArray(new Peer[0]))) {
					changedAnything = true;
					if (logMINOR) {
						Logger.minor(this, "Got new physical.udp for " + this + " : "
								+ Arrays.toString(this.nominalPeer.toArray()));
					}
					// Look up the DNS names if any ASAP
					this.lastAttemptedHandshakeIPUpdateTime = 0;
					// Clear nonces to prevent leak. Will kill any in-progress connect
					// attempts, but that is okay because
					// either we got an ARK which changed our peers list, or we just
					// connected.
					this.jfkNoncesSent.clear();
				}

			}
			else if (forARK || forFullNodeRef) {
				// Connection setup doesn't include a physical.udp.
				// Differential noderefs only include it on the first one after connect.
				Logger.error(this, "ARK noderef has no physical.udp for " + this + " : forDiffNodeRef=" + forDiffNodeRef
						+ " forARK=" + forARK);
				if (forFullNodeRef) {
					throw new FSParseException("ARK noderef has no physical.udp");
				}
			}
		}
		catch (Exception e1) {
			Logger.error(this, "Caught " + e1, e1);
			throw new FSParseException(e1);
		}

		if (logMINOR) {
			Logger.minor(this, "Parsed successfully; changedAnything = " + changedAnything);
		}

		int[] newNegTypes = fs.getIntArray("auth.negTypes");

		boolean refHadNegTypes = false;

		if (newNegTypes == null || newNegTypes.length == 0) {
			newNegTypes = new int[] { 0 };
		}
		else {
			refHadNegTypes = true;
		}
		if (!forDiffNodeRef || refHadNegTypes) {
			if (!Arrays.equals(this.negTypes, newNegTypes)) {
				changedAnything = true;
				this.negTypes = newNegTypes;
			}
		}

		/* Read the ECDSA key material for the peer */
		SimpleFieldSet sfs = fs.subset("ecdsa.P256");
		if (sfs != null) {
			byte[] pub;
			try {
				pub = Base64.decode(sfs.get("pub"));
			}
			catch (IllegalBase64Exception ex) {
				Logger.error(this, "Caught " + ex + " parsing ECC pubkey", ex);
				throw new FSParseException(ex);
			}
			if (pub.length > ECDSA.Curves.P256.modulusSize) {
				throw new FSParseException("ecdsa.P256.pub is not the right size!");
			}
			ECPublicKey key = ECDSA.getPublicKey(pub, ECDSA.Curves.P256);
			if (key == null) {
				throw new FSParseException("ecdsa.P256.pub is invalid!");
			}
			if (!key.equals(this.peerECDSAPubKey)) {
				Logger.error(this, "Tried to change ECDSA key on " + this.userToString()
						+ " - did neighbour try to downgrade? Rejecting...");
				throw new FSParseException("Changing ECDSA key not allowed!");
			}
		}

		if (this.parseARK(fs, false, forDiffNodeRef)) {
			changedAnything = true;
		}
		if (shouldUpdatePeerCounts) {
			this.node.executor.execute(PeerNode.this.node.peers::updatePMUserAlert);

		}
		return changedAnything;
	}

	/**
	 * Get a PeerNodeStatus for this node.
	 * @param noHeavy If true, avoid any expensive operations e.g. the message count
	 * hashtables.
	 */
	public abstract PeerNodeStatus getStatus(boolean noHeavy);

	public String getTMCIPeerInfo() {
		long now = System.currentTimeMillis();
		int idle;
		synchronized (this) {
			idle = (int) ((now - this.timeLastReceivedPacket) / 1000);
		}
		if ((this.getPeerNodeStatus() == PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED)
				&& (this.getPeerAddedTime() > 1)) {
			idle = (int) ((now - this.getPeerAddedTime()) / 1000);
		}
		return String.valueOf(this.getPeer()) + '\t' + this.getIdentityString() + '\t' + this.getLocation() + '\t'
				+ this.getPeerNodeStatusString() + '\t' + idle;
	}

	public synchronized String getVersion() {
		return this.version;
	}

	private synchronized String getLastGoodVersion() {
		return this.lastGoodVersion;
	}

	private int simpleVersion;

	public int getSimpleVersion() {
		return this.simpleVersion;
	}

	/**
	 * Write the peer's noderef to disk
	 */
	public void write(Writer w) throws IOException {
		SimpleFieldSet fs = this.exportFieldSet();
		SimpleFieldSet meta = this.exportMetadataFieldSet(System.currentTimeMillis());
		if (!meta.isEmpty()) {
			fs.put("metadata", meta);
		}
		fs.writeTo(w);
	}

	/**
	 * (both metadata + normal fieldset but atomically)
	 */
	public synchronized SimpleFieldSet exportDiskFieldSet() {
		SimpleFieldSet fs = this.exportFieldSet();
		SimpleFieldSet meta = this.exportMetadataFieldSet(System.currentTimeMillis());
		if (!meta.isEmpty()) {
			fs.put("metadata", meta);
		}
		if (this.fullFieldSet != null) {
			fs.put("full", this.fullFieldSet);
		}
		return fs;
	}

	/**
	 * Export metadata about the node as a SimpleFieldSet
	 */
	public synchronized SimpleFieldSet exportMetadataFieldSet(long now) {
		SimpleFieldSet fs = new SimpleFieldSet(true);
		if (this.detectedPeer != null) {
			fs.putSingle("detected.udp", this.detectedPeer.toStringPrefNumeric());
		}
		if (this.lastReceivedPacketTime() > 0) {
			fs.put("timeLastReceivedPacket", this.timeLastReceivedPacket);
		}
		if (this.lastReceivedAckTime() > 0) {
			fs.put("timeLastReceivedAck", this.timeLastReceivedAck);
		}
		long timeLastConnected = this.isConnected.getTimeLastTrue(now);
		if (timeLastConnected > 0) {
			fs.put("timeLastConnected", timeLastConnected);
		}
		if (this.timeLastRoutable() > 0) {
			fs.put("timeLastRoutable", this.timeLastRoutable);
		}
		if (this.getPeerAddedTime() > 0 && this.shouldExportPeerAddedTime()) {
			fs.put("peerAddedTime", this.peerAddedTime);
		}
		if (this.neverConnected) {
			fs.putSingle("neverConnected", "true");
		}
		if (this.hadRoutableConnectionCount > 0) {
			fs.put("hadRoutableConnectionCount", this.hadRoutableConnectionCount);
		}
		if (this.routableConnectionCheckCount > 0) {
			fs.put("routableConnectionCheckCount", this.routableConnectionCheckCount);
		}
		double[] peerLocs = this.getPeersLocationArray();
		if (peerLocs != null) {
			fs.put("peersLocation", peerLocs);
		}
		return fs;
	}

	// Opennet peers don't persist or export the peer added time.
	protected abstract boolean shouldExportPeerAddedTime();

	/**
	 * Export volatile data about the node as a SimpleFieldSet
	 */
	public SimpleFieldSet exportVolatileFieldSet() {
		SimpleFieldSet fs = new SimpleFieldSet(true);
		long now = System.currentTimeMillis();
		synchronized (this) {
			fs.put("averagePingTime", this.averagePingTime());
			long idle = now - this.lastReceivedPacketTime();
			if (idle > TimeUnit.SECONDS.toMillis(60) && -1 != this.lastReceivedPacketTime()) {
				fs.put("idle", idle);
			}
			if (this.peerAddedTime > 1) {
				fs.put("peerAddedTime", this.peerAddedTime);
			}
			fs.putSingle("lastRoutingBackoffReasonRT", this.lastRoutingBackoffReasonRT);
			fs.putSingle("lastRoutingBackoffReasonBulk", this.lastRoutingBackoffReasonBulk);
			fs.put("routingBackoffPercent", this.backedOffPercent.currentValue() * 100);
			fs.put("routingBackoffRT",
					Math.max(Math.max(this.routingBackedOffUntilRT, this.transferBackedOffUntilRT) - now, 0));
			fs.put("routingBackoffBulk",
					Math.max(Math.max(this.routingBackedOffUntilBulk, this.transferBackedOffUntilBulk) - now, 0));
			fs.put("routingBackoffLengthRT", this.routingBackoffLengthRT);
			fs.put("routingBackoffLengthBulk", this.routingBackoffLengthBulk);
			fs.put("overloadProbability", this.getPRejected() * 100);
			fs.put("percentTimeRoutableConnection", this.getPercentTimeRoutableConnection() * 100);
		}
		fs.putSingle("status", this.getPeerNodeStatusString());
		return fs;
	}

	/**
	 * Export the peer's noderef as a SimpleFieldSet
	 */
	public synchronized SimpleFieldSet exportFieldSet() {
		SimpleFieldSet fs = new SimpleFieldSet(true);
		if (this.getLastGoodVersion() != null) {
			fs.putSingle("lastGoodVersion", this.lastGoodVersion);
		}
		for (Peer peer : this.nominalPeer) {
			fs.putAppend("physical.udp", peer.toString());
		}
		fs.put("auth.negTypes", this.negTypes);
		fs.putSingle("identity", this.getIdentityString());
		fs.put("location", this.getLocation());
		fs.put("testnet", this.testnetEnabled);
		fs.putSingle("version", this.version);
		fs.put("ecdsa", ECDSA.Curves.P256.getSFS(this.peerECDSAPubKey));

		if (this.myARK != null) {
			// Decrement it because we keep the number we would like to fetch, not the
			// last one fetched.
			fs.put("ark.number", this.myARK.suggestedEdition - 1);
			fs.putSingle("ark.pubURI", this.myARK.getBaseSSK().toString(false, false));
		}
		fs.put("opennet", this.isOpennetForNoderef());
		fs.put("seed", this.isSeed());
		fs.put("totalInput", this.getTotalInputBytes());
		fs.put("totalOutput", this.getTotalOutputBytes());
		return fs;
	}

	/**
	 * @return True if the node is a full darknet peer ("Friend"), which should usually be
	 * in the darknet routing table.
	 */
	public abstract boolean isDarknet();

	/**
	 * @return True if the node is a full opennet peer ("Stranger"), which should usually
	 * be in the OpennetManager and opennet routing table.
	 */
	public abstract boolean isOpennet();

	/**
	 * @return Expected value of "opennet=" in the noderef. This returns true if the node
	 * is an actual opennet peer, but also if the node is a seed client or seed server,
	 * even though they are never part of the routing table. This also determines whether
	 * we use the opennet or darknet NodeCrypto.
	 */
	public abstract boolean isOpennetForNoderef();

	/**
	 * @return True if the node is a seed client or seed server. These are never in the
	 * routing table, but their noderefs should still say opennet=true.
	 */
	public abstract boolean isSeed();

	/**
	 * @return The time at which we last connected (or reconnected).
	 */
	public synchronized long timeLastConnectionCompleted() {
		return this.connectedTime;
	}

	@Override
	public boolean equals(Object o) {
		if (o == this) {
			return true;
		}
		if (o instanceof PeerNode pn) {
			return Arrays.equals(pn.peerECDSAPubKeyHash, this.peerECDSAPubKeyHash);
		}
		else {
			return false;
		}
	}

	@Override
	public final int hashCode() {
		return this.hashCode;
	}

	@Override
	public String toString() {
		// FIXME?
		return this.shortToString() + '@' + Integer.toHexString(super.hashCode());
	}

	public boolean isRoutingBackedOff(long ignoreBackoffUnder, boolean realTime) {
		long now = System.currentTimeMillis();
		double pingTime;
		synchronized (this) {
			long routingBackedOffUntil = realTime ? this.routingBackedOffUntilRT : this.routingBackedOffUntilBulk;
			if (now < routingBackedOffUntil) {
				if (routingBackedOffUntil - now >= ignoreBackoffUnder) {
					return true;
				}
			}
			long transferBackedOffUntil = realTime ? this.transferBackedOffUntilRT : this.transferBackedOffUntilBulk;
			if (now < transferBackedOffUntil) {
				if (transferBackedOffUntil - now >= ignoreBackoffUnder) {
					return true;
				}
			}
			if (this.isInMandatoryBackoff(now, realTime)) {
				return true;
			}
			pingTime = this.averagePingTime();
		}
		return pingTime > this.maxPeerPingTime();
	}

	public boolean isRoutingBackedOff(boolean realTime) {
		long now = System.currentTimeMillis();
		double pingTime;
		synchronized (this) {
			long routingBackedOffUntil = realTime ? this.routingBackedOffUntilRT : this.routingBackedOffUntilBulk;
			long transferBackedOffUntil = realTime ? this.transferBackedOffUntilRT : this.transferBackedOffUntilBulk;
			if (now < routingBackedOffUntil || now < transferBackedOffUntil) {
				return true;
			}
			pingTime = this.averagePingTime();
		}
		return pingTime > this.maxPeerPingTime();
	}

	public boolean isRoutingBackedOffEither() {
		long now = System.currentTimeMillis();
		double pingTime;
		synchronized (this) {
			long routingBackedOffUntil = Math.max(this.routingBackedOffUntilRT, this.routingBackedOffUntilBulk);
			long transferBackedOffUntil = Math.max(this.transferBackedOffUntilRT, this.transferBackedOffUntilBulk);
			if (now < routingBackedOffUntil || now < transferBackedOffUntil) {
				return true;
			}
			pingTime = this.averagePingTime();
		}
		return pingTime > this.maxPeerPingTime();
	}

	long routingBackedOffUntilRT = -1;

	long routingBackedOffUntilBulk = -1;

	/** Initial nominal routing backoff length */
	static final int INITIAL_ROUTING_BACKOFF_LENGTH = (int) TimeUnit.SECONDS.toMillis(1);

	/** How much to multiply by during fast routing backoff */

	static final int BACKOFF_MULTIPLIER = 2;

	/** Maximum upper limit to routing backoff slow or fast */
	static final int MAX_ROUTING_BACKOFF_LENGTH = (int) TimeUnit.MINUTES.toMillis(8);

	/** Current nominal routing backoff length */

	// Transfer Backoff

	long transferBackedOffUntilRT = -1;

	long transferBackedOffUntilBulk = -1;
	static final int INITIAL_TRANSFER_BACKOFF_LENGTH = (int) TimeUnit.SECONDS.toMillis(30); // 60

	// seconds,
	// but
	// it
	// starts
	// at
	// twice
	// this.
	static final int TRANSFER_BACKOFF_MULTIPLIER = 2;
	static final int MAX_TRANSFER_BACKOFF_LENGTH = (int) TimeUnit.MINUTES.toMillis(8);

	int transferBackoffLengthRT = INITIAL_TRANSFER_BACKOFF_LENGTH;

	int transferBackoffLengthBulk = INITIAL_TRANSFER_BACKOFF_LENGTH;

	int routingBackoffLengthRT = INITIAL_ROUTING_BACKOFF_LENGTH;

	int routingBackoffLengthBulk = INITIAL_ROUTING_BACKOFF_LENGTH;

	/** Last backoff reason */
	String lastRoutingBackoffReasonRT;

	String lastRoutingBackoffReasonBulk;

	/** Previous backoff reason (used by setPeerNodeStatus) */
	String previousRoutingBackoffReasonRT;

	String previousRoutingBackoffReasonBulk;

	/* percent of time this peer is backed off */
	public final RunningAverage backedOffPercent;

	public final RunningAverage backedOffPercentRT;

	public final RunningAverage backedOffPercentBulk;

	/* time of last sample */
	private long lastSampleTime = Long.MAX_VALUE;

	// Separate, mandatory backoff mechanism for when nodes are consistently sending
	// unexpected soft rejects.
	// E.g. when load management predicts GUARANTEED and yet we are rejected.
	// This can happens when the peer's view of how many of our requests are running is
	// different to our view.
	// But there has not been a timeout, so we haven't called fatalTimeout() and
	// reconnected.

	// FIXME 3 different kinds of backoff? Can we get rid of some???

	long mandatoryBackoffUntilRT = -1;

	int mandatoryBackoffLengthRT = INITIAL_MANDATORY_BACKOFF_LENGTH;

	long mandatoryBackoffUntilBulk = -1;

	int mandatoryBackoffLengthBulk = INITIAL_MANDATORY_BACKOFF_LENGTH;
	static final int INITIAL_MANDATORY_BACKOFF_LENGTH = (int) TimeUnit.SECONDS.toMillis(1);
	static final int MANDATORY_BACKOFF_MULTIPLIER = 2;

	/**
	 * When load management predicts that a peer will definitely accept the request, both
	 * before it was sent and after we got the rejected, we go into mandatory backoff.
	 */
	public void enterMandatoryBackoff(String reason, boolean realTime) {
		long now = System.currentTimeMillis();
		synchronized (this) {
			long mandatoryBackoffUntil = realTime ? this.mandatoryBackoffUntilRT : this.mandatoryBackoffUntilBulk;
			int mandatoryBackoffLength = realTime ? this.mandatoryBackoffLengthRT : this.mandatoryBackoffLengthBulk;
			if (mandatoryBackoffUntil > -1 && mandatoryBackoffUntil > now) {
				return;
			}
			Logger.error(this, "Entering mandatory backoff for " + this + (realTime ? " (realtime)" : " (bulk)"));
			mandatoryBackoffUntil = now + (mandatoryBackoffLength / 2)
					+ this.node.fastWeakRandom.nextInt(mandatoryBackoffLength / 2);
			mandatoryBackoffLength *= MANDATORY_BACKOFF_MULTIPLIER;
			this.node.nodeStats.reportMandatoryBackoff(reason, mandatoryBackoffUntil - now, realTime);
			if (realTime) {
				this.mandatoryBackoffLengthRT = mandatoryBackoffLength;
				this.mandatoryBackoffUntilRT = mandatoryBackoffUntil;
			}
			else {
				this.mandatoryBackoffLengthBulk = mandatoryBackoffLength;
				this.mandatoryBackoffUntilBulk = mandatoryBackoffUntil;
			}
			this.setLastBackoffReason(reason, realTime);
		}
		if (realTime) {
			this.outputLoadTrackerRealTime.failSlotWaiters(true);
		}
		else {
			this.outputLoadTrackerBulk.failSlotWaiters(true);
		}
	}

	/**
	 * Called when a request is accepted. We don't wait for completion, unlike
	 * successNotOverload().
	 */
	public synchronized void resetMandatoryBackoff(boolean realTime) {
		if (realTime) {
			this.mandatoryBackoffLengthRT = INITIAL_MANDATORY_BACKOFF_LENGTH;
		}
		else {
			this.mandatoryBackoffLengthBulk = INITIAL_MANDATORY_BACKOFF_LENGTH;
		}
	}

	/**
	 * Track the percentage of time a peer spends backed off
	 */
	private void reportBackoffStatus(long now) {
		synchronized (this) {
			if (now > this.lastSampleTime) { // don't report twice in the same millisecond
				double report = 0.0;
				if (now > this.routingBackedOffUntilRT) { // not backed off
					if (this.lastSampleTime > this.routingBackedOffUntilRT) { // last
																				// sample
																				// after
						// last backoff
						this.backedOffPercentRT.report(0.0);
						report = 0.0;
					}
					else {
						if (this.routingBackedOffUntilRT > 0) {
							report = (double) (this.routingBackedOffUntilRT - this.lastSampleTime)
									/ (double) (now - this.lastSampleTime);
							this.backedOffPercentRT.report(report);
						}
					}
				}
				else {
					report = 0.0;
					this.backedOffPercentRT.report(1.0);
				}

				if (now > this.routingBackedOffUntilBulk) { // not backed off
					if (this.lastSampleTime > this.routingBackedOffUntilBulk) { // last
																				// sample
																				// after
						// last backoff
						report = 0.0;
						this.backedOffPercentBulk.report(0.0);
					}
					else {
						if (this.routingBackedOffUntilBulk > 0) {
							double myReport = (double) (this.routingBackedOffUntilBulk - this.lastSampleTime)
									/ (double) (now - this.lastSampleTime);
							this.backedOffPercentBulk.report(myReport);
							if (report > myReport) {
								report = myReport;
							}
						}
					}
				}
				else {
					this.backedOffPercentBulk.report(1.0);
				}
				this.backedOffPercent.report(report);
			}
			this.lastSampleTime = now;
		}
	}

	/**
	 * Got a local RejectedOverload. Back off this node for a while.
	 */
	public void localRejectedOverload(String reason, boolean realTime) {
		assert reason.indexOf(' ') == -1;
		this.pRejected.report(1.0);
		if (logMINOR) {
			Logger.minor(this, "Local rejected overload (" + reason + ") on " + this + " : pRejected="
					+ this.pRejected.currentValue());
		}
		long now = System.currentTimeMillis();
		Peer peer = this.getPeer();
		this.reportBackoffStatus(now);
		// We need it because of nested locking on getStatus()
		synchronized (this) {
			// Don't back off any further if we are already backed off
			long routingBackedOffUntil = realTime ? this.routingBackedOffUntilRT : this.routingBackedOffUntilBulk;
			int routingBackoffLength = realTime ? this.routingBackoffLengthRT : this.routingBackoffLengthBulk;
			if (now > routingBackedOffUntil) {
				routingBackoffLength = routingBackoffLength * BACKOFF_MULTIPLIER;
				if (routingBackoffLength > MAX_ROUTING_BACKOFF_LENGTH) {
					routingBackoffLength = MAX_ROUTING_BACKOFF_LENGTH;
				}
				int x = this.node.random.nextInt(routingBackoffLength);
				routingBackedOffUntil = now + x;
				this.node.nodeStats.reportRoutingBackoff(reason, x, realTime);
				if (logMINOR) {
					String reasonWrapper = "";
					if (0 < reason.length()) {
						reasonWrapper = " because of '" + reason + '\'';
					}
					Logger.minor(this, "Backing off" + reasonWrapper + ": routingBackoffLength=" + routingBackoffLength
							+ ", until " + x + "ms on " + peer);
				}
				if (realTime) {
					this.routingBackedOffUntilRT = routingBackedOffUntil;
					this.routingBackoffLengthRT = routingBackoffLength;
				}
				else {
					this.routingBackedOffUntilBulk = routingBackedOffUntil;
					this.routingBackoffLengthBulk = routingBackoffLength;
				}
			}
			else {
				if (logMINOR) {
					Logger.minor(this, "Ignoring localRejectedOverload: " + (routingBackedOffUntil - now)
							+ "ms remaining on routing backoff on " + peer);
				}
				return;
			}
			this.setLastBackoffReason(reason, realTime);
		}
		this.setPeerNodeStatus(now);
		if (realTime) {
			this.outputLoadTrackerRealTime.failSlotWaiters(true);
		}
		else {
			this.outputLoadTrackerBulk.failSlotWaiters(true);
		}
	}

	/**
	 * Didn't get RejectedOverload. Reset routing backoff.
	 */
	public void successNotOverload(boolean realTime) {
		this.pRejected.report(0.0);
		if (logMINOR) {
			Logger.minor(this, "Success not overload on " + this + " : pRejected=" + this.pRejected.currentValue());
		}
		Peer peer = this.getPeer();
		long now = System.currentTimeMillis();
		this.reportBackoffStatus(now);
		synchronized (this) {
			// Don't un-backoff if still backed off
			long until = realTime ? this.routingBackedOffUntilRT : this.routingBackedOffUntilBulk;
			if (now > until) {
				if (realTime) {
					this.routingBackoffLengthRT = INITIAL_ROUTING_BACKOFF_LENGTH;
				}
				else {
					this.routingBackoffLengthBulk = INITIAL_ROUTING_BACKOFF_LENGTH;
				}
				if (logMINOR) {
					Logger.minor(this, "Resetting routing backoff on " + peer);
				}
			}
			else {
				if (logMINOR) {
					Logger.minor(this, "Ignoring successNotOverload: " + (until - now)
							+ "ms remaining on routing backoff on " + peer);
				}
				return;
			}
		}
		this.setPeerNodeStatus(now);
	}

	/**
	 * A transfer failed. Back off this node for a while.
	 */
	@Override
	public void transferFailed(String reason, boolean realTime) {
		assert reason.indexOf(' ') == -1;
		this.pRejected.report(1.0);
		if (logMINOR) {
			Logger.minor(this,
					"Transfer failed (" + reason + ") on " + this + " : pRejected=" + this.pRejected.currentValue());
		}
		long now = System.currentTimeMillis();
		Peer peer = this.getPeer();
		this.reportBackoffStatus(now);
		// We need it because of nested locking on getStatus()
		synchronized (this) {
			// Don't back off any further if we are already backed off
			long transferBackedOffUntil = realTime ? this.transferBackedOffUntilRT : this.transferBackedOffUntilBulk;
			int transferBackoffLength = realTime ? this.transferBackoffLengthRT : this.transferBackoffLengthBulk;
			if (now > transferBackedOffUntil) {
				transferBackoffLength = transferBackoffLength * TRANSFER_BACKOFF_MULTIPLIER;
				if (transferBackoffLength > MAX_TRANSFER_BACKOFF_LENGTH) {
					transferBackoffLength = MAX_TRANSFER_BACKOFF_LENGTH;
				}
				int x = this.node.random.nextInt(transferBackoffLength);
				transferBackedOffUntil = now + x;
				this.node.nodeStats.reportTransferBackoff(reason, x, realTime);
				if (logMINOR) {
					String reasonWrapper = "";
					if (0 < reason.length()) {
						reasonWrapper = " because of '" + reason + '\'';
					}
					Logger.minor(this, "Backing off (transfer)" + reasonWrapper + ": transferBackoffLength="
							+ transferBackoffLength + ", until " + x + "ms on " + peer);
				}
				if (realTime) {
					this.transferBackedOffUntilRT = transferBackedOffUntil;
					this.transferBackoffLengthRT = transferBackoffLength;
				}
				else {
					this.transferBackedOffUntilBulk = transferBackedOffUntil;
					this.transferBackoffLengthBulk = transferBackoffLength;
				}
			}
			else {
				if (logMINOR) {
					Logger.minor(this, "Ignoring transfer failure: " + (transferBackedOffUntil - now)
							+ "ms remaining on transfer backoff on " + peer);
				}
				return;
			}
			this.setLastBackoffReason(reason, realTime);
		}
		if (realTime) {
			this.outputLoadTrackerRealTime.failSlotWaiters(true);
		}
		else {
			this.outputLoadTrackerBulk.failSlotWaiters(true);
		}
		this.setPeerNodeStatus(now);
	}

	/**
	 * A transfer succeeded. Reset backoff.
	 */
	public void transferSuccess(boolean realTime) {
		this.pRejected.report(0.0);
		if (logMINOR) {
			Logger.minor(this, "Transfer success on " + this + " : pRejected=" + this.pRejected.currentValue());
		}
		Peer peer = this.getPeer();
		long now = System.currentTimeMillis();
		this.reportBackoffStatus(now);
		synchronized (this) {
			// Don't un-backoff if still backed off
			long until = realTime ? this.transferBackedOffUntilRT : this.transferBackedOffUntilBulk;
			if (now > until) {
				if (realTime) {
					this.transferBackoffLengthRT = INITIAL_TRANSFER_BACKOFF_LENGTH;
				}
				else {
					this.transferBackoffLengthBulk = INITIAL_TRANSFER_BACKOFF_LENGTH;
				}
				if (logMINOR) {
					Logger.minor(this, "Resetting transfer backoff on " + peer);
				}
			}
			else {
				if (logMINOR) {
					Logger.minor(this, "Ignoring transfer success: " + (until - now)
							+ "ms remaining on transfer backoff on " + peer);
				}
				return;
			}
		}
		this.setPeerNodeStatus(now);
	}

	long pingNumber;

	private final RunningAverage pingAverage;

	/**
	 * @return The probability of a request sent to this peer being rejected (locally) due
	 * to overload, or timing out after being accepted.
	 */
	public double getPRejected() {
		return this.pRejected.currentValue();
	}

	@Override
	public double averagePingTime() {
		return this.pingAverage.currentValue();
	}

	private boolean reportedRTT;

	private double SRTT = 1000;

	private double RTTVAR = 0;

	private double RTO = 1000;

	/** Calculated as per RFC 2988 */
	@Override
	public synchronized double averagePingTimeCorrected() {
		return this.RTO;
	}

	@Override
	public void reportThrottledPacketSendTime(long timeDiff, boolean realTime) {
		// FIXME do we need this?
		if (logMINOR) {
			Logger.minor(this, "Reporting throttled packet send time: " + timeDiff + " to " + this.getPeer() + " ("
					+ (realTime ? "realtime" : "bulk") + ")");
		}
	}

	public void setRemoteDetectedPeer(Peer p) {
		this.remoteDetectedPeer = p;
	}

	public Peer getRemoteDetectedPeer() {
		return this.remoteDetectedPeer;
	}

	public synchronized long getRoutingBackoffLength(boolean realTime) {
		return realTime ? this.routingBackoffLengthRT : this.routingBackoffLengthBulk;
	}

	public synchronized long getRoutingBackedOffUntil(boolean realTime) {
		return Math.max(realTime ? this.mandatoryBackoffUntilRT : this.mandatoryBackoffUntilBulk,
				Math.max(realTime ? this.routingBackedOffUntilRT : this.routingBackedOffUntilBulk,
						realTime ? this.transferBackedOffUntilRT : this.transferBackedOffUntilBulk));
	}

	public synchronized long getRoutingBackedOffUntilMax() {
		return Math.max(Math.max(this.mandatoryBackoffUntilRT, this.mandatoryBackoffUntilBulk),
				Math.max(Math.max(this.routingBackedOffUntilRT, this.routingBackedOffUntilBulk),
						Math.max(this.transferBackedOffUntilRT, this.transferBackedOffUntilBulk)));
	}

	public synchronized long getRoutingBackedOffUntilRT() {
		return Math.max(this.routingBackedOffUntilRT, this.transferBackedOffUntilRT);
	}

	public synchronized long getRoutingBackedOffUntilBulk() {
		return Math.max(this.routingBackedOffUntilBulk, this.transferBackedOffUntilBulk);
	}

	public synchronized String getLastBackoffReason(boolean realTime) {
		return realTime ? this.lastRoutingBackoffReasonRT : this.lastRoutingBackoffReasonBulk;
	}

	public synchronized String getPreviousBackoffReason(boolean realTime) {
		return realTime ? this.previousRoutingBackoffReasonRT : this.previousRoutingBackoffReasonBulk;
	}

	public synchronized void setLastBackoffReason(String s, boolean realTime) {
		if (realTime) {
			this.lastRoutingBackoffReasonRT = s;
		}
		else {
			this.lastRoutingBackoffReasonBulk = s;
		}
	}

	public void addToLocalNodeSentMessagesToStatistic(Message m) {
		String messageSpecName;
		Long count;

		messageSpecName = m.getSpec().getName();
		// Synchronize to make increments atomic.
		synchronized (this.localNodeSentMessageTypes) {
			count = this.localNodeSentMessageTypes.get(messageSpecName);
			if (count == null) {
				count = 1L;
			}
			else {
				count = count + 1;
			}
			this.localNodeSentMessageTypes.put(messageSpecName, count);
		}
	}

	public void addToLocalNodeReceivedMessagesFromStatistic(Message m) {
		String messageSpecName;
		Long count;

		messageSpecName = m.getSpec().getName();
		// Synchronize to make increments atomic.
		synchronized (this.localNodeReceivedMessageTypes) {
			count = this.localNodeReceivedMessageTypes.get(messageSpecName);
			if (count == null) {
				count = 1L;
			}
			else {
				count = count + 1;
			}
			this.localNodeReceivedMessageTypes.put(messageSpecName, count);
		}
	}

	public Hashtable<String, Long> getLocalNodeSentMessagesToStatistic() {
		// Must be synchronized *during the copy*
		synchronized (this.localNodeSentMessageTypes) {
			return new Hashtable<>(this.localNodeSentMessageTypes);
		}
	}

	public Hashtable<String, Long> getLocalNodeReceivedMessagesFromStatistic() {
		// Must be synchronized *during the copy*
		synchronized (this.localNodeReceivedMessageTypes) {
			return new Hashtable<>(this.localNodeReceivedMessageTypes);
		}
	}

	synchronized USK getARK() {
		return this.myARK;
	}

	public void gotARK(SimpleFieldSet fs, long fetchedEdition) {
		try {
			synchronized (this) {
				this.handshakeCount = 0;
				// edition +1 because we store the ARK edition that we want to fetch.
				if (this.myARK.suggestedEdition < fetchedEdition + 1) {
					this.myARK = this.myARK.copy(fetchedEdition + 1);
				}
			}
			this.processNewNoderef(fs, true, false, false);
		}
		catch (FSParseException ex) {
			Logger.error(this, "Invalid ARK update: " + ex, ex);
			// This is ok as ARKs are limited to 4K anyway.
			Logger.error(this, "Data was: \n" + fs.toString());
			synchronized (this) {
				this.handshakeCount = PeerNode.MAX_HANDSHAKE_COUNT;
			}
		}
	}

	public synchronized int getPeerNodeStatus() {
		return this.peerNodeStatus;
	}

	public String getPeerNodeStatusString() {
		int status = this.getPeerNodeStatus();
		return getPeerNodeStatusString(status);
	}

	public static String getPeerNodeStatusString(int status) {
		if (status == PeerManager.PEER_NODE_STATUS_CONNECTED) {
			return "CONNECTED";
		}
		if (status == PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF) {
			return "BACKED OFF";
		}
		if (status == PeerManager.PEER_NODE_STATUS_TOO_NEW) {
			return "TOO NEW";
		}
		if (status == PeerManager.PEER_NODE_STATUS_TOO_OLD) {
			return "TOO OLD";
		}
		if (status == PeerManager.PEER_NODE_STATUS_DISCONNECTED) {
			return "DISCONNECTED";
		}
		if (status == PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED) {
			return "NEVER CONNECTED";
		}
		if (status == PeerManager.PEER_NODE_STATUS_DISABLED) {
			return "DISABLED";
		}
		if (status == PeerManager.PEER_NODE_STATUS_CLOCK_PROBLEM) {
			return "CLOCK PROBLEM";
		}
		if (status == PeerManager.PEER_NODE_STATUS_CONN_ERROR) {
			return "CONNECTION ERROR";
		}
		if (status == PeerManager.PEER_NODE_STATUS_ROUTING_DISABLED) {
			return "ROUTING DISABLED";
		}
		if (status == PeerManager.PEER_NODE_STATUS_LISTEN_ONLY) {
			return "LISTEN ONLY";
		}
		if (status == PeerManager.PEER_NODE_STATUS_LISTENING) {
			return "LISTENING";
		}
		if (status == PeerManager.PEER_NODE_STATUS_BURSTING) {
			return "BURSTING";
		}
		if (status == PeerManager.PEER_NODE_STATUS_DISCONNECTING) {
			return "DISCONNECTING";
		}
		if (status == PeerManager.PEER_NODE_STATUS_NO_LOAD_STATS) {
			return "NO LOAD STATS";
		}
		return "UNKNOWN STATUS";
	}

	public String getPeerNodeStatusCSSClassName() {
		int status = this.getPeerNodeStatus();
		return getPeerNodeStatusCSSClassName(status);
	}

	public static String getPeerNodeStatusCSSClassName(int status) {
		if (status == PeerManager.PEER_NODE_STATUS_CONNECTED) {
			return "peer_connected";
		}
		else if (status == PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF) {
			return "peer_backed_off";
		}
		else if (status == PeerManager.PEER_NODE_STATUS_TOO_NEW) {
			return "peer_too_new";
		}
		else if (status == PeerManager.PEER_NODE_STATUS_TOO_OLD) {
			return "peer_too_old";
		}
		else if (status == PeerManager.PEER_NODE_STATUS_DISCONNECTED) {
			return "peer_disconnected";
		}
		else if (status == PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED) {
			return "peer_never_connected";
		}
		else if (status == PeerManager.PEER_NODE_STATUS_DISABLED) {
			return "peer_disabled";
		}
		else if (status == PeerManager.PEER_NODE_STATUS_ROUTING_DISABLED) {
			return "peer_routing_disabled";
		}
		else if (status == PeerManager.PEER_NODE_STATUS_BURSTING) {
			return "peer_bursting";
		}
		else if (status == PeerManager.PEER_NODE_STATUS_CLOCK_PROBLEM) {
			return "peer_clock_problem";
		}
		else if (status == PeerManager.PEER_NODE_STATUS_LISTENING) {
			return "peer_listening";
		}
		else if (status == PeerManager.PEER_NODE_STATUS_LISTEN_ONLY) {
			return "peer_listen_only";
		}
		else if (status == PeerManager.PEER_NODE_STATUS_DISCONNECTING) {
			return "peer_disconnecting";
		}
		else if (status == PeerManager.PEER_NODE_STATUS_NO_LOAD_STATS) {
			return "peer_no_load_stats";
		}
		else {
			return "peer_unknown_status";
		}
	}

	protected synchronized int getPeerNodeStatus(long now, long routingBackedOffUntilRT,
			long localRoutingBackedOffUntilBulk, boolean overPingTime, boolean noLoadStats) {
		if (this.disconnecting) {
			return PeerManager.PEER_NODE_STATUS_DISCONNECTING;
		}
		boolean isConnected = this.isConnected();
		if (this.isRoutable()) { // Function use also updates timeLastConnected and
			// timeLastRoutable
			if (noLoadStats) {
				this.peerNodeStatus = PeerManager.PEER_NODE_STATUS_NO_LOAD_STATS;
			}
			else {
				this.peerNodeStatus = PeerManager.PEER_NODE_STATUS_CONNECTED;
				if (overPingTime && (this.lastRoutingBackoffReasonRT == null || now >= routingBackedOffUntilRT)) {
					this.lastRoutingBackoffReasonRT = "TooHighPing";
				}
				if (now < routingBackedOffUntilRT || overPingTime || this.isInMandatoryBackoff(now, true)) {
					this.peerNodeStatus = PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF;
					if (!this.lastRoutingBackoffReasonRT.equals(this.previousRoutingBackoffReasonRT)) {
						if (this.previousRoutingBackoffReasonRT != null) {
							this.peers.removePeerNodeRoutingBackoffReason(this.previousRoutingBackoffReasonRT, this,
									true);
						}
						this.peers.addPeerNodeRoutingBackoffReason(this.lastRoutingBackoffReasonRT, this, true);
						this.previousRoutingBackoffReasonRT = this.lastRoutingBackoffReasonRT;
					}
				}
				else {
					if (this.previousRoutingBackoffReasonRT != null) {
						this.peers.removePeerNodeRoutingBackoffReason(this.previousRoutingBackoffReasonRT, this, true);
						this.previousRoutingBackoffReasonRT = null;
					}
				}
				if (overPingTime
						&& (this.lastRoutingBackoffReasonBulk == null || now >= this.routingBackedOffUntilBulk)) {
					this.lastRoutingBackoffReasonBulk = "TooHighPing";
				}

				if (now < this.routingBackedOffUntilBulk || overPingTime || this.isInMandatoryBackoff(now, false)) {
					this.peerNodeStatus = PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF;
					if (!this.lastRoutingBackoffReasonBulk.equals(this.previousRoutingBackoffReasonBulk)) {
						if (this.previousRoutingBackoffReasonBulk != null) {
							this.peers.removePeerNodeRoutingBackoffReason(this.previousRoutingBackoffReasonBulk, this,
									false);
						}
						this.peers.addPeerNodeRoutingBackoffReason(this.lastRoutingBackoffReasonBulk, this, false);
						this.previousRoutingBackoffReasonBulk = this.lastRoutingBackoffReasonBulk;
					}
				}
				else {
					if (this.previousRoutingBackoffReasonBulk != null) {
						this.peers.removePeerNodeRoutingBackoffReason(this.previousRoutingBackoffReasonBulk, this,
								false);
						this.previousRoutingBackoffReasonBulk = null;
					}
				}
			}
		}
		else if (isConnected && this.bogusNoderef) {
			this.peerNodeStatus = PeerManager.PEER_NODE_STATUS_CONN_ERROR;
		}
		else if (isConnected && this.unroutableNewerVersion) {
			this.peerNodeStatus = PeerManager.PEER_NODE_STATUS_TOO_NEW;
		}
		else if (isConnected && this.unroutableOlderVersion) {
			this.peerNodeStatus = PeerManager.PEER_NODE_STATUS_TOO_OLD;
		}
		else if (isConnected && this.disableRouting) {
			this.peerNodeStatus = PeerManager.PEER_NODE_STATUS_ROUTING_DISABLED;
		}
		else if (isConnected && Math.abs(this.clockDelta) > MAX_CLOCK_DELTA) {
			this.peerNodeStatus = PeerManager.PEER_NODE_STATUS_CLOCK_PROBLEM;
		}
		else if (this.neverConnected) {
			this.peerNodeStatus = PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED;
		}
		else if (this.isBursting) {
			return PeerManager.PEER_NODE_STATUS_BURSTING;
		}
		else {
			this.peerNodeStatus = PeerManager.PEER_NODE_STATUS_DISCONNECTED;
		}
		if (!isConnected && (this.previousRoutingBackoffReasonRT != null)) {
			this.peers.removePeerNodeRoutingBackoffReason(this.previousRoutingBackoffReasonRT, this, true);
			this.previousRoutingBackoffReasonRT = null;
		}
		if (!isConnected && (this.previousRoutingBackoffReasonBulk != null)) {
			this.peers.removePeerNodeRoutingBackoffReason(this.previousRoutingBackoffReasonBulk, this, false);
			this.previousRoutingBackoffReasonBulk = null;
		}
		return this.peerNodeStatus;
	}

	public int setPeerNodeStatus(long now) {
		return this.setPeerNodeStatus(now, false);
	}

	public int setPeerNodeStatus(long now, boolean noLog) {
		long localRoutingBackedOffUntilRT = this.getRoutingBackedOffUntil(true);
		long localRoutingBackedOffUntilBulk = this.getRoutingBackedOffUntil(true);
		int oldPeerNodeStatus;
		long threshold = this.maxPeerPingTime();
		boolean noLoadStats = this.noLoadStats();
		synchronized (this) {
			oldPeerNodeStatus = this.peerNodeStatus;
			this.peerNodeStatus = this.getPeerNodeStatus(now, localRoutingBackedOffUntilRT,
					localRoutingBackedOffUntilBulk, this.averagePingTime() > threshold, noLoadStats);

			if (this.peerNodeStatus != oldPeerNodeStatus && this.recordStatus()) {
				this.peers.changePeerNodeStatus(this, oldPeerNodeStatus, this.peerNodeStatus, noLog);
			}

		}
		if (logMINOR) {
			Logger.minor(this, "Peer node status now " + this.peerNodeStatus + " was " + oldPeerNodeStatus);
		}
		if (this.peerNodeStatus != oldPeerNodeStatus) {
			if (oldPeerNodeStatus == PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF) {
				this.outputLoadTrackerRealTime.maybeNotifySlotWaiter();
				this.outputLoadTrackerBulk.maybeNotifySlotWaiter();
			}
			this.notifyPeerNodeStatusChangeListeners();
		}
		if (this.peerNodeStatus == PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF) {
			long delta = Math.max(localRoutingBackedOffUntilRT, localRoutingBackedOffUntilBulk) - now + 1;
			if (delta > 0) {
				this.node.ticker.queueTimedJob(this.checkStatusAfterBackoff, "Update status for " + this, delta, true,
						true);
			}
		}
		return this.peerNodeStatus;
	}

	/**
	 * @return True if either bulk or realtime has not yet received a valid peer load
	 * stats message. If so, we will not be able to route requests to the node under new
	 * load management.
	 */
	private boolean noLoadStats() {
		if (this.node.enableNewLoadManagement(false) || this.node.enableNewLoadManagement(true)) {
			if (this.outputLoadTrackerRealTime.getLastIncomingLoadStats() == null) {
				if (this.isRoutable()) {
					Logger.normal(this, "No realtime load stats on " + this);
				}
				return true;
			}
			if (this.outputLoadTrackerBulk.getLastIncomingLoadStats() == null) {
				if (this.isRoutable()) {
					Logger.normal(this, "No bulk load stats on " + this);
				}
				return true;
			}
		}
		return false;
	}

	private final Runnable checkStatusAfterBackoff;

	public abstract boolean recordStatus();

	public String getIdentityString() {
		return this.identityAsBase64String;
	}

	public boolean isFetchingARK() {
		return this.arkFetcher != null;
	}

	public synchronized int getHandshakeCount() {
		return this.handshakeCount;
	}

	/**
	 * Queries the Version class to determine if this peers advertised build-number is
	 * either too-old or to new for the routing of requests.
	 */
	synchronized void updateVersionRoutablity() {
		this.unroutableOlderVersion = this.forwardInvalidVersion();
		this.unroutableNewerVersion = this.reverseInvalidVersion();
	}

	/**
	 * Will return true if routing to this node is either explictly disabled, or disabled
	 * due to noted incompatiblity in build-version numbers. Logically:
	 * "not(isRoutable())", but will return false even if disconnected (meaning routing is
	 * not disabled).
	 */
	public synchronized boolean noLongerRoutable() {
		return this.unroutableNewerVersion || this.unroutableOlderVersion || this.disableRouting;
	}

	final void invalidate(long now) {
		synchronized (this) {
			this.isRoutable = false;
		}
		Logger.normal(this, "Invalidated " + this);
		this.setPeerNodeStatus(System.currentTimeMillis());
	}

	public void maybeOnConnect() {
		if (this.wasDisconnected && this.isConnected()) {
			synchronized (this) {
				this.wasDisconnected = false;
			}
			this.onConnect();
		}
		else if (!this.isConnected()) {
			synchronized (this) {
				this.wasDisconnected = true;
			}
		}
	}

	/**
	 * A method to be called once at the beginning of every time isConnected() is true
	 */
	protected void onConnect() {
		synchronized (this) {
			this.uomCount = 0;
			this.lastSentUOM = -1;
			this.sendingUOMMainJar = false;
			this.sendingUOMLegacyExtJar = false;
		}
		OpennetManager om = this.node.getOpennet();
		if (om != null) {
			// OpennetManager must be notified of a new connection even if it is a darknet
			// peer.
			om.onConnectedPeer(this);
		}
	}

	@Override
	public void onFound(USK origUSK, long edition, FetchResult result) {
		if (this.isConnected() || this.myARK.suggestedEdition > edition) {
			result.asBucket().free();
			return;
		}

		byte[] data;
		try {
			data = result.asByteArray();
		}
		catch (IOException ex) {
			Logger.error(this, "I/O error reading fetched ARK: " + ex, ex);
			result.asBucket().free();
			return;
		}

		String ref;
		ref = new String(data, StandardCharsets.UTF_8);

		SimpleFieldSet fs;
		try {
			fs = new SimpleFieldSet(ref, false, true, false);
			if (logMINOR) {
				Logger.minor(this, "Got ARK for " + this);
			}
			this.gotARK(fs, edition);
		}
		catch (IOException ex) {
			// Corrupt ref.
			Logger.error(this, "Corrupt ARK reference? Fetched " + this.myARK.copy(edition) + " got while parsing: "
					+ ex + " from:\n" + ref, ex);
		}
		result.asBucket().free();

	}

	public synchronized boolean noContactDetails() {
		return this.handshakeIPs == null || this.handshakeIPs.length == 0;
	}

	public synchronized void reportIncomingBytes(int length) {
		this.totalInputSinceStartup += length;
		this.totalBytesExchangedWithCurrentTracker += length;
	}

	public synchronized void reportOutgoingBytes(int length) {
		this.totalOutputSinceStartup += length;
		this.totalBytesExchangedWithCurrentTracker += length;
	}

	public synchronized long getTotalInputBytes() {
		return this.bytesInAtStartup + this.totalInputSinceStartup;
	}

	public synchronized long getTotalOutputBytes() {
		return this.bytesOutAtStartup + this.totalOutputSinceStartup;
	}

	public synchronized long getTotalInputSinceStartup() {
		return this.totalInputSinceStartup;
	}

	public synchronized long getTotalOutputSinceStartup() {
		return this.totalOutputSinceStartup;
	}

	public boolean isSignatureVerificationSuccessfull() {
		return this.isSignatureVerificationSuccessfull;
	}

	public void checkRoutableConnectionStatus() {
		synchronized (this) {
			if (this.isRoutable()) {
				this.hadRoutableConnectionCount += 1;
			}
			this.routableConnectionCheckCount += 1;
			// prevent the average from moving too slowly by capping the checkcount to
			// 200000,
			// which, at 7 seconds between counts, works out to about 2 weeks. This also
			// prevents
			// knowing how long we've had a particular peer long term.
			if (this.routableConnectionCheckCount >= 200000) {
				// divide both sides by the same amount to keep the same ratio
				this.hadRoutableConnectionCount = this.hadRoutableConnectionCount / 2;
				this.routableConnectionCheckCount = this.routableConnectionCheckCount / 2;
			}
		}
	}

	public synchronized double getPercentTimeRoutableConnection() {
		if (this.hadRoutableConnectionCount == 0) {
			return 0.0;
		}
		return ((double) this.hadRoutableConnectionCount) / this.routableConnectionCheckCount;
	}

	@Override
	public int getVersionNumber() {
		return Version.getArbitraryBuildNumber(this.getVersion(), -1);
	}

	private final PacketThrottle _lastThrottle = new PacketThrottle(Node.PACKET_SIZE);

	@Override
	public PacketThrottle getThrottle() {
		return this._lastThrottle;
	}

	/**
	 * Select the most appropriate negType, taking the user's preference into account
	 * order matters
	 * @return -1 if no common negType has been found
	 */
	public int selectNegType(OutgoingPacketMangler mangler) {
		int[] hisNegTypes;
		int[] myNegTypes = mangler.supportedNegTypes(false);
		synchronized (this) {
			hisNegTypes = this.negTypes;
		}
		int bestNegType = -1;
		for (int negType : myNegTypes) {
			for (int hisNegType : hisNegTypes) {
				if (hisNegType == negType) {
					bestNegType = negType;
					break;
				}
			}
		}
		return bestNegType;
	}

	public String userToString() {
		return String.valueOf(this.getPeer());
	}

	public void setTimeDelta(long delta) {
		synchronized (this) {
			this.clockDelta = delta;
			if (Math.abs(this.clockDelta) > MAX_CLOCK_DELTA) {
				this.isRoutable = false;
			}
		}
		this.setPeerNodeStatus(System.currentTimeMillis());
	}

	public long getClockDelta() {
		return this.clockDelta;
	}

	/** Offer a key to this node */
	public void offer(Key key) {
		byte[] keyBytes = key.getFullKey();
		// FIXME maybe the authenticator should be shorter than 32 bytes to save memory?
		byte[] authenticator = HMAC.macWithSHA256(this.node.failureTable.offerAuthenticatorKey, keyBytes);
		Message msg = DMT.createFNPOfferKey(key, authenticator);
		try {
			this.sendAsync(msg, null, this.node.nodeStats.sendOffersCtr);
		}
		catch (NotConnectedException ignored) {
			// Ignore
		}
	}

	@Override
	public OutgoingPacketMangler getOutgoingMangler() {
		return this.outgoingMangler;
	}

	@Override
	public SocketHandler getSocketHandler() {
		return this.outgoingMangler.getSocketHandler();
	}

	/** Is this peer disabled? I.e. has the user explicitly disabled it? */
	public boolean isDisabled() {
		return false;
	}

	/**
	 * Is this peer allowed local addresses? If false, we will never connect to this peer
	 * via a local address even if it advertises them.
	 */
	public boolean allowLocalAddresses() {
		return this.outgoingMangler.alwaysAllowLocalAddresses();
	}

	/**
	 * Is this peer set to ignore source address? If so, we will always reply to the
	 * peer's official address, even if we get packets from somewhere else. @see
	 * DarknetPeerNode.isIgnoreSourcePort().
	 */
	public boolean isIgnoreSource() {
		return false;
	}

	/**
	 * Create a DarknetPeerNode or an OpennetPeerNode as appropriate
	 */
	public static PeerNode create(SimpleFieldSet fs, Node node2, NodeCrypto crypto, OpennetManager opennet,
			PeerManager manager)
			throws FSParseException, PeerParseException, ReferenceSignatureVerificationException, PeerTooOldException {
		if (crypto.isOpennet) {
			return new OpennetPeerNode(fs, node2, crypto, opennet, true);
		}
		else {
			return new DarknetPeerNode(fs, node2, crypto, true, null, null);
		}
	}

	public boolean neverConnected() {
		return this.neverConnected;
	}

	/** Called when a request or insert succeeds. Used by opennet. */
	public abstract void onSuccess(boolean insert, boolean ssk);

	/**
	 * Called when a delayed disconnect is occurring. Tell the node that it is being
	 * disconnected, but that the process may take a while. After this point, requests
	 * will not be accepted from the peer nor routed to it.
	 * @param dumpMessageQueue If true, immediately dump the message queue, since we are
	 * closing the connection due to some low level trouble e.g. not acknowledging. We
	 * will continue to try to send anything already in flight, and it is possible to send
	 * more messages after this point, for instance the message telling it we are
	 * disconnecting, but see above - no requests will be routed across this connection.
	 * @return True if we have already started disconnecting, false otherwise.
	 */
	public boolean notifyDisconnecting(boolean dumpMessageQueue) {
		MessageItem[] messagesTellDisconnected = null;
		synchronized (this) {
			if (this.disconnecting) {
				return true;
			}
			this.disconnecting = true;
			this.jfkNoncesSent.clear();
			if (dumpMessageQueue) {
				// Reset the boot ID so that we get different trackers next time.
				this.myBootID = this.node.fastWeakRandom.nextLong();
				messagesTellDisconnected = this.grabQueuedMessageItems();
			}
		}
		this.setPeerNodeStatus(System.currentTimeMillis());
		if (messagesTellDisconnected != null) {
			if (logMINOR) {
				Logger.minor(this, "Messages to dump: " + messagesTellDisconnected.length);
			}
			for (MessageItem mi : messagesTellDisconnected) {
				mi.onDisconnect();
			}
		}
		return false;
	}

	/**
	 * Called to cancel a delayed disconnect. Always succeeds even if the node was not
	 * being disconnected.
	 */
	public void forceCancelDisconnecting() {
		synchronized (this) {
			this.removed = false;
			if (!this.disconnecting) {
				return;
			}
			this.disconnecting = false;
		}
		this.setPeerNodeStatus(System.currentTimeMillis(), true);
	}

	/** Called when the peer is removed from the PeerManager */
	public void onRemove() {
		synchronized (this) {
			this.removed = true;
		}
		this.node.getTicker().removeQueuedJob(this.checkStatusAfterBackoff);
		this.disconnected(true, true);
		this.stopARKFetcher();
	}

	/**
	 * @return True if we have been removed from the peers list.
	 */
	synchronized boolean cachedRemoved() {
		return this.removed;
	}

	public synchronized boolean isDisconnecting() {
		return this.disconnecting;
	}

	protected byte[] getJFKBuffer() {
		return this.jfkBuffer;
	}

	protected void setJFKBuffer(byte[] bufferJFK) {
		this.jfkBuffer = bufferJFK;
	}

	static final int MAX_SIMULTANEOUS_ANNOUNCEMENTS = 1;
	static final int MAX_ANNOUNCE_DELAY = 1000;

	private long timeLastAcceptedAnnouncement;

	private long[] runningAnnounceUIDs = new long[0];

	public synchronized boolean shouldAcceptAnnounce(long uid) {
		long now = System.currentTimeMillis();
		if (this.runningAnnounceUIDs.length < MAX_SIMULTANEOUS_ANNOUNCEMENTS
				&& now - this.timeLastAcceptedAnnouncement > MAX_ANNOUNCE_DELAY) {
			long[] newList = new long[this.runningAnnounceUIDs.length + 1];
			if (this.runningAnnounceUIDs.length > 0) {
				System.arraycopy(this.runningAnnounceUIDs, 0, newList, 0, this.runningAnnounceUIDs.length);
			}
			newList[this.runningAnnounceUIDs.length] = uid;
			this.timeLastAcceptedAnnouncement = now;
			return true;
		}
		else {
			return false;
		}
	}

	public synchronized boolean completedAnnounce(long uid) {
		final int runningAnnounceUIDsLength = this.runningAnnounceUIDs.length;
		if (runningAnnounceUIDsLength < 1) {
			return false;
		}
		long[] newList = new long[runningAnnounceUIDsLength - 1];
		int x = 0;
		for (long l : this.runningAnnounceUIDs) {
			if (l == uid) {
				continue;
			}
			newList[x++] = l;
		}
		this.runningAnnounceUIDs = newList;
		if (x < this.runningAnnounceUIDs.length) {
			assert (false); // Callers prevent duplicated UIDs.
			this.runningAnnounceUIDs = Arrays.copyOf(this.runningAnnounceUIDs, x);
		}
		return true;
	}

	public synchronized long timeLastDisconnect() {
		return this.timeLastDisconnect;
	}

	/**
	 * Does this peernode want to be returned by for example PeerManager.getByPeer() ?
	 * False = seednode etc, never going to be routable.
	 */
	public abstract boolean isRealConnection();

	/** Can we accept announcements from this node? */
	public abstract boolean canAcceptAnnouncements();

	public boolean handshakeUnknownInitiator() {
		return false;
	}

	public int handshakeSetupType() {
		return -1;
	}

	@Override
	public WeakReference<PeerNode> getWeakRef() {
		return this.myRef;
	}

	/**
	 * Get a single address to send a handshake to. The current code doesn't work well
	 * with multiple simulataneous handshakes. Alternates between valid values. (FIXME!)
	 */
	public Peer getHandshakeIP() {
		Peer[] localHandshakeIPs;
		if (!this.shouldSendHandshake()) {
			if (logMINOR) {
				Logger.minor(this, "Not sending handshake to " + this.getPeer()
						+ " because pn.shouldSendHandshake() returned false");
			}
			return null;
		}
		long firstTime = System.currentTimeMillis();
		localHandshakeIPs = this.getHandshakeIPs();
		long secondTime = System.currentTimeMillis();
		if ((secondTime - firstTime) > 1000) {
			Logger.error(this, "getHandshakeIPs() took more than a second to execute (" + (secondTime - firstTime)
					+ ") working on " + this.userToString());
		}
		if (localHandshakeIPs.length == 0) {
			long thirdTime = System.currentTimeMillis();
			if ((thirdTime - secondTime) > 1000) {
				Logger.error(this,
						"couldNotSendHandshake() (after getHandshakeIPs()) took more than a second to execute ("
								+ (thirdTime - secondTime) + ") working on " + this.userToString());
			}
			return null;
		}
		long loopTime1 = System.currentTimeMillis();
		List<Peer> validIPs = new ArrayList<>(localHandshakeIPs.length);
		boolean allowLocalAddresses = this.allowLocalAddresses();
		for (Peer peer : localHandshakeIPs) {
			FreenetInetAddress addr = peer.getFreenetAddress();
			if (peer.getAddress(false) == null) {
				if (logMINOR) {
					Logger.minor(this, "Not sending handshake to " + peer + " for " + this.getPeer()
							+ " because the DNS lookup failed or it's a currently unsupported IPv6 address");
				}
				continue;
			}
			if (!peer.isRealInternetAddress(false, false, allowLocalAddresses)) {
				if (logMINOR) {
					Logger.minor(this, "Not sending handshake to " + peer + " for " + this.getPeer()
							+ " because it's not a real Internet address and metadata.allowLocalAddresses is not true");
				}
				continue;
			}
			if (!this.isConnected()) {
				// If we are connected, we are rekeying.
				// We have separate code to boot out connections.
				if (!this.outgoingMangler.allowConnection(this, addr)) {
					if (logMINOR) {
						Logger.minor(this, "Not sending handshake packet to " + peer + " for " + this);
					}
					continue;
				}
			}
			validIPs.add(peer);
		}
		Peer ret;
		if (validIPs.isEmpty()) {
			ret = null;
		}
		else if (validIPs.size() == 1) {
			ret = validIPs.get(0);
		}
		else {
			// Don't need to synchronize for this value as we're only called from one
			// thread anyway.
			this.handshakeIPAlternator %= validIPs.size();
			ret = validIPs.get(this.handshakeIPAlternator);
			this.handshakeIPAlternator++;
		}
		long loopTime2 = System.currentTimeMillis();
		if ((loopTime2 - loopTime1) > 1000) {
			Logger.normal(this, "loopTime2 is more than a second after loopTime1 (" + (loopTime2 - loopTime1)
					+ ") working on " + this.userToString());
		}
		return ret;
	}

	private int handshakeIPAlternator;

	public void sendNodeToNodeMessage(SimpleFieldSet fs, int n2nType, boolean includeSentTime, long now,
			boolean queueOnNotConnected) {
		fs.putOverwrite("n2nType", Integer.toString(n2nType));
		if (includeSentTime) {
			fs.put("sentTime", now);
		}
		Message n2nm;
		n2nm = DMT.createNodeToNodeMessage(n2nType, fs.toString().getBytes(StandardCharsets.UTF_8));
		UnqueueMessageOnAckCallback cb = null;
		if (this.isDarknet() && queueOnNotConnected) {
			int fileNumber = this.queueN2NM(fs);
			cb = new UnqueueMessageOnAckCallback((DarknetPeerNode) this, fileNumber);
		}
		try {
			this.sendAsync(n2nm, cb, this.node.nodeStats.nodeToNodeCounter);
		}
		catch (NotConnectedException ignored) {
			if (includeSentTime) {
				fs.removeValue("sentTime");
			}
		}
	}

	/**
	 * A method to queue an N2NM in a extra peer data file, only implemented by
	 * DarknetPeerNode.
	 *
	 * Returns the fileNumber of the created n2nm, -1 if no file was created.
	 */
	public int queueN2NM(SimpleFieldSet fs) {
		return -1; // Do nothing in the default impl
	}

	/**
	 * Return the relevant local node reference related to this peer's type
	 */
	protected SimpleFieldSet getLocalNoderef() {
		return this.crypto.exportPublicFieldSet();
	}

	/**
	 * A method to be called after completing a handshake to send the newly connected
	 * peer, as a differential node reference, the parts of our node reference not needed
	 * for handshake. Should only be called by completedHandshake() after we're happy with
	 * the connection
	 *
	 * FIXME this should be sent when our noderef changes.
	 */
	protected void sendConnectedDiffNoderef() {
		SimpleFieldSet fs = new SimpleFieldSet(true);
		SimpleFieldSet nfs = this.getLocalNoderef();
		if (null == nfs) {
			return;
		}
		String s;
		s = nfs.get("ark.pubURI");
		if (null != s) {
			fs.putOverwrite("ark.pubURI", s);
		}
		s = nfs.get("ark.number");
		if (null != s) {
			fs.putOverwrite("ark.number", s);
		}
		if (this.isDarknet()) {
			s = nfs.get("myName");
			if (s != null) {
				fs.putOverwrite("myName", s);
			}
		}
		String[] physicalUDPEntries = nfs.getAll("physical.udp");
		if (physicalUDPEntries != null) {
			fs.putOverwrite("physical.udp", physicalUDPEntries);
		}
		if (!fs.isEmpty()) {
			if (logMINOR) {
				Logger.minor(this, "fs is '" + fs + "'");
			}
			this.sendNodeToNodeMessage(fs, Node.N2N_MESSAGE_TYPE_DIFFNODEREF, false, 0, false);
		}
		else {
			if (logMINOR) {
				Logger.minor(this, "fs is empty");
			}
		}
	}

	@Override
	public boolean shouldThrottle() {
		return shouldThrottle(this.getPeer(), this.node);
	}

	public static boolean shouldThrottle(Peer peer, Node node) {
		if (node.throttleLocalData) {
			return true;
		}
		if (peer == null) {
			return true; // presumably
		}
		InetAddress addr = peer.getAddress(false);
		if (addr == null) {
			return true; // presumably
		}
		return IPUtil.isValidAddress(addr, false);
	}

	static final long MAX_RTO = TimeUnit.SECONDS.toMillis(60);
	static final long MIN_RTO = TimeUnit.SECONDS.toMillis(1);

	private int consecutiveRTOBackoffs;

	// Clock generally has 20ms granularity or better, right?
	// FIXME determine the clock granularity.
	private static final int CLOCK_GRANULARITY = 20;

	@Override
	public void reportPing(long t) {
		this.pingAverage.report(t);
		synchronized (this) {
			this.consecutiveRTOBackoffs = 0;
			// Update RTT according to RFC 2988.
			if (!this.reportedRTT) {
				double oldRTO = this.RTO;
				// Initialize
				this.SRTT = t;
				this.RTTVAR = ((double) t) / 2;
				this.RTO = this.SRTT + Math.max(CLOCK_GRANULARITY, this.RTTVAR * 4);
				// RFC 2988 specifies a 1 second minimum RTT, mostly due to legacy issues,
				// but given that Freenet is mostly used on very slow upstream links, it
				// probably makes sense for us too for now, to avoid excessive
				// retransmits.
				// FIXME !!!
				if (this.RTO < MIN_RTO) {
					this.RTO = MIN_RTO;
				}
				if (this.RTO > MAX_RTO) {
					this.RTO = MAX_RTO;
				}
				this.reportedRTT = true;
				if (logMINOR) {
					Logger.minor(this,
							"Received first packet on " + this.shortToString() + " setting RTO to " + this.RTO);
				}
				if (oldRTO > this.RTO) {
					// We have backed off
					if (logMINOR) {
						Logger.minor(this, "Received first packet after backing off on resend. RTO is " + this.RTO
								+ " but was " + oldRTO);
					}
					// FIXME: do something???
				}
			}
			else {
				// Update
				this.RTTVAR = 0.75 * this.RTTVAR + 0.25 * Math.abs(this.SRTT - t);
				this.SRTT = 0.875 * this.SRTT + 0.125 * t;
				this.RTO = this.SRTT + Math.max(CLOCK_GRANULARITY, this.RTTVAR * 4);
				// RFC 2988 specifies a 1 second minimum RTT, mostly due to legacy issues,
				// but given that Freenet is mostly used on very slow upstream links, it
				// probably makes sense for us too for now, to avoid excessive
				// retransmits.
				// FIXME !!!
				if (this.RTO < MIN_RTO) {
					this.RTO = MIN_RTO;
				}
				if (this.RTO > MAX_RTO) {
					this.RTO = MAX_RTO;
				}
			}
			if (logMINOR) {
				Logger.minor(this,
						"Reported ping " + t + " avg is now " + this.pingAverage.currentValue() + " RTO is " + this.RTO
								+ " SRTT is " + this.SRTT + " RTTVAR is " + this.RTTVAR + " for "
								+ this.shortToString());
			}
		}
	}

	/**
	 * RFC 2988: Note that a TCP implementation MAY clear SRTT and RTTVAR after backing
	 * off the timer multiple times as it is likely that the current SRTT and RTTVAR are
	 * bogus in this situation. Once SRTT and RTTVAR are cleared they should be
	 * initialized with the next RTT sample taken per (2.2) rather than using (2.3).
	 */
	static final int MAX_CONSECUTIVE_RTO_BACKOFFS = 5;

	@Override
	public synchronized void backoffOnResend() {
		if (this.RTO >= MAX_RTO) {
			Logger.error(this, "Major packet loss on " + this + " - RTO is already at limit and still losing packets!");
		}
		this.RTO = this.RTO * 2;
		if (this.RTO > MAX_RTO) {
			this.RTO = MAX_RTO;
		}
		this.consecutiveRTOBackoffs++;
		if (this.consecutiveRTOBackoffs > MAX_CONSECUTIVE_RTO_BACKOFFS) {
			Logger.warning(this, "Resetting RTO for " + this + " after " + this.consecutiveRTOBackoffs
					+ " consecutive backoffs due to packet loss");
			this.consecutiveRTOBackoffs = 0;
			this.reportedRTT = false;
		}
		if (logMINOR) {
			Logger.minor(this, "Backed off on resend, RTO is now " + this.RTO + " for " + this.shortToString()
					+ " consecutive RTO backoffs is " + this.consecutiveRTOBackoffs);
		}
	}

	private long resendBytesSent;

	public final ByteCounter resendByteCounter = new ByteCounter() {

		@Override
		public void receivedBytes(int x) {
			// Ignore
		}

		@Override
		public void sentBytes(int x) {
			synchronized (PeerNode.this) {
				PeerNode.this.resendBytesSent += x;
			}
			PeerNode.this.node.nodeStats.resendByteCounter.sentBytes(x);
		}

		@Override
		public void sentPayload(int x) {
			// Ignore
		}

	};

	public long getResendBytesSent() {
		return this.resendBytesSent;
	}

	/**
	 * Should this peer be disconnected and removed immediately?
	 */
	public boolean shouldDisconnectAndRemoveNow() {
		return false;
	}

	public void setUptime(byte uptime2) {
		this.uptime = uptime2;
	}

	public short getUptime() {
		return (short) (this.uptime & 0xFF);
	}

	public void incrementNumberOfSelections(long time) {
		// TODO: reimplement with a bit field to spare memory
		synchronized (this) {
			this.countSelectionsSinceConnected++;
		}
	}

	/**
	 * @return The rate at which this peer has been selected since it connected.
	 */
	public synchronized double selectionRate() {
		long timeSinceConnected = System.currentTimeMillis() - this.connectedTime;
		// Avoid bias due to short uptime.
		if (timeSinceConnected < TimeUnit.SECONDS.toMillis(10)) {
			return 0.0;
		}
		return this.countSelectionsSinceConnected / (double) timeSinceConnected;
	}

	private volatile long offeredManifestVersion;

	public void setManifestOfferedVersion(long mainJarVersion) {
		this.offeredManifestVersion = mainJarVersion;
	}

	public long getManifestOfferedVersion() {
		return this.offeredManifestVersion;
	}

	/**
	 * Maybe send something. A SINGLE PACKET. Don't send everything at once, for two
	 * reasons: 1. It is possible for a node to have a very long backlog. 2. Sometimes
	 * sending a packet can take a long time. 3. In the near future PacketSender will be
	 * responsible for output bandwidth throttling. So it makes sense to send a single
	 * packet and round-robin.
	 */
	public boolean maybeSendPacket(long now, boolean ackOnly) throws BlockedTooLongException {
		PacketFormat pf;
		synchronized (this) {
			if (this.packetFormat == null) {
				return false;
			}
			pf = this.packetFormat;
		}
		return pf.maybeSendPacket(now, ackOnly);
	}

	/**
	 * @return The ID of a reusable PacketTracker if there is one, otherwise -1.
	 */
	public long getReusableTrackerID() {
		SessionKey cur;
		synchronized (this) {
			cur = this.currentTracker;
		}
		if (cur == null) {
			if (logMINOR) {
				Logger.minor(this, "getReusableTrackerID(): cur = null on " + this);
			}
			return -1;
		}
		if (logMINOR) {
			Logger.minor(this, "getReusableTrackerID(): " + cur.trackerID + " on " + this);
		}
		return cur.trackerID;
	}

	private long lastFailedRevocationTransfer;

	/** Reset on disconnection */
	private int countFailedRevocationTransfers;

	public void failedRevocationTransfer() {
		// Something odd happened, possibly a disconnect, maybe looking up the DNS names
		// will help?
		this.lastAttemptedHandshakeIPUpdateTime = System.currentTimeMillis();
		this.countFailedRevocationTransfers++;
	}

	public int countFailedRevocationTransfers() {
		return this.countFailedRevocationTransfers;
	}

	/**
	 * Registers a listener that will be notified when status changes. Only the
	 * WeakReference of it is stored, so there is no need for deregistering
	 * @param listener - The listener to be registered
	 */
	public void registerPeerNodeStatusChangeListener(PeerManager.PeerStatusChangeListener listener) {
		this.listeners.add(listener);
	}

	/** Notifies the listeners that status has been changed */
	private void notifyPeerNodeStatusChangeListeners() {
		synchronized (this.listeners) {
			for (PeerManager.PeerStatusChangeListener l : this.listeners) {
				l.onPeerStatusChange();
			}
		}
	}

	public boolean isLowUptime() {
		return this.getUptime() < Node.MIN_UPTIME_STORE_KEY;
	}

	public void setAddedReason(OpennetManager.ConnectionType connectionType) {
		// Do nothing.
	}

	public synchronized OpennetManager.ConnectionType getAddedReason() {
		return null;
	}

	private final Object routedToLock = new Object();

	final LoadSender loadSenderRealTime = new LoadSender(true);

	final LoadSender loadSenderBulk = new LoadSender(false);

	void removeUIDsFromMessageQueues(Long[] list) {
		this.messageQueue.removeUIDsFromMessageQueues(list);
	}

	public void onSetMaxOutputTransfers(boolean realTime, int maxOutputTransfers) {
		(realTime ? this.loadSenderRealTime : this.loadSenderBulk).onSetMaxOutputTransfers(maxOutputTransfers);
	}

	public void onSetMaxOutputTransfersPeerLimit(boolean realTime, int maxOutputTransfers) {
		(realTime ? this.loadSenderRealTime : this.loadSenderBulk).onSetMaxOutputTransfersPeerLimit(maxOutputTransfers);
	}

	public void onSetPeerAllocation(boolean input, int thisAllocation, int transfersPerInsert, int maxOutputTransfers,
			boolean realTime) {
		(realTime ? this.loadSenderRealTime : this.loadSenderBulk).onSetPeerAllocation(input, thisAllocation,
				transfersPerInsert);
	}

	// FIXME add LOW_CAPACITY/BROKEN. Set this when the published capacity is way below
	// the median.
	// FIXME will need to calculate the median first!

	OutputLoadTracker outputLoadTrackerRealTime = new OutputLoadTracker(true);

	OutputLoadTracker outputLoadTrackerBulk = new OutputLoadTracker(false);

	public OutputLoadTracker outputLoadTracker(boolean realTime) {
		return realTime ? this.outputLoadTrackerRealTime : this.outputLoadTrackerBulk;
	}

	public void reportLoadStatus(NodeStats.PeerLoadStats stat) {
		this.outputLoadTracker(stat.realTime).reportLoadStatus(stat);
		this.node.executor.execute(this.checkStatusAfterBackoff);
	}

	/** cached RequestType.values(). Never modify or pass this array to outside code! */
	private static final NodeStats.RequestType[] RequestType_values = NodeStats.RequestType.values();

	public void noLongerRoutingTo(UIDTag tag, boolean offeredKey) {
		if (offeredKey && !(tag instanceof RequestTag)) {
			throw new IllegalArgumentException("Only requests can have offeredKey=true");
		}
		synchronized (this.routedToLock) {
			if (offeredKey) {
				tag.removeFetchingOfferedKeyFrom(this);
			}
			else {
				tag.removeRoutingTo(this);
			}
		}
		if (logMINOR) {
			Logger.minor(this, "No longer routing " + tag + " to " + this);
		}
		this.outputLoadTracker(tag.realTimeFlag).maybeNotifySlotWaiter();
	}

	public void postUnlock(UIDTag tag) {
		this.outputLoadTracker(tag.realTimeFlag).maybeNotifySlotWaiter();
	}

	static SlotWaiter createSlotWaiter(UIDTag tag, NodeStats.RequestType type, boolean offeredKey, boolean realTime,
			PeerNode source) {
		return new SlotWaiter(tag, type, offeredKey, realTime, source);
	}

	public IncomingLoadSummaryStats getIncomingLoadStats(boolean realTime) {
		return this.outputLoadTracker(realTime).getIncomingLoadStats();
	}

	public LoadSender loadSender(boolean realtime) {
		return realtime ? this.loadSenderRealTime : this.loadSenderBulk;
	}

	/**
	 * A fatal timeout occurred, and we don't know whether the peer is still running the
	 * request we passed in for us. If it is, we cannot reuse that slot. So we need to
	 * query it periodically until it is no longer running it. If we cannot send the query
	 * or if we don't get a response, we disconnect via fatalTimeout() (with no
	 * arguments).
	 * @param tag The request which we routed to this peer. It may or may not still be
	 * running.
	 */
	public void fatalTimeout(UIDTag tag, boolean offeredKey) {
		// FIXME implement! For now we just disconnect (no-op).
		// A proper implementation requires new messages.
		this.noLongerRoutingTo(tag, offeredKey);
		this.fatalTimeout();
	}

	/**
	 * After a fatal timeout - that is, a timeout that we reasonably believe originated on
	 * the node rather than downstream - we do not know whether or not the node thinks the
	 * request is still running. Hence load management will get really confused and likely
	 * start to send requests over and over, which are repeatedly rejected.
	 *
	 * So we have some alternatives: 1) Lock the slot forever (or at least until the node
	 * reconnects). So every time a node times out, it loses a slot, and gradually it
	 * becomes completely catatonic. 2) Wait forever for an acknowledgement of the
	 * timeout. This may be worth investigating. One problem with this is that the slot
	 * would still count towards our overall load management, which is surely a bad thing,
	 * although we could make it only count towards this node. Also, if it doesn't arrive
	 * in a reasonable time maybe there has been a severe problem e.g. out of memory, bug
	 * etc; in that case, waiting forever may not be sensible. 3) Disconnect the node.
	 * This makes perfect sense for opennet. For darknet it's a bit more problematic. 4)
	 * Turn off routing to the node, possibly for a limited period. This would need to
	 * include the effects of disconnection. It might open up some cheapish local DoS's.
	 *
	 * For all nodes, at present, we disconnect. For darknet nodes, we log an error, and
	 * allow them to reconnect.
	 */
	public abstract void fatalTimeout();

	public abstract boolean shallWeRouteAccordingToOurPeersLocation(int htl);

	@Override
	public PeerMessageQueue getMessageQueue() {
		return this.messageQueue;
	}

	public boolean handleReceivedPacket(byte[] buf, int offset, int length, long now, Peer replyTo) {
		PacketFormat pf;
		synchronized (this) {
			pf = this.packetFormat;
			if (pf == null) {
				return false;
			}
		}
		return pf.handleReceivedPacket(buf, offset, length, now, replyTo);
	}

	public void checkForLostPackets() {
		PacketFormat pf;
		synchronized (this) {
			pf = this.packetFormat;
			if (pf == null) {
				return;
			}
		}
		pf.checkForLostPackets();
	}

	public long timeCheckForLostPackets() {
		PacketFormat pf;
		synchronized (this) {
			pf = this.packetFormat;
			if (pf == null) {
				return Long.MAX_VALUE;
			}
		}
		return pf.timeCheckForLostPackets();
	}

	/**
	 * Only called for new format connections, for which we don't care about PacketTracker
	 */
	public void dumpTracker(SessionKey brokenKey) {
		long now = System.currentTimeMillis();
		synchronized (this) {
			if (this.currentTracker == brokenKey) {
				this.currentTracker = null;
				this.isConnected.set(false, now);
			}
			else if (this.previousTracker == brokenKey) {
				this.previousTracker = null;
			}
			else if (this.unverifiedTracker == brokenKey) {
				this.unverifiedTracker = null;
			}
		}
		// Update connected vs not connected status.
		this.isConnected();
		this.setPeerNodeStatus(System.currentTimeMillis());
	}

	@Override
	public void handleMessage(Message m) {
		this.node.usm.checkFilters(m, this.crypto.socket);
	}

	@Override
	public void sendEncryptedPacket(byte[] data) throws LocalAddressException {
		this.crypto.socket.sendPacket(data, this.getPeer(), this.allowLocalAddresses());
	}

	@Override
	public int getMaxPacketSize() {
		return this.crypto.socket.getMaxPacketSize();
	}

	@Override
	public boolean shouldPadDataPackets() {
		return this.crypto.config.paddDataPackets();
	}

	@Override
	public void sentThrottledBytes(int count) {
		this.node.outputThrottle.forceGrab(count);
	}

	@Override
	public void onNotificationOnlyPacketSent(int length) {
		this.node.nodeStats.reportNotificationOnlyPacketSent(length);
	}

	@Override
	public void resentBytes(int length) {
		this.resendByteCounter.sentBytes(length);
	}

	// FIXME move this to PacketFormat eventually.
	@Override
	public Random paddingGen() {
		return this.paddingGen;
	}

	public synchronized boolean matchesPeerAndPort(Peer peer) {
		if (this.detectedPeer != null && this.detectedPeer.laxEquals(peer)) {
			return true;
		}
		if (this.nominalPeer != null) { // FIXME condition necessary???
			for (Peer p : this.nominalPeer) {
				if (p != null && p.laxEquals(peer)) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Does this PeerNode match the given IP address?
	 * @param strict If true, only match if the IP is actually in use. If false, also
	 * match from nominal IP addresses and domain names etc.
	 */
	public synchronized boolean matchesIP(FreenetInetAddress addr, boolean strict) {
		if (this.detectedPeer != null) {
			FreenetInetAddress a = this.detectedPeer.getFreenetAddress();
			if (a != null) {
				if (strict ? a.equals(addr) : a.laxEquals(addr)) {
					return true;
				}
			}
		}
		if ((!strict) && this.nominalPeer != null) {
			for (Peer p : this.nominalPeer) {
				if (p == null) {
					continue;
				}
				FreenetInetAddress a = p.getFreenetAddress();
				if (a == null) {
					continue;
				}
				if (a.laxEquals(addr)) {
					return true;
				}
			}
		}
		return false;
	}

	@Override
	public MessageItem makeLoadStats(boolean realtime, boolean boostPriority, boolean noRemember) {
		// FIXME re-enable when try NLM again.
		return null;
		// Message msg = loadSender(realtime).makeLoadStats(System.currentTimeMillis(),
		// node.nodeStats.outwardTransfersPerInsert(), noRemember);
		// if(msg == null) return null;
		// return new MessageItem(msg, null, node.nodeStats.allocationNoticesCounter,
		// boostPriority ? DMT.PRIORITY_NOW : (short)-1);
	}

	@Override
	public boolean grabSendLoadStatsASAP(boolean realtime) {
		return this.loadSender(realtime).grabSendASAP();
	}

	@Override
	public void setSendLoadStatsASAP(boolean realtime) {
		this.loadSender(realtime).setSendASAP();
	}

	@Override
	public DecodingMessageGroup startProcessingDecryptedMessages(int size) {
		return new MyDecodingMessageGroup(size);
	}

	public boolean isLowCapacity(boolean isRealtime) {
		NodeStats.PeerLoadStats stats = this.outputLoadTracker(isRealtime).getLastIncomingLoadStats();
		if (stats == null) {
			return false;
		}
		NodePinger pinger = this.node.nodeStats.nodePinger;
		if (pinger == null) {
			return false; // FIXME possible?
		}
		if (pinger.capacityThreshold(isRealtime, true) > stats.peerLimit(true)) {
			return true;
		}
		return pinger.capacityThreshold(isRealtime, false) > stats.peerLimit(false);
	}

	public void reportRoutedTo(double target, boolean isLocal, boolean realTime, PeerNode prev, Set<PeerNode> routedTo,
			int htl) {
		double distance = Location.distance(target, this.getLocation());

		double myLoc = this.node.getLocation();
		double prevLoc;
		if (prev != null) {
			prevLoc = prev.getLocation();
		}
		else {
			prevLoc = -1.0;
		}

		Set<Double> excludeLocations = new HashSet<>();
		excludeLocations.add(myLoc);
		excludeLocations.add(prevLoc);
		for (PeerNode routedToNode : routedTo) {
			excludeLocations.add(routedToNode.getLocation());
		}

		if (this.shallWeRouteAccordingToOurPeersLocation(htl)) {
			double l = this.getClosestPeerLocation(target, excludeLocations);
			if (!Double.isNaN(l)) {
				double newDiff = Location.distance(l, target);
				if (newDiff < distance) {
					distance = newDiff;
				}
			}
			if (logMINOR) {
				Logger.minor(this,
						"The peer " + this
								+ " has published his peer's locations and the closest we have found to the target is "
								+ distance + " away.");
			}
		}

		this.node.nodeStats.routingMissDistanceOverall.report(distance);
		(isLocal ? this.node.nodeStats.routingMissDistanceLocal : this.node.nodeStats.routingMissDistanceRemote)
				.report(distance);
		(realTime ? this.node.nodeStats.routingMissDistanceRT : this.node.nodeStats.routingMissDistanceBulk)
				.report(distance);
		this.node.peers.incrementSelectionSamples(System.currentTimeMillis(), this);
	}

	private long maxPeerPingTime() {
		if (this.node == null) {
			return NodeStats.DEFAULT_MAX_PING_TIME * 2;
		}
		NodeStats stats = this.node.nodeStats;
		if (this.node.nodeStats == null) {
			return NodeStats.DEFAULT_MAX_PING_TIME * 2;
		}
		else {
			return stats.maxPeerPingTime();
		}
	}

	/** Whether we are sending the main jar to this peer */
	protected boolean sendingUOMMainJar;

	/** Whether we are sending the ext jar (legacy) to this peer */
	protected boolean sendingUOMLegacyExtJar;

	/**
	 * The number of UOM transfers in progress to this peer. Note that there are
	 * mechanisms in UOM to limit this.
	 */
	private int uomCount;

	/**
	 * The time when we last had UOM transfers in progress to this peer, if uomCount == 0.
	 */
	private long lastSentUOM;

	// FIXME consider limiting the individual dependencies.
	// Not clear whether that would actually improve protection against DoS, given that
	// transfer failures happen naturally anyway.

	/**
	 * Start sending a UOM jar to this peer.
	 * @return True unless it was already sending, in which case the caller should reject
	 * it.
	 */
	public synchronized boolean sendingUOMJar(boolean isExt) {
		if (isExt) {
			if (this.sendingUOMLegacyExtJar) {
				return false;
			}
			this.sendingUOMLegacyExtJar = true;
		}
		else {
			if (this.sendingUOMMainJar) {
				return false;
			}
			this.sendingUOMMainJar = true;
		}
		return true;
	}

	public synchronized void finishedSendingUOMJar(boolean isExt) {
		if (isExt) {
			this.sendingUOMLegacyExtJar = false;
			if (!(this.sendingUOMMainJar || this.uomCount > 0)) {
				this.lastSentUOM = System.currentTimeMillis();
			}
		}
		else {
			this.sendingUOMMainJar = false;
			if (!(this.sendingUOMLegacyExtJar || this.uomCount > 0)) {
				this.lastSentUOM = System.currentTimeMillis();
			}
		}
	}

	protected synchronized long timeSinceSentUOM() {
		if (this.sendingUOMMainJar || this.sendingUOMLegacyExtJar) {
			return 0;
		}
		if (this.uomCount > 0) {
			return 0;
		}
		if (this.lastSentUOM <= 0) {
			return Long.MAX_VALUE;
		}
		return System.currentTimeMillis() - this.lastSentUOM;
	}

	public synchronized void incrementUOMSends() {
		this.uomCount++;
	}

	public synchronized void decrementUOMSends() {
		this.uomCount--;
		if (this.uomCount == 0 && (!this.sendingUOMMainJar) && (!this.sendingUOMLegacyExtJar)) {
			this.lastSentUOM = System.currentTimeMillis();
		}
	}

	/**
	 * Get the boot ID for purposes of the other node. This is set to a random number on
	 * startup, but also whenever we disconnected(true,...) i.e. whenever we dump the
	 * message queues and PacketFormat's.
	 */
	public synchronized long getOutgoingBootID() {
		return this.myBootID;
	}

	private long lastIncomingRekey;

	static final long THROTTLE_REKEY = 1000;

	public synchronized boolean throttleRekey() {
		long now = System.currentTimeMillis();
		if (now - this.lastIncomingRekey < THROTTLE_REKEY) {
			Logger.error(this, "Two rekeys initiated by other side within " + THROTTLE_REKEY + "ms");
			return true;
		}
		this.lastIncomingRekey = now;
		return false;
	}

	public boolean fullPacketQueued() {
		PacketFormat pf;
		synchronized (this) {
			pf = this.packetFormat;
			if (pf == null) {
				return false;
			}
		}
		return pf.fullPacketQueued(this.getMaxPacketSize());
	}

	public long timeSendAcks() {
		PacketFormat pf;
		synchronized (this) {
			pf = this.packetFormat;
			if (pf == null) {
				return Long.MAX_VALUE;
			}
		}
		return pf.timeSendAcks();
	}

	/**
	 * Calculate the maximum number of outgoing transfers to this peer that we will accept
	 * in requests and inserts.
	 */
	public int calculateMaxTransfersOut(int timeout, double nonOverheadFraction) {
		// First get usable bandwidth.
		double bandwidth = (this.getThrottle().getBandwidth() + 1.0);
		if (this.shouldThrottle()) {
			bandwidth = Math.min(bandwidth, ((double) this.node.getOutputBandwidthLimit()) / 2);
		}
		bandwidth *= nonOverheadFraction;
		// Transfers are divided into packets. Packets are 1KB. There are 1-2
		// of these for SSKs and 32 of them for CHKs, but that's irrelevant here.
		// We are only concerned here with the time that a transfer will have to
		// wait after sending a packet for it to have an opportunity to send
		// another one. Or equivalently the delay between starting and sending
		// the first packet.
		double packetsPerSecond = bandwidth / 1024.0;
		return (int) Math.max(1, Math.min(packetsPerSecond * timeout, Integer.MAX_VALUE));
	}

	public synchronized boolean hasFullNoderef() {
		return this.fullFieldSet != null;
	}

	public synchronized SimpleFieldSet getFullNoderef() {
		return this.fullFieldSet;
	}

	private int consecutiveGuaranteedRejectsRT = 0;

	private int consecutiveGuaranteedRejectsBulk = 0;

	private static final int CONSECUTIVE_REJECTS_MANDATORY_BACKOFF = 5;

	/**
	 * After 5 consecutive GUARANTEED soft rejections, we enter mandatory backoff. The
	 * reason why we don't immediately enter mandatory backoff is as follows: PROBLEM:
	 * Requests could have completed between the time when the request was rejected and
	 * now. SOLUTION A: Tracking all possible requests which completed since the request
	 * was sent. CON: This would be rather complex, and I'm not sure how well it would
	 * work when there are many requests in flight; would it even be possible without
	 * stopping sending requests after some arbitrary threshold? We might need a time
	 * element, and would probably need parameters... SOLUTION B: Enforcing a hard peer
	 * limit on both sides, as opposed to accepting a request if the *current* usage,
	 * without the new request, is over the limit. CON: This would break fairness between
	 * request types.
	 *
	 * Of course, the problem with just using a counter is it may need to be changed
	 * frequently ... FIXME create a better solution!
	 *
	 * Fortunately, this is pretty rare. It happens when e.g. we send an SSK, then we send
	 * a CHK, the messages are reordered and the CHK is accepted, and then the SSK is
	 * rejected. Both were GUARANTEED because if they are accepted in order, thanks to the
	 * mechanism referred to in solution B, they will both be accepted.
	 */
	public void rejectedGuaranteed(boolean realTimeFlag) {
		synchronized (this) {
			if (realTimeFlag) {
				this.consecutiveGuaranteedRejectsRT++;
				if (this.consecutiveGuaranteedRejectsRT != CONSECUTIVE_REJECTS_MANDATORY_BACKOFF) {
					return;
				}
				this.consecutiveGuaranteedRejectsRT = 0;
			}
			else {
				this.consecutiveGuaranteedRejectsBulk++;
				if (this.consecutiveGuaranteedRejectsBulk != CONSECUTIVE_REJECTS_MANDATORY_BACKOFF) {
					return;
				}
				this.consecutiveGuaranteedRejectsBulk = 0;
			}
		}
		this.enterMandatoryBackoff("Mandatory:RejectedGUARANTEED", realTimeFlag);
	}

	/**
	 * Accepting a request, even if it was not GUARANTEED, resets the counters for
	 * consecutive guaranteed rejections. @see rejectedGuaranteed(boolean realTimeFlag).
	 */
	public void acceptedAny(boolean realTimeFlag) {
		synchronized (this) {
			if (realTimeFlag) {
				this.consecutiveGuaranteedRejectsRT = 0;
			}
			else {
				this.consecutiveGuaranteedRejectsBulk = 0;
			}
		}
	}

	/**
	 * @return The largest throttle window size of any of our throttles. This is just for
	 * guesstimating how many blocks we can have in flight.
	 */
	@Override
	public int getThrottleWindowSize() {
		PacketThrottle throttle = this.getThrottle();
		if (throttle != null) {
			return (int) (Math.min(throttle.getWindowSize(), Integer.MAX_VALUE));
		}
		else {
			return Integer.MAX_VALUE;
		}
	}

	private boolean verifyReferenceSignature(SimpleFieldSet fs) throws ReferenceSignatureVerificationException {
		// Assume we failed at validating
		boolean failed;
		String signatureP256 = fs.get("sigP256");
		try {
			// If we have:
			// - the new P256 signature AND the P256 pubkey
			// OR
			// - the old DSA signature the pubkey and the groups
			// THEN
			// verify the signatures
			fs.removeValue("sig");
			fs.removeValue("sigP256");
			byte[] toVerifyECDSA = fs.toOrderedString().getBytes(StandardCharsets.UTF_8);

			boolean isECDSAsigPresent = (signatureP256 != null && this.peerECDSAPubKey != null);
			boolean verifyECDSA = false; // assume it failed.

			// Is there a new ECDSA sig?
			if (isECDSAsigPresent) {
				fs.putSingle("sigP256", signatureP256);
				verifyECDSA = ECDSA.verify(Curves.P256, this.peerECDSAPubKey, Base64.decode(signatureP256),
						toVerifyECDSA);
			}

			// If there is no signature, FAIL
			// If there is an ECDSA signature, and it doesn't verify, FAIL
			boolean hasNoSignature = (!isECDSAsigPresent);
			boolean isECDSAsigInvalid = (isECDSAsigPresent && !verifyECDSA);
			failed = hasNoSignature || isECDSAsigInvalid;
			if (failed) {
				String errCause = "";
				if (hasNoSignature) {
					errCause += " (No signature)";
				}
				if (isECDSAsigInvalid) {
					errCause += " (ECDSA signature is invalid)";
				}
				errCause += " (VERIFICATION FAILED)";
				Logger.error(this, "The integrity of the reference has been compromised!" + errCause + " fs was\n"
						+ fs.toOrderedString());
				this.isSignatureVerificationSuccessfull = false;
				throw new ReferenceSignatureVerificationException(
						"The integrity of the reference has been compromised!" + errCause);
			}
			else {
				this.isSignatureVerificationSuccessfull = true;
				if (!this.dontKeepFullFieldSet()) {
					this.fullFieldSet = fs;
				}
			}
		}
		catch (IllegalBase64Exception ex) {
			Logger.error(this, "Invalid reference: " + ex, ex);
			throw new ReferenceSignatureVerificationException(
					"The node reference you added is invalid: It does not have a valid ECDSA signature.");
		}
		return true;
	}

	protected final byte[] getPubKeyHash() {
		return this.peerECDSAPubKeyHash;
	}

	private class SyncMessageCallback implements AsyncMessageCallback {

		private boolean done = false;

		private boolean disconnected = false;

		private boolean sent = false;

		synchronized void waitForSend(long maxWaitInterval) throws NotConnectedException {
			long now = System.currentTimeMillis();
			long end = now + maxWaitInterval;
			while ((now = System.currentTimeMillis()) < end) {
				if (this.done) {
					if (this.disconnected) {
						throw new NotConnectedException();
					}
					return;
				}
				int waitTime = (int) (Math.min(end - now, Integer.MAX_VALUE));
				try {
					this.wait(waitTime);
				}
				catch (InterruptedException ignored) {
					// Ignore
				}
			}
		}

		@Override
		public void acknowledged() {
			synchronized (this) {
				if (!this.done) {
					if (!this.sent) {
						// Can happen due to lag.
						Logger.normal(this,
								"Acknowledged but not sent?! on " + this + " for " + PeerNode.this + " - lag ???");
					}
				}
				else {
					return;
				}
				this.done = true;
				this.notifyAll();
			}
		}

		@Override
		public void disconnected() {
			synchronized (this) {
				this.done = true;
				this.disconnected = true;
				this.notifyAll();
			}
		}

		@Override
		public void fatalError() {
			synchronized (this) {
				this.done = true;
				this.notifyAll();
			}
		}

		@Override
		public void sent() {
			// It might have been lost, we wait until it is acked.
			synchronized (this) {
				this.sent = true;
			}
		}

	}

	class LoadSender {

		LoadSender(boolean realTimeFlag) {
			this.realTimeFlag = realTimeFlag;
		}

		void onDisconnect() {
			this.lastSentAllocationInput = 0;
			this.lastSentAllocationOutput = 0;
			this.timeLastSentAllocationNotice = -1;
			this.lastFullStats = null;
		}

		private int lastSentAllocationInput;

		private int lastSentAllocationOutput;

		private int lastSentMaxOutputTransfers = Integer.MAX_VALUE;

		private long timeLastSentAllocationNotice;

		private NodeStats.PeerLoadStats lastFullStats;

		private final boolean realTimeFlag;

		private boolean sendASAP;

		void onSetPeerAllocation(boolean input, int thisAllocation, int transfersPerInsert) {

			boolean mustSend = false;
			// FIXME review constants, how often are allocations actually sent?
			long now = System.currentTimeMillis();
			synchronized (this) {
				int last = input ? this.lastSentAllocationInput : this.lastSentAllocationOutput;
				if (now - this.timeLastSentAllocationNotice > 5000) {
					if (logMINOR) {
						Logger.minor(this,
								"Last sent allocation " + TimeUtil.formatTime(now - this.timeLastSentAllocationNotice));
					}
					mustSend = true;
				}
				else {
					if (thisAllocation > last * 1.05) {
						if (logMINOR) {
							Logger.minor(this, "Last allocation was " + last + " this is " + thisAllocation);
						}
						mustSend = true;
					}
					else if (thisAllocation < last * 0.9) {
						if (logMINOR) {
							Logger.minor(this, "Last allocation was " + last + " this is " + thisAllocation);
						}
						mustSend = true;
					}
				}
				if (!mustSend) {
					return;
				}
				this.sendASAP = true;
			}
		}

		void onSetMaxOutputTransfers(int maxOutputTransfers) {
			synchronized (this) {
				if (maxOutputTransfers == this.lastSentMaxOutputTransfers) {
					return;
				}
				if (this.lastSentMaxOutputTransfers == Integer.MAX_VALUE || this.lastSentMaxOutputTransfers == 0) {
					this.sendASAP = true;
				}
				else if (maxOutputTransfers > this.lastSentMaxOutputTransfers * 1.05
						|| maxOutputTransfers < this.lastSentMaxOutputTransfers * 0.9) {
					this.sendASAP = true;
				}
			}
		}

		void onSetMaxOutputTransfersPeerLimit(int maxOutputTransfersPeerLimit) {
			synchronized (this) {
				int lastSentMaxOutputTransfersPeerLimit = Integer.MAX_VALUE;
				if (maxOutputTransfersPeerLimit == lastSentMaxOutputTransfersPeerLimit) {
					return;
				}
				this.sendASAP = true;
			}
		}

		Message makeLoadStats(long now, int transfersPerInsert, boolean noRemember) {
			NodeStats.PeerLoadStats stats = PeerNode.this.node.nodeStats.createPeerLoadStats(PeerNode.this,
					transfersPerInsert, this.realTimeFlag);
			synchronized (this) {
				this.lastSentAllocationInput = (int) stats.inputBandwidthPeerLimit;
				this.lastSentAllocationOutput = (int) stats.outputBandwidthPeerLimit;
				this.lastSentMaxOutputTransfers = stats.maxTransfersOut;
				if (!noRemember) {
					if (this.lastFullStats != null && this.lastFullStats.equals(stats)) {
						return null;
					}
					this.lastFullStats = stats;
				}
				this.timeLastSentAllocationNotice = now;
				if (logMINOR) {
					Logger.minor(this, "Sending allocation notice to " + this + " allocation is "
							+ this.lastSentAllocationInput + " input " + this.lastSentAllocationOutput + " output.");
				}
			}
			return DMT.createFNPPeerLoadStatus(stats);
		}

		synchronized boolean grabSendASAP() {
			boolean send = this.sendASAP;
			this.sendASAP = false;
			return send;
		}

		synchronized void setSendASAP() {
			this.sendASAP = true;
		}

	}

	public static class IncomingLoadSummaryStats {

		public IncomingLoadSummaryStats(int totalRequests, double outputBandwidthPeerLimit,
				double inputBandwidthPeerLimit, double outputBandwidthTotalLimit, double inputBandwidthTotalLimit,
				double usedOutput, double usedInput, double othersUsedOutput, double othersUsedInput) {
			this.runningRequestsTotal = totalRequests;
			this.peerCapacityOutputBytes = (int) outputBandwidthPeerLimit;
			this.peerCapacityInputBytes = (int) inputBandwidthPeerLimit;
			this.totalCapacityOutputBytes = (int) outputBandwidthTotalLimit;
			this.totalCapacityInputBytes = (int) inputBandwidthTotalLimit;
			this.usedCapacityOutputBytes = (int) usedOutput;
			this.usedCapacityInputBytes = (int) usedInput;
			this.othersUsedCapacityOutputBytes = (int) othersUsedOutput;
			this.othersUsedCapacityInputBytes = (int) othersUsedInput;
		}

		public final int runningRequestsTotal;

		public final int peerCapacityOutputBytes;

		public final int peerCapacityInputBytes;

		public final int totalCapacityOutputBytes;

		public final int totalCapacityInputBytes;

		public final int usedCapacityOutputBytes;

		public final int usedCapacityInputBytes;

		public final int othersUsedCapacityOutputBytes;

		public final int othersUsedCapacityInputBytes;

	}

	enum RequestLikelyAcceptedState {

		GUARANTEED, // guaranteed to be accepted, under the per-peer guaranteed limit
		LIKELY, // likely to be accepted even though above the per-peer guaranteed limit,
		// as overall is below the overall lower limit
		UNLIKELY, // not likely to be accepted; peer is over the per-peer guaranteed
		// limit, and global is over the overall lower limit
		UNKNOWN // no data but accepting anyway

	}

	static class SlotWaiterList {

		private final LinkedHashMap<PeerNode, TreeMap<Long, SlotWaiter>> lru = new LinkedHashMap<>();

		synchronized void put(SlotWaiter waiter) {
			PeerNode source = waiter.source;
			TreeMap<Long, SlotWaiter> map = this.lru.computeIfAbsent(source, (k) -> new TreeMap<>());
			map.put(waiter.counter, waiter);
		}

		synchronized void remove(SlotWaiter waiter) {
			PeerNode source = waiter.source;
			TreeMap<Long, SlotWaiter> map = this.lru.get(source);
			if (map == null) {
				if (logMINOR) {
					Logger.minor(this, "SlotWaiter " + waiter + " was not queued");
				}
				return;
			}
			map.remove(waiter.counter);
			if (map.isEmpty()) {
				this.lru.remove(source);
			}
		}

		synchronized boolean isEmpty() {
			return this.lru.isEmpty();
		}

		synchronized SlotWaiter removeFirst() {
			if (this.lru.isEmpty()) {
				return null;
			}
			// FIXME better to use LRUMap?
			// Would need to update it to use Iterator and other modern APIs in values(),
			// and creating two objects here isn't THAT expensive on modern VMs...
			PeerNode source = this.lru.keySet().iterator().next();
			TreeMap<Long, SlotWaiter> map = this.lru.get(source);
			Long key = map.firstKey();
			SlotWaiter ret = map.get(key);
			map.remove(key);
			this.lru.remove(source);
			if (!map.isEmpty()) {
				this.lru.put(source, map);
			}
			return ret;
		}

		synchronized ArrayList<SlotWaiter> values() {
			ArrayList<SlotWaiter> list = new ArrayList<>();
			for (TreeMap<Long, SlotWaiter> map : this.lru.values()) {
				list.addAll(map.values());
			}
			return list;
		}

		public String toString() {
			return super.toString() + ":peers=" + this.lru.size();
		}

	}

	static class SlotWaiterFailedException extends Exception {

		final PeerNode pn;

		final boolean fatal;

		SlotWaiterFailedException(PeerNode p, boolean f) {
			this.pn = p;
			this.fatal = f;
			// FIXME OPTIMISATION: arrange for empty stack trace
		}

	}

	public static class SlotWaiter {

		final PeerNode source;

		private final HashSet<PeerNode> waitingFor;

		private PeerNode acceptedBy;

		private RequestLikelyAcceptedState acceptedState;

		final UIDTag tag;

		final boolean offeredKey;

		final NodeStats.RequestType requestType;

		private boolean failed;

		private SlotWaiterFailedException fe;

		final boolean realTime;

		// FIXME the counter is a quick hack to ensure that the original ordering is
		// preserved
		// even after failures (transfer failures, backoffs).
		// The real solution, which would likely result in simpler code as well as saving
		// a thread, is to make the wait loop in RequestSender asynchronous i.e. to not
		// block at all there, but process the waiters in order in a callback when we get
		// such a failure.

		final long counter;

		private static long waiterCounter;

		SlotWaiter(UIDTag tag, NodeStats.RequestType type, boolean offeredKey, boolean realTime, PeerNode source) {
			this.tag = tag;
			this.requestType = type;
			this.offeredKey = offeredKey;
			this.waitingFor = new HashSet<>();
			this.realTime = realTime;
			this.source = source;
			synchronized (SlotWaiter.class) {
				this.counter = waiterCounter++;
			}
		}

		/**
		 * Add another node to wait for.
		 * @return True unless queueing the slot was impossible due to a problem with the
		 * PeerNode. So we return true when there is a successful queueing, and we also
		 * return true when there is a race condition and the waiter has already
		 * completed.
		 */
		public boolean addWaitingFor(PeerNode peer) {
			boolean cantQueue = (!peer.isRoutable())
					|| peer.isInMandatoryBackoff(System.currentTimeMillis(), this.realTime);
			synchronized (this) {
				if (this.acceptedBy != null) {
					if (logMINOR) {
						Logger.minor(this, "Not adding " + peer.shortToString + " because already matched on " + this);
					}
					return true;
				}
				if (this.failed) {
					if (logMINOR) {
						Logger.minor(this, "Not adding " + peer.shortToString + " because already failed on " + this);
					}
					return true;
				}
				if (this.waitingFor.contains(peer)) {
					return true;
				}
				// Race condition if contains() && cantQueue (i.e. it was accepted then it
				// became backed off), but probably not serious.
				if (cantQueue) {
					return false;
				}
				this.waitingFor.add(peer);
				this.tag.setWaitingForSlot();
			}
			if (!peer.outputLoadTracker(this.realTime).queueSlotWaiter(this)) {
				synchronized (this) {
					this.waitingFor.remove(peer);
					if (this.acceptedBy != null || this.failed) {
						return true;
					}
				}
				return false;
			}
			else {
				return true;
			}
		}

		/**
		 * First part of wake-up callback. If this returns null, we have already woken up,
		 * but if it returns a PeerNode[], the SlotWaiter has been woken up, and the
		 * caller **must** call unregister() with the returned data.
		 * @param peer The peer waking up the SlotWaiter.
		 * @param state The accept state we are waking up with.
		 * @return Null if already woken up or not waiting for this peer, otherwise an
		 * array of all the PeerNode's the slot was registered on, which *must* be passed
		 * to unregister() as soon as the caller has unlocked everything that reasonably
		 * can be unlocked.
		 */
		synchronized PeerNode[] innerOnWaited(PeerNode peer, RequestLikelyAcceptedState state) {
			if (logMINOR) {
				Logger.minor(this, "Waking slot waiter " + this + " on " + peer);
			}
			if (this.acceptedBy != null) {
				if (logMINOR) {
					Logger.minor(this, "Already accepted on " + this);
				}
				if (this.acceptedBy != peer) {
					if (this.offeredKey) {
						this.tag.removeFetchingOfferedKeyFrom(peer);
					}
					else {
						this.tag.removeRoutingTo(peer);
					}
				}
				return null;
			}
			if (!this.waitingFor.contains(peer)) {
				if (logMINOR) {
					Logger.minor(this, "Not waiting for peer " + peer + " on " + this);
				}
				if (this.acceptedBy != peer) {
					if (this.offeredKey) {
						this.tag.removeFetchingOfferedKeyFrom(peer);
					}
					else {
						this.tag.removeRoutingTo(peer);
					}
				}
				return null;
			}
			this.acceptedBy = peer;
			this.acceptedState = state;
			if (!this.tag.addRoutedTo(peer, this.offeredKey)) {
				Logger.normal(this,
						"onWaited for " + this + " added on " + this.tag + " but already added - race condition?");
			}
			this.notifyAll();
			// Because we are no longer in the slot queue we must remove it.
			// If we want to wait for it again it must be re-queued.
			PeerNode[] toUnreg = this.waitingFor.toArray(new PeerNode[0]);
			this.waitingFor.clear();
			this.tag.clearWaitingForSlot();
			return toUnreg;
		}

		/**
		 * Caller should not hold locks while calling this.
		 * @param exclude Only set this if you have already removed the slot waiter.
		 */
		void unregister(PeerNode exclude, PeerNode[] all) {
			if (all == null) {
				return;
			}
			for (PeerNode p : all) {
				if (p != exclude) {
					p.outputLoadTracker(this.realTime).unqueueSlotWaiter(this);
				}
			}
		}

		/**
		 * Some sort of failure.
		 * @param reallyFailed If true, we can't route to the node, or should reconsider
		 * routing to it, due to e.g. backoff or disconnection. If false, this is
		 * something like the node is now regarded as low capacity so we should consider
		 * other nodes, but still allow this one.
		 */
		void onFailed(PeerNode peer, boolean reallyFailed) {
			if (logMINOR) {
				Logger.minor(this, "onFailed() on " + this + " reallyFailed=" + reallyFailed);
			}
			synchronized (this) {
				if (this.acceptedBy != null) {
					if (logMINOR) {
						Logger.minor(this, "Already matched on " + this);
					}
					return;
				}
				// Always wake up.
				// Whether it's a backoff or a disconnect, we probably want to add another
				// peer.
				// FIXME get rid of parameter.
				this.failed = true;
				this.fe = new SlotWaiterFailedException(peer, reallyFailed);
				this.tag.clearWaitingForSlot();
				this.notifyAll();
			}
		}

		public HashSet<PeerNode> waitingForList() {
			synchronized (this) {
				return new HashSet<>(this.waitingFor);
			}
		}

		/**
		 * Wait for any of the PeerNode's we have queued on to accept (locally i.e. to
		 * allocate a local slot to) this request.
		 * @param maxWait The time to wait for. Can be 0, but if it is 0, this is a
		 * "peek", i.e. if we return null, the queued slots remain live. Whereas if
		 * maxWait is not 0, we will unregister when we timeout.
		 * @param timeOutIsFatal If true, if we timeout, count it for each node involved
		 * as a fatal timeout.
		 * @return A matched node, or null.
		 * @throws SlotWaiterFailedException If a peer actually failed.
		 */
		public PeerNode waitForAny(long maxWait, boolean timeOutIsFatal) throws SlotWaiterFailedException {
			// If waitingFor is non-empty after this function returns, we can
			// be accepted when we shouldn't be accepted. So always ensure that
			// the state is clean when returning, by clearing waitingFor and
			// calling unregister().
			PeerNode[] all;
			PeerNode ret = null;
			boolean grabbed = false;
			SlotWaiterFailedException f = null;
			synchronized (this) {
				if (this.shouldGrab()) {
					if (logMINOR) {
						Logger.minor(this, "Already matched on " + this);
					}
					ret = this.grab();
					grabbed = true;
				}
				if (this.fe != null) {
					f = this.fe;
					this.fe = null;
					grabbed = true;
				}
				all = this.waitingFor.toArray(new PeerNode[0]);
				if (ret != null) {
					this.waitingFor.clear();
				}
				if (grabbed || all.length == 0) {
					this.tag.clearWaitingForSlot();
				}
			}
			if (grabbed) {
				this.unregister(ret, all);
				if (f != null && ret == null) {
					throw f;
				}
				return ret;
			}
			// grab() above will have set failed = false if necessary.
			// acceptedBy = null because ret = null, and it won't change after that
			// because waitingFor is empty.
			if (all.length == 0) {
				if (logMINOR) {
					Logger.minor(this, "None to wait for on " + this);
				}
				return null;
			}
			// Double-check before blocking, prevent race condition.
			long now = System.currentTimeMillis();
			boolean anyValid = false;
			for (PeerNode p : all) {
				if ((!p.isRoutable()) || p.isInMandatoryBackoff(now, this.realTime)) {
					if (logMINOR) {
						Logger.minor(this, "Peer is not valid in waitForAny(): " + p);
					}
					continue;
				}
				anyValid = true;
				RequestLikelyAcceptedState accept = p.outputLoadTracker(this.realTime).tryRouteTo(this.tag,
						RequestLikelyAcceptedState.LIKELY, this.offeredKey);
				if (accept != null) {
					if (logMINOR) {
						Logger.minor(this, "tryRouteTo() pre-wait check returned " + accept);
					}
					PeerNode[] unreg;
					PeerNode other = null;
					synchronized (this) {
						if (logMINOR) {
							Logger.minor(this, "tryRouteTo() succeeded to " + p + " on " + this + " with " + accept
									+ " - checking whether we have already accepted.");
						}
						unreg = this.innerOnWaited(p, accept);
						if (unreg == null) {
							// Recover from race condition.
							if (this.shouldGrab()) {
								other = this.grab();
							}
						}
						if (other == null) {
							if (logMINOR) {
								Logger.minor(this, "Trying the original tryRouteTo() on " + this);
							}
							// Having set the acceptedBy etc, clear it now.
							this.acceptedBy = null;
							this.failed = false;
							this.fe = null;
						}
						this.tag.clearWaitingForSlot();
					}
					this.unregister(null, unreg);
					if (other != null) {
						Logger.normal(this, "Race condition: tryRouteTo() succeeded on " + p.shortToString()
								+ " but already matched on " + other.shortToString() + " on " + this);
						this.tag.removeRoutingTo(p);
						return other;
					}
					p.outputLoadTracker(this.realTime).reportAllocated(this.isLocal());
					// p != null so in this one instance we're going to ignore fe.
					return p;
				}
			}
			if (maxWait == 0) {
				return null;
			}
			// Don't need to clear waiting here because we are still waiting.
			if (!anyValid) {
				synchronized (this) {
					if (this.fe != null) {
						f = this.fe;
						this.fe = null;
					}
					if (this.shouldGrab()) {
						ret = this.grab();
					}
					all = this.waitingFor.toArray(new PeerNode[0]);
					this.waitingFor.clear();
					this.failed = false;
					this.acceptedBy = null;
				}
				if (logMINOR) {
					Logger.minor(this, "None valid to wait for on " + this);
				}
				this.unregister(ret, all);
				if (f != null && ret == null) {
					throw f;
				}
				this.tag.clearWaitingForSlot();
				return ret;
			}
			synchronized (this) {
				if (logMINOR) {
					Logger.minor(this, "Waiting for any node to wake up " + this + " : "
							+ Arrays.toString(this.waitingFor.toArray()) + " (for up to " + maxWait + "ms)");
				}
				long waitStart = System.currentTimeMillis();
				long deadline = waitStart + maxWait;
				boolean timedOut = false;
				while (this.acceptedBy == null && (!this.waitingFor.isEmpty()) && !this.failed) {
					try {
						if (maxWait == Long.MAX_VALUE) {
							this.wait();
						}
						else {
							int wait = (int) Math.min(Integer.MAX_VALUE, deadline - System.currentTimeMillis());
							if (wait > 0) {
								this.wait(wait);
							}
							if (logMINOR) {
								Logger.minor(this, "Maximum wait time exceeded on " + this);
							}
							if (this.shouldGrab()) {
								// Race condition resulting in stalling
								// All we have to do is break.
							}
							else {
								// Bigger problem.
								// No external entity called us, so waitingFor have not
								// been unregistered.
								timedOut = true;
								this.waitingFor.clear();
								// Now no callers will succeed.
								// But we still need to unregister the waitingFor's or
								// they will stick around until they are matched, and
								// then, if we are unlucky, will lock a slot on the
								// RequestTag forever and thus cause a catastrophic stall
								// of the whole peer.
							}
							break;
						}
					}
					catch (InterruptedException ignored) {
						// Ignore
					}
				}
				if (!timedOut) {
					long waitEnd = System.currentTimeMillis();
					if (waitEnd - waitStart > (this.realTime ? 6000 : 60000)) {
						Logger.warning(this, "Waited " + (waitEnd - waitStart) + "ms for " + this);
					}
					else if (waitEnd - waitStart > (this.realTime ? 1000 : 10000)) {
						Logger.normal(this, "Waited " + (waitEnd - waitStart) + "ms for " + this);
					}
					else {
						if (logMINOR) {
							Logger.minor(this, "Waited " + (waitEnd - waitStart) + "ms for " + this);
						}
					}
				}
				if (logMINOR) {
					Logger.minor(this, "Returning after waiting: accepted by " + this.acceptedBy + " waiting for "
							+ this.waitingFor.size() + " failed " + this.failed + " on " + this);
				}
				ret = this.acceptedBy;
				this.acceptedBy = null; // Allow for it to wait again if necessary
				all = this.waitingFor.toArray(new PeerNode[0]);
				this.waitingFor.clear();
				this.failed = false;
				this.fe = null;
				this.tag.clearWaitingForSlot();
			}
			if (timeOutIsFatal) {
				for (PeerNode pn : all) {
					pn.outputLoadTracker(this.realTime).reportFatalTimeoutInWait(this.isLocal());
				}
			}
			this.unregister(ret, all);
			return ret;
		}

		final boolean isLocal() {
			return this.source == null;
		}

		private boolean shouldGrab() {
			return this.acceptedBy != null || this.waitingFor.isEmpty() || this.failed;
		}

		private synchronized PeerNode grab() {
			if (logMINOR) {
				Logger.minor(this, "Returning in first check: accepted by " + this.acceptedBy + " waiting for "
						+ this.waitingFor.size() + " failed " + this.failed + " accepted state " + this.acceptedState);
			}
			this.failed = false;
			PeerNode got = this.acceptedBy;
			this.acceptedBy = null; // Allow for it to wait again if necessary
			return got;
		}

		public synchronized RequestLikelyAcceptedState getAcceptedState() {
			return this.acceptedState;
		}

		@Override
		public String toString() {
			return super.toString() + ":" + this.counter + ":" + this.requestType + ":" + this.realTime;
		}

		public synchronized int waitingForCount() {
			return this.waitingFor.size();
		}

	}

	/**
	 * Uses the information we receive on the load on the target node to determine whether
	 * we can route to it and when we can route to it.
	 */
	class OutputLoadTracker {

		final boolean realTime;

		private NodeStats.PeerLoadStats lastIncomingLoadStats;

		private boolean dontSendUnlessGuaranteed;

		// These only count remote timeouts.
		// Strictly local and remote should be the same in new load management, but
		// local often produces more load than can be handled by our peers.
		// Fair sharing in SlotWaiterList ensures that this doesn't cause excessive
		// timeouts for others, but we want the stats that determine their RecentlyFailed
		// times to be based on remote requests only. Also, local requests by definition
		// do not cause downstream problems.
		private long totalFatalTimeouts;

		private long totalAllocated;

		void reportLoadStatus(NodeStats.PeerLoadStats stat) {
			if (logMINOR) {
				Logger.minor(this, "Got load status : " + stat);
			}
			synchronized (PeerNode.this.routedToLock) {
				this.lastIncomingLoadStats = stat;
			}
			this.maybeNotifySlotWaiter();
		}

		synchronized /* lock only used for counter */ void reportFatalTimeoutInWait(boolean local) {
			if (!local) {
				this.totalFatalTimeouts++;
			}
			PeerNode.this.node.nodeStats.reportFatalTimeoutInWait(local);
		}

		synchronized /* lock only used for counter */ void reportAllocated(boolean local) {
			if (!local) {
				this.totalAllocated++;
			}
			PeerNode.this.node.nodeStats.reportAllocatedSlot(local);
		}

		synchronized double proportionTimingOutFatallyInWait() {
			if (this.totalFatalTimeouts == 1 && this.totalAllocated == 0) {
				return 0.5; // Limit impact if the first one is rejected.
			}
			return (double) this.totalFatalTimeouts / ((double) (this.totalFatalTimeouts + this.totalAllocated));
		}

		NodeStats.PeerLoadStats getLastIncomingLoadStats() {
			synchronized (PeerNode.this.routedToLock) {
				return this.lastIncomingLoadStats;
			}
		}

		OutputLoadTracker(boolean realTime) {
			this.realTime = realTime;
		}

		IncomingLoadSummaryStats getIncomingLoadStats() {
			NodeStats.PeerLoadStats loadStats;
			synchronized (PeerNode.this.routedToLock) {
				if (this.lastIncomingLoadStats == null) {
					return null;
				}
				loadStats = this.lastIncomingLoadStats;
			}
			NodeStats.RunningRequestsSnapshot runningRequests = PeerNode.this.node.nodeStats
					.getRunningRequestsTo(PeerNode.this, loadStats.averageTransfersOutPerInsert, this.realTime);
			NodeStats.RunningRequestsSnapshot otherRunningRequests = loadStats.getOtherRunningRequests();
			boolean ignoreLocalVsRemoteBandwidthLiability = PeerNode.this.node.nodeStats
					.ignoreLocalVsRemoteBandwidthLiability();
			return new IncomingLoadSummaryStats(runningRequests.totalRequests(), loadStats.outputBandwidthPeerLimit,
					loadStats.inputBandwidthPeerLimit, loadStats.outputBandwidthUpperLimit,
					loadStats.inputBandwidthUpperLimit,
					runningRequests.calculate(ignoreLocalVsRemoteBandwidthLiability, false),
					runningRequests.calculate(ignoreLocalVsRemoteBandwidthLiability, true),
					otherRunningRequests.calculate(ignoreLocalVsRemoteBandwidthLiability, false),
					otherRunningRequests.calculate(ignoreLocalVsRemoteBandwidthLiability, true));
		}

		/**
		 * Can we route the tag to this peer? If so (including if we are accepting because
		 * we don't have any load stats), and we haven't already, addRoutedTo() and return
		 * the accepted state. Otherwise return null.
		 */
		RequestLikelyAcceptedState tryRouteTo(UIDTag tag, RequestLikelyAcceptedState worstAcceptable,
				boolean offeredKey) {
			NodeStats.PeerLoadStats loadStats;
			boolean ignoreLocalVsRemote = PeerNode.this.node.nodeStats.ignoreLocalVsRemoteBandwidthLiability();
			if (!PeerNode.this.isRoutable()) {
				return null;
			}
			if (PeerNode.this.isInMandatoryBackoff(System.currentTimeMillis(), this.realTime)) {
				return null;
			}
			synchronized (PeerNode.this.routedToLock) {
				loadStats = this.lastIncomingLoadStats;
				if (loadStats == null) {
					Logger.error(this, "Accepting because no load stats from " + PeerNode.this.shortToString() + " ("
							+ PeerNode.this.getVersionNumber() + ")");
					if (tag.addRoutedTo(PeerNode.this, offeredKey)) {
						// FIXME maybe wait a bit, check the other side's version first???
						return RequestLikelyAcceptedState.UNKNOWN;
					}
					else {
						return null;
					}
				}
				if (this.dontSendUnlessGuaranteed) {
					worstAcceptable = RequestLikelyAcceptedState.GUARANTEED;
				}
				// Requests already running to this node
				NodeStats.RunningRequestsSnapshot runningRequests = PeerNode.this.node.nodeStats
						.getRunningRequestsTo(PeerNode.this, loadStats.averageTransfersOutPerInsert, this.realTime);
				runningRequests.log(PeerNode.this);
				// Requests running from its other peers
				NodeStats.RunningRequestsSnapshot otherRunningRequests = loadStats.getOtherRunningRequests();
				RequestLikelyAcceptedState acceptState = this.getRequestLikelyAcceptedState(runningRequests,
						otherRunningRequests, ignoreLocalVsRemote, loadStats);
				if (logMINOR) {
					Logger.minor(this,
							"Predicted acceptance state for request: " + acceptState + " must beat " + worstAcceptable);
				}
				if (acceptState.ordinal() > worstAcceptable.ordinal()) {
					return null;
				}
				if (tag.addRoutedTo(PeerNode.this, offeredKey)) {
					return acceptState;
				}
				else {
					if (logMINOR) {
						Logger.minor(this, "Already routed to peer");
					}
					return null;
				}
			}
		}

		// FIXME on capacity changing so that we should add another node???
		// FIXME on backoff so that we should add another node???

		private final EnumMap<NodeStats.RequestType, SlotWaiterList> slotWaiters = new EnumMap<>(
				NodeStats.RequestType.class);

		boolean queueSlotWaiter(SlotWaiter waiter) {
			if (!PeerNode.this.isRoutable()) {
				if (logMINOR) {
					Logger.minor(this, "Not routable, so not queueing");
				}
				return false;
			}
			if (PeerNode.this.isInMandatoryBackoff(System.currentTimeMillis(), this.realTime)) {
				if (logMINOR) {
					Logger.minor(this, "In mandatory backoff, so not queueing");
				}
				return false;
			}
			boolean noLoadStats;
			PeerNode[] all = null;
			boolean queued = false;
			synchronized (PeerNode.this.routedToLock) {
				noLoadStats = (this.lastIncomingLoadStats == null);
				if (!noLoadStats) {
					SlotWaiterList list = this.makeSlotWaiters(waiter.requestType);
					list.put(waiter);
					if (logMINOR) {
						Logger.minor(this, "Queued slot " + waiter + " waiter for " + waiter.requestType + " on " + list
								+ " on " + this + " for " + PeerNode.this);
					}
					queued = true;
				}
				else {
					if (logMINOR) {
						Logger.minor(this, "Not waiting for " + this + " as no load stats");
					}
					all = waiter.innerOnWaited(PeerNode.this, RequestLikelyAcceptedState.UNKNOWN);
				}
			}
			if (all != null) {
				this.reportAllocated(waiter.isLocal());
				waiter.unregister(null, all);
			}
			else if (queued) {
				if ((!PeerNode.this.isRoutable())
						|| (PeerNode.this.isInMandatoryBackoff(System.currentTimeMillis(), this.realTime))) {
					// Has lost connection etc since start of the method.
					if (logMINOR) {
						Logger.minor(this, "Queued but not routable or in mandatory backoff, failing");
					}
					waiter.onFailed(PeerNode.this, true);
					return false;
				}
			}
			return true;
		}

		private SlotWaiterList makeSlotWaiters(NodeStats.RequestType requestType) {
			SlotWaiterList slots = this.slotWaiters.get(requestType);
			if (slots == null) {
				slots = new SlotWaiterList();
				this.slotWaiters.put(requestType, slots);
			}
			return slots;
		}

		void unqueueSlotWaiter(SlotWaiter waiter) {
			synchronized (PeerNode.this.routedToLock) {
				SlotWaiterList map = this.slotWaiters.get(waiter.requestType);
				if (map == null) {
					return;
				}
				map.remove(waiter);
			}
		}

		private void failSlotWaiters(boolean reallyFailed) {
			for (NodeStats.RequestType type : RequestType_values) {
				SlotWaiterList slots;
				synchronized (PeerNode.this.routedToLock) {
					slots = this.slotWaiters.get(type);
					if (slots == null) {
						continue;
					}
					this.slotWaiters.remove(type);
				}
				for (SlotWaiter w : slots.values()) {
					w.onFailed(PeerNode.this, reallyFailed);
				}
			}
		}

		private int slotWaiterTypeCounter = 0;

		private void maybeNotifySlotWaiter() {
			if (!PeerNode.this.isRoutable()) {
				return;
			}
			boolean ignoreLocalVsRemote = PeerNode.this.node.nodeStats.ignoreLocalVsRemoteBandwidthLiability();
			if (logMINOR) {
				Logger.minor(this, "Maybe waking up slot waiters for " + this + " realtime=" + this.realTime + " for "
						+ PeerNode.this.shortToString());
			}
			while (true) {
				boolean foundNone = true;
				int typeNum;
				NodeStats.PeerLoadStats loadStats;
				synchronized (PeerNode.this.routedToLock) {
					loadStats = this.lastIncomingLoadStats;
					if (this.slotWaiters.isEmpty()) {
						if (logMINOR) {
							Logger.minor(this, "No slot waiters for " + this);
						}
						return;
					}
					typeNum = this.slotWaiterTypeCounter;
				}
				typeNum++;
				if (typeNum == RequestType_values.length) {
					typeNum = 0;
				}
				for (int i = 0; i < RequestType_values.length; i++) {
					SlotWaiterList list;
					NodeStats.RequestType type = RequestType_values[typeNum];
					if (logMINOR) {
						Logger.minor(this, "Checking slot waiter list for " + type);
					}
					SlotWaiter slot;
					RequestLikelyAcceptedState acceptState;
					PeerNode[] peersForSuccessfulSlot;
					synchronized (PeerNode.this.routedToLock) {
						list = this.slotWaiters.get(type);
						if (list == null) {
							if (logMINOR) {
								Logger.minor(this, "No list");
							}
							typeNum++;
							if (typeNum == RequestType_values.length) {
								typeNum = 0;
							}
							continue;
						}
						if (list.isEmpty()) {
							if (logMINOR) {
								Logger.minor(this, "List empty");
							}
							typeNum++;
							if (typeNum == RequestType_values.length) {
								typeNum = 0;
							}
							continue;
						}
						if (logMINOR) {
							Logger.minor(this, "Checking slot waiters for " + type);
						}
						foundNone = false;
						// Requests already running to this node
						NodeStats.RunningRequestsSnapshot runningRequests = PeerNode.this.node.nodeStats
								.getRunningRequestsTo(PeerNode.this, loadStats.averageTransfersOutPerInsert,
										this.realTime);
						runningRequests.log(PeerNode.this);
						// Requests running from its other peers
						NodeStats.RunningRequestsSnapshot otherRunningRequests = loadStats.getOtherRunningRequests();
						acceptState = this.getRequestLikelyAcceptedState(runningRequests, otherRunningRequests,
								ignoreLocalVsRemote, loadStats);
						if (acceptState == RequestLikelyAcceptedState.UNLIKELY) {
							if (logMINOR) {
								Logger.minor(this,
										"Accept state is " + acceptState + " - not waking up - type is " + type);
							}
							return;
						}
						if (this.dontSendUnlessGuaranteed && acceptState != RequestLikelyAcceptedState.GUARANTEED) {
							if (logMINOR) {
								Logger.minor(this, "Not accepting until guaranteed for " + PeerNode.this + " realtime="
										+ this.realTime);
							}
							return;
						}
						if (list.isEmpty()) {
							continue;
						}
						slot = list.removeFirst();
						if (logMINOR) {
							Logger.minor(this,
									"Accept state is " + acceptState + " for " + slot + " - waking up on " + this);
						}
						peersForSuccessfulSlot = slot.innerOnWaited(PeerNode.this, acceptState);
						if (peersForSuccessfulSlot == null) {
							continue;
						}
						this.reportAllocated(slot.isLocal());
						this.slotWaiterTypeCounter = typeNum;
					}
					slot.unregister(PeerNode.this, peersForSuccessfulSlot);
					if (logMINOR) {
						Logger.minor(this, "Accept state is " + acceptState + " for " + slot + " - waking up");
					}
					typeNum++;
					if (typeNum == RequestType_values.length) {
						typeNum = 0;
					}
				}
				if (foundNone) {
					return;
				}
			}
		}

		/**
		 * LOCKING: Call inside routedToLock
		 */
		private RequestLikelyAcceptedState getRequestLikelyAcceptedState(
				NodeStats.RunningRequestsSnapshot runningRequests,
				NodeStats.RunningRequestsSnapshot otherRunningRequests, boolean ignoreLocalVsRemote,
				NodeStats.PeerLoadStats stats) {
			RequestLikelyAcceptedState outputState = this.getRequestLikelyAcceptedStateBandwidth(false, runningRequests,
					otherRunningRequests, ignoreLocalVsRemote, stats);
			RequestLikelyAcceptedState inputState = this.getRequestLikelyAcceptedStateBandwidth(true, runningRequests,
					otherRunningRequests, ignoreLocalVsRemote, stats);
			RequestLikelyAcceptedState transfersState = this.getRequestLikelyAcceptedStateTransfers(runningRequests,
					otherRunningRequests, ignoreLocalVsRemote, stats);
			RequestLikelyAcceptedState ret = inputState;

			if (outputState.ordinal() > ret.ordinal()) {
				ret = outputState;
			}
			if (transfersState.ordinal() > ret.ordinal()) {
				ret = transfersState;
			}
			return ret;
		}

		private RequestLikelyAcceptedState getRequestLikelyAcceptedStateBandwidth(boolean input,
				NodeStats.RunningRequestsSnapshot runningRequests,
				NodeStats.RunningRequestsSnapshot otherRunningRequests, boolean ignoreLocalVsRemote,
				NodeStats.PeerLoadStats stats) {
			double ourUsage = runningRequests.calculate(ignoreLocalVsRemote, input);
			if (logMINOR) {
				Logger.minor(this,
						"Our usage is " + ourUsage + " peer limit is " + stats.peerLimit(input) + " lower limit is "
								+ stats.lowerLimit(input) + " realtime " + this.realTime + " input " + input);
			}
			if (ourUsage < stats.peerLimit(input)) {
				return RequestLikelyAcceptedState.GUARANTEED;
			}
			otherRunningRequests.log(PeerNode.this);
			double theirUsage = otherRunningRequests.calculate(ignoreLocalVsRemote, input);
			if (logMINOR) {
				Logger.minor(this, "Their usage is " + theirUsage);
			}
			if (ourUsage + theirUsage < stats.lowerLimit(input)) {
				return RequestLikelyAcceptedState.LIKELY;
			}
			else {
				return RequestLikelyAcceptedState.UNLIKELY;
			}
		}

		private RequestLikelyAcceptedState getRequestLikelyAcceptedStateTransfers(
				NodeStats.RunningRequestsSnapshot runningRequests,
				NodeStats.RunningRequestsSnapshot otherRunningRequests, boolean ignoreLocalVsRemote,
				NodeStats.PeerLoadStats stats) {

			int ourUsage = runningRequests.totalOutTransfers();
			int maxTransfersOutPeerLimit = Math.min(stats.maxTransfersOutPeerLimit, stats.maxTransfersOut);
			if (logMINOR) {
				Logger.minor(this, "Our usage is " + ourUsage + " peer limit is " + maxTransfersOutPeerLimit
						+ " lower limit is " + stats.maxTransfersOutLowerLimit + " realtime " + this.realTime);
			}
			if (ourUsage < maxTransfersOutPeerLimit) {
				return RequestLikelyAcceptedState.GUARANTEED;
			}
			otherRunningRequests.log(PeerNode.this);
			int theirUsage = otherRunningRequests.totalOutTransfers();
			if (logMINOR) {
				Logger.minor(this, "Their usage is " + theirUsage);
			}
			if (ourUsage + theirUsage < stats.maxTransfersOutLowerLimit) {
				return RequestLikelyAcceptedState.LIKELY;
			}
			else {
				return RequestLikelyAcceptedState.UNLIKELY;
			}
		}

		void setDontSendUnlessGuaranteed() {
			synchronized (PeerNode.this.routedToLock) {
				if (!this.dontSendUnlessGuaranteed) {
					Logger.error(this,
							"Setting don't-send-unless-guaranteed for " + PeerNode.this + " realtime=" + this.realTime);
					this.dontSendUnlessGuaranteed = true;
				}
			}
		}

		void clearDontSendUnlessGuaranteed() {
			synchronized (PeerNode.this.routedToLock) {
				if (this.dontSendUnlessGuaranteed) {
					Logger.error(this, "Clearing don't-send-unless-guaranteed for " + PeerNode.this + " realtime="
							+ this.realTime);
					this.dontSendUnlessGuaranteed = false;
				}
			}
		}

	}

	class MyDecodingMessageGroup implements DecodingMessageGroup {

		private final ArrayList<Message> messages;

		private final ArrayList<Message> messagesWantSomething;

		MyDecodingMessageGroup(int size) {
			this.messages = new ArrayList<>(size);
			this.messagesWantSomething = new ArrayList<>(size);
		}

		@Override
		public void processDecryptedMessage(byte[] data, int offset, int length, int overhead) {
			Message m = PeerNode.this.node.usm.decodeSingleMessage(data, offset, length, PeerNode.this, overhead);
			if (m == null) {
				if (logMINOR) {
					Logger.minor(this, "Message not decoded from " + PeerNode.this + " ("
							+ PeerNode.this.getVersionNumber() + ")");
				}
				return;
			}
			if (DMT.isPeerLoadStatusMessage(m)) {
				PeerNode.this.handleMessage(m);
				return;
			}
			if (DMT.isLoadLimitedRequest(m)) {
				this.messagesWantSomething.add(m);
			}
			else {
				this.messages.add(m);
			}
		}

		@Override
		public void complete() {
			for (Message msg : this.messages) {
				PeerNode.this.handleMessage(msg);
			}
			for (Message msg : this.messagesWantSomething) {
				PeerNode.this.handleMessage(msg);
			}
		}

	}

}
