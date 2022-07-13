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

package freenet.node.updater.uom;

import java.net.MalformedURLException;
import java.util.HashSet;
import java.util.concurrent.TimeUnit;

import freenet.bucket.Bucket;
import freenet.io.comm.AsyncMessageCallback;
import freenet.io.comm.ByteCounter;
import freenet.io.comm.DMT;
import freenet.io.comm.Message;
import freenet.io.comm.NotConnectedException;
import freenet.keys.FreenetURI;
import freenet.node.Node;
import freenet.node.NodeStats;
import freenet.node.PeerNode;
import freenet.node.Version;
import freenet.node.event.DiffNoderefProcessedEvent;
import freenet.node.event.EventBus;
import freenet.node.updater.AbstractUpdateFileFetcher;
import freenet.node.updater.RevocationChecker;
import freenet.nodelogger.Logger;
import freenet.support.TimeUtil;
import org.greenrobot.eventbus.Subscribe;

/**
 * Exchange one type of update file via UOM (Update Over Mandatory).
 *
 * @since 1.0.1493
 */
public abstract class AbstractUOMUpdateFileExchanger extends AbstractUpdateFileFetcher {

	private static volatile boolean logMINOR;

	static {
		Logger.registerClass(AbstractUOMUpdateFileExchanger.class);
	}

	// ** Grace time before we use UoM to update */
	public static final long GRACE_TIME = TimeUnit.HOURS.toMillis(3);

	// 2 for reliability, no more as gets very slow/wasteful
	static final int MAX_NODES_SENDING_UPDATE_FILE = 2;

	/** Maximum time between asking for the update file and it starting to transfer */
	static final long REQUEST_UPDATE_FILE_TIMEOUT = TimeUnit.SECONDS.toMillis(60);

	public void setPeersSayBlown(boolean peersSayBlown) {
		this.peersSayBlown = peersSayBlown;
	}

	public void setHasBeenBlown(boolean hasBeenBlown) {
		this.hasBeenBlown = hasBeenBlown;
	}

	protected volatile boolean peersSayBlown;

	protected volatile boolean hasBeenBlown;

	protected final FreenetURI updateURI;

	/**
	 * PeerNode's which have offered the update file which we are not fetching it from
	 * right now
	 */
	protected final HashSet<PeerNode> nodesOffered;

	/**
	 * PeerNode's which have offered the update file which we are not fetching it from
	 * right now
	 */
	protected final HashSet<PeerNode> nodesAskedSend;

	/** PeerNode's sending us the update file */
	protected final HashSet<PeerNode> nodesSending;

	/** PeerNode's that we've successfully fetched an update file from */
	protected final HashSet<PeerNode> nodesSent;

	/**
	 * All PeerNode's that offered the update file, regardless of what happened after
	 * that.
	 */
	private final HashSet<PeerNode> allNodesOffered;

	private final FreenetURI revocationURI;

	private final RevocationChecker revocationChecker;

	private final NodeStats nodeStats;

	/**
	 * Set of PeerNode's which say (or said before they disconnected) the key has been
	 * revoked
	 */
	private final HashSet<PeerNode> nodesSayKeyRevoked;

	/**
	 * Set of PeerNode's which say the key has been revoked but failed to transfer the
	 * revocation key.
	 */
	private final HashSet<PeerNode> nodesSayKeyRevokedFailedTransfer;

	/**
	 * Set of PeerNode's which say the key has been revoked and are transferring the
	 * revocation certificate.
	 */
	private final HashSet<PeerNode> nodesSayKeyRevokedTransferring;

	/** Sync lock */
	private final Object broadcastUOMAnnounceUpdateFileSync = new Object();

	/**
	 * True if we're ready to broadcast UOMAnnounceUpdateFile message to other connected
	 * peers.
	 */
	private volatile boolean broadcastUOMAnnounceUpdateFile;

	private boolean fetchingUOM;

	final ByteCounter ctr = new ByteCounter() {

		@Override
		public void receivedBytes(int x) {
			// FIXME
		}

		@Override
		public void sentBytes(int x) {
			AbstractUOMUpdateFileExchanger.this.node.nodeStats.reportUOMBytesSent(x);
		}

		@Override
		public void sentPayload(int x) {
			// Ignore. It will be reported to sentBytes() as well.
		}

	};

	public AbstractUOMUpdateFileExchanger(Node node, String fileType, int currentVersion, int minDeployVersion,
			int maxDeployVersion, FreenetURI updateURI, FreenetURI revocationURI, RevocationChecker revocationChecker) {

		super(node, fileType, currentVersion, minDeployVersion, maxDeployVersion);

		this.updateURI = updateURI;

		this.revocationURI = revocationURI;
		this.revocationChecker = revocationChecker;
		this.nodeStats = node.nodeStats;

		this.nodesOffered = new HashSet<>();
		this.nodesAskedSend = new HashSet<>();
		this.nodesSending = new HashSet<>();
		this.nodesSent = new HashSet<>();
		this.allNodesOffered = new HashSet<>();
		this.nodesSayKeyRevoked = new HashSet<>();
		this.nodesSayKeyRevokedFailedTransfer = new HashSet<>();
		this.nodesSayKeyRevokedTransferring = new HashSet<>();

		EventBus.get().register(this);
	}

	/**
	 * An event is received when out node has processed a peer node's noderef after
	 * connected to a peer. we'll check if we may send UOMAnnounceUpdateFile.
	 * @see PeerNode#processDiffNoderef
	 */
	@Subscribe
	public void onDiffNoderefProcessed(DiffNoderefProcessedEvent event) {
		// Send UOMAnnouncement only *after* we know what the other side's version.
		var pn = event.getPn();
		if (pn.isRealConnection()) {
			this.maybeSendUOMAnnounceUpdateFile(pn);
		}
	}

	// region UOM message handlers
	// ================================================================================
	public boolean handleUOMAnnounceUpdateFile(Message message, final PeerNode source) {
		String fileType = message.getString(DMT.UPDATE_FILE_TYPE);
		String fileKey = message.getString(DMT.UPDATE_FILE_KEY);
		String revocationKey = message.getString(DMT.REVOCATION_KEY);
		boolean haveRevocationKey = message.getBoolean(DMT.HAVE_REVOCATION_KEY);
		long fileVersion = message.getLong(DMT.UPDATE_FILE_VERSION);
		long revocationKeyLastTried = message.getLong(DMT.REVOCATION_KEY_TIME_LAST_TRIED);
		int revocationKeyDNFs = message.getInt(DMT.REVOCATION_KEY_DNF_COUNT);
		long revocationKeyFileLength = message.getLong(DMT.REVOCATION_KEY_FILE_LENGTH);
		long fileLength = message.getLong(DMT.UPDATE_FILE_LENGTH);
		int pingTime = message.getInt(DMT.PING_TIME);
		int delayTime = message.getInt(DMT.BWLIMIT_DELAY_TIME);

		// First off, if a node says it has the revocation key, and its key is the same as
		// ours, we should 1) suspend any auto-updates and tell the user, 2) try to
		// download it, and 3) if the download fails, move the notification; if the
		// download succeeds, process it

		if (haveRevocationKey) {

			if (this.updateBlown) {
				return true; // We already know
			}

			// First, is the key the same as ours?
			try {
				FreenetURI revocationURI = new FreenetURI(revocationKey);
				if (revocationURI.equals(this.revocationURI)) {

					// Uh oh...

					// Have to do this first to avoid race condition
					synchronized (this) {
						// If already transferring, don't start another transfer.
						if (this.nodesSayKeyRevokedTransferring.contains(source)) {
							return true;
						}
						// If waiting for SendingRevocation, don't start another transfer.
						if (this.nodesSayKeyRevoked.contains(source)) {
							return true;
						}
						this.nodesSayKeyRevoked.add(source);
					}

					// Disable the update
					this.peersSayBlown = true;

					// TODO: event
					// Tell the user
					// this.alertUser();

					System.err.println("Your peer " + source.userToString() + " (build #" + source.getSimpleVersion()
							+ ") says that the auto-update key is blown!");
					System.err.println("Attempting to fetch it...");

					this.tryFetchRevocation(source);

				}
				else {
					// Should probably also be a useralert?
					Logger.normal(this, "Node " + source
							+ " sent us a UOM claiming that the auto-update key was blown, but it used a different key to us: \nour key="
							+ this.revocationURI + "\nhis key=" + revocationURI);
				}
			}
			catch (MalformedURLException ex) {
				// Should maybe be a useralert?
				Logger.error(this, "Node " + source
						+ " sent us a UOMAnnounceManifest claiming that the auto-update key was blown, but it had an invalid revocation URI: "
						+ revocationKey + " : " + ex, ex);
				System.err.println("Node " + source.userToString()
						+ " sent us a UOMAnnounceManifest claiming that the revocation key was blown, but it had an invalid revocation URI: "
						+ revocationKey + " : " + ex);
			}
			catch (NotConnectedException ex) {
				System.err.println("Node " + source
						+ " says that the auto-update key was blown, but has now gone offline! Something bad may be happening!");
				Logger.error(this, "Node " + source
						+ " says that the auto-update key was blown, but has now gone offline! Something bad may be happening!");
				synchronized (this) {
					this.nodesSayKeyRevoked.remove(source);
				}
				// Might be valid, but no way to tell except if other peers tell us.
				// And there's a good chance it isn't.
				this.maybeNotRevoked();
			}

		}

		// TODO: notify update manager
		// this.tellFetchers(source);

		if (this.updateBlown) {
			return true; // We already know
		}

		if (!this.updateEnabled) {
			return true; // Don't care if not enabled, except for the revocation URI
		}

		long now = System.currentTimeMillis();

		this.handleUpdateFileOffer(now, fileLength, fileVersion, source, fileKey);

		return true;

	}
	// ================================================================================
	// endregion

	private void handleUpdateFileOffer(long now, long fileLength, long fileVersion, PeerNode source,
			String manifestKey) {

		long started = this.startedFetchingNextFile;
		long whenToTakeOverTheNormalUpdater;
		if (started > 0) {
			whenToTakeOverTheNormalUpdater = started + GRACE_TIME;
		}
		else {
			whenToTakeOverTheNormalUpdater = System.currentTimeMillis() + GRACE_TIME;
		}
		boolean isOutdated = this.node.isOudated();
		// if the new build is self-mandatory or if the "normal" updater has been trying
		// to update for more than one hour
		Logger.normal(this,
				"We received a valid UOMAnnounceManifest (main) : (isOutdated=" + isOutdated + " version=" + fileVersion
						+ " whenToTakeOverTheNormalUpdater=" + TimeUtil.formatTime(whenToTakeOverTheNormalUpdater - now)
						+ ") file length " + fileLength + " updateManager version " + this.fetchedVersion);
		if (fileVersion > Version.buildNumber() && fileLength > 0 && fileVersion > this.fetchedVersion) {
			source.setManifestOfferedVersion(fileVersion);
			// Offer is valid.
			if (logMINOR) {
				Logger.minor(this, "Offer is valid");
			}
			if ((isOutdated) || whenToTakeOverTheNormalUpdater < now) {
				// Take up the offer, subject to limits on number of simultaneous
				// downloads.
				// If we have fetches running already, then sendUOMRequestMainJar() will
				// add the offer to nodesOfferedMainJar,
				// so that if all our fetches fail, we can fetch from this node.
				if (!isOutdated) {
					String howLong = TimeUtil.formatTime(now - started);
					Logger.error(this, "The update process seems to have been stuck for " + howLong
							+ "; let's switch to UoM! SHOULD NOT HAPPEN! (1)");
					System.out.println("The update process seems to have been stuck for " + howLong
							+ "; let's switch to UoM! SHOULD NOT HAPPEN! (1)");
				}
				else if (logMINOR) {
					Logger.minor(this, "Fetching via UOM as our build is deprecated");
				}
				// Fetch it
				try {
					FreenetURI manifestURI = new FreenetURI(manifestKey).setSuggestedEdition(fileVersion);
					if (manifestURI.equals(this.updateURI.setSuggestedEdition(fileVersion))) {
						this.sendUOMRequestUpdateFile(source, true);
					}
					else {
						// FIXME don't log if it's the transitional version.
						System.err.println("Node " + source.userToString() + " offered us a new main jar (version "
								+ fileVersion + ") but his key was different to ours:\n" + "our key: " + this.updateURI
								+ "\nhis key:" + manifestURI);
					}
				}
				catch (MalformedURLException ex) {
					// Should maybe be a useralert?
					Logger.error(this, "Node " + source
							+ " sent us a UOMAnnouncement claiming to have a new ext jar, but it had an invalid URI: "
							+ manifestKey + " : " + ex, ex);
					System.err.println("Node " + source.userToString()
							+ " sent us a UOMAnnouncement claiming to have a new ext jar, but it had an invalid URI: "
							+ manifestKey + " : " + ex);
				}
				synchronized (this) {
					this.allNodesOffered.add(source);
				}
			}
			else {
				// Don't take up the offer. Add to nodesOfferedManifest, so that we know
				// where to fetch it from when we need it.
				synchronized (this) {
					this.nodesOffered.add(source);
					this.allNodesOffered.add(source);
				}
				this.node.getTicker().queueTimedJob(new Runnable() {

					@Override
					public void run() {
						if (AbstractUOMUpdateFileExchanger.this.updateBlown) {
							return;
						}
						if (!AbstractUOMUpdateFileExchanger.this.updateEnabled) {
							return;
						}
						if (AbstractUOMUpdateFileExchanger.this.hasNewFile) {
							return;
						}
						if (!AbstractUOMUpdateFileExchanger.this.node.isOudated()) {
							Logger.error(this,
									"The update process seems to have been stuck for too long; let's switch to UoM! SHOULD NOT HAPPEN! (2) (ext)");
							System.out.println(
									"The update process seems to have been stuck for too long; let's switch to UoM! SHOULD NOT HAPPEN! (2) (ext)");
						}
						AbstractUOMUpdateFileExchanger.this.maybeRequestManifest();
					}
				}, whenToTakeOverTheNormalUpdater - now);
			}
		}
		else {
			// We may want the dependencies.
			// These may be similar even if his url is different, so add unconditionally.
			synchronized (this) {
				this.allNodesOffered.add(source);
			}
		}
		// TODO
		// this.startSomeDependencyFetchers();
	}

	private void sendUOMRequestUpdateFile(final PeerNode source, boolean addOnFail) {
		final String name = "Main";
		String lname = "main";
		if (logMINOR) {
			Logger.minor(this, "sendUOMRequestUpdateFile" + name + "(" + source + "," + addOnFail + ")");
		}
		if (!source.isConnected() || source.isSeed()) {
			if (logMINOR) {
				Logger.minor(this,
						"Not sending UOM " + lname + " request to " + source + " (disconnected or seednode)");
			}
			return;
		}
		final HashSet<PeerNode> sendingManifest = this.nodesSending;
		final HashSet<PeerNode> askedSendManifest = this.nodesAskedSend;
		boolean wasFetchingUOM;
		synchronized (this) {
			long offeredVersion = source.getManifestOfferedVersion();
			long updateVersion = this.fetchedVersion;
			if (offeredVersion < updateVersion) {
				if (offeredVersion <= 0) {
					Logger.error(this, "Not sending UOM " + lname + " request to " + source
							+ " because it hasn't offered anything!");
				}
				else if (logMINOR) {
					Logger.minor(this, "Not sending UOM " + lname + " request to " + source
							+ " because we already have its offered version " + offeredVersion);
				}
				return;
			}
			if (this.currentVersion >= offeredVersion) {
				if (logMINOR) {
					Logger.minor(this, "Not fetching from " + source + " because current " + lname
							+ " manifest version " + this.currentVersion + " is more recent than " + offeredVersion);
				}
				return;
			}
			if (askedSendManifest.contains(source)) {
				if (logMINOR) {
					Logger.minor(this, "Recently asked node " + source + " (" + lname + ") so not re-asking yet.");
				}
				return;
			}
			if (addOnFail && askedSendManifest.size() + sendingManifest.size() >= MAX_NODES_SENDING_UPDATE_FILE) {
				if (this.nodesOffered.add(source)) {
					System.err.println("Offered " + lname + " manifest by " + source.userToString()
							+ " (already fetching from " + sendingManifest.size()
							+ "), but will use this offer if our current fetches fail).");
				}
				return;
			}
			else {
				if (sendingManifest.contains(source)) {
					if (logMINOR) {
						Logger.minor(this, "Not fetching " + lname + " manifest from " + source.userToString()
								+ " because already fetching from that node");
					}
					return;
				}
				sendingManifest.add(source);
			}
			wasFetchingUOM = this.fetchingUOM;
			this.fetchingUOM = true;
		}
		if (!wasFetchingUOM) {
			this.nodeUpdateManager.onStartFetchingUOM();
		}

		Message msg = DMT.createUOMRequestUpdateFile(this.node.random.nextLong());

		try {
			System.err.println("Fetching " + lname + " manifest from " + source.userToString());
			source.sendAsync(msg, new AsyncMessageCallback() {

				@Override
				public void acknowledged() {
					// Cool! Wait for the actual transfer.
				}

				@Override
				public void disconnected() {
					Logger.normal(this,
							"Disconnected from " + source.userToString() + " after sending UOMRequestUpdateFile");
					synchronized (AbstractUOMUpdateFileExchanger.this) {
						sendingManifest.remove(source);
					}
					AbstractUOMUpdateFileExchanger.this.maybeRequestManifest();
				}

				@Override
				public void fatalError() {
					Logger.normal(this,
							"Fatal error from " + source.userToString() + " after sending UOMRequestManifest");
					synchronized (AbstractUOMUpdateFileExchanger.this) {
						askedSendManifest.remove(source);
					}
					AbstractUOMUpdateFileExchanger.this.maybeRequestManifest();
				}

				@Override
				public void sent() {
					// Timeout...
					AbstractUOMUpdateFileExchanger.this.node.ticker.queueTimedJob(() -> {
						synchronized (AbstractUOMUpdateFileExchanger.this) {
							// free up a slot
							if (!askedSendManifest.remove(source)) {
								return;
							}
						}
						AbstractUOMUpdateFileExchanger.this.maybeRequestManifest();
					}, REQUEST_UPDATE_FILE_TIMEOUT);
				}
			}, this.ctr);
		}
		catch (NotConnectedException ignored) {
			synchronized (this) {
				askedSendManifest.remove(source);
			}
			this.maybeRequestManifest();
		}
	}

	protected void maybeRequestManifest() {
		PeerNode[] offers;
		synchronized (this) {
			if (this.nodesAskedSend.size() + this.nodesSending.size() >= MAX_NODES_SENDING_UPDATE_FILE) {
				return;
			}
			if (this.nodesOffered.isEmpty()) {
				return;
			}
			offers = this.nodesOffered.toArray(new PeerNode[0]);
		}
		for (PeerNode offer : offers) {
			if (!offer.isConnected()) {
				continue;
			}
			synchronized (this) {
				if (this.nodesAskedSend.size() + this.nodesSending.size() >= MAX_NODES_SENDING_UPDATE_FILE) {
					return;
				}
				if (this.nodesSending.contains(offer)) {
					continue;
				}
				if (this.nodesAskedSend.contains(offer)) {
					continue;
				}
			}
			this.sendUOMRequestUpdateFile(offer, false);
		}
	}

	private void tryFetchRevocation(final PeerNode source) throws NotConnectedException {
		// Try to transfer it.

		Message msg = DMT.createUOMRequestRevocationManifest(this.node.random.nextLong());
		source.sendAsync(msg, new AsyncMessageCallback() {

			@Override
			public void acknowledged() {
				// Ok
			}

			@Override
			public void disconnected() {
				// :(
				System.err.println("Failed to send request for revocation key to " + source.userToString() + " (build #"
						+ source.getSimpleVersion() + ") because it disconnected!");
				source.failedRevocationTransfer();
				synchronized (AbstractUOMUpdateFileExchanger.this) {
					AbstractUOMUpdateFileExchanger.this.nodesSayKeyRevokedFailedTransfer.add(source);
				}
			}

			@Override
			public void fatalError() {
				// Not good!
				System.err.println("Failed to send request for revocation key to " + source.userToString()
						+ " because of a fatal error.");
			}

			@Override
			public void sent() {
				// Cool
			}
		}, this.ctr);

		this.node.getTicker().queueTimedJob(() -> {
			if (AbstractUOMUpdateFileExchanger.this.updateBlown) {
				return;
			}
			synchronized (AbstractUOMUpdateFileExchanger.this) {
				if (AbstractUOMUpdateFileExchanger.this.nodesSayKeyRevokedFailedTransfer.contains(source)) {
					return;
				}
				if (AbstractUOMUpdateFileExchanger.this.nodesSayKeyRevokedTransferring.contains(source)) {
					return;
				}
				AbstractUOMUpdateFileExchanger.this.nodesSayKeyRevoked.remove(source);
			}
			System.err.println("Peer " + source + " (build #" + source.getSimpleVersion()
					+ ") said that the auto-update key had been blown, but did not transfer the revocation certificate. The most likely explanation is that the key has not been blown (the node is buggy or malicious), so we are ignoring this.");
			AbstractUOMUpdateFileExchanger.this.maybeNotRevoked();
		}, TimeUnit.SECONDS.toMillis(60));

		// The reply message will start the transfer. It includes the revocation URI
		// so we can tell if anything wierd is happening.

	}

	protected void maybeNotRevoked() {
		synchronized (this) {
			if (!this.peersSayBlown) {
				return;
			}
			if (this.mightBeRevoked()) {
				return;
			}
			// TODO: post event
			// this.updateManager.notPeerClaimsKeyBlown();
		}
	}

	private boolean mightBeRevoked() {
		PeerNode[] started;
		PeerNode[] transferring;
		synchronized (this) {
			started = this.nodesSayKeyRevoked.toArray(new PeerNode[0]);
			transferring = this.nodesSayKeyRevokedTransferring.toArray(new PeerNode[0]);
		}
		// If a peer is not connected, ignore it.
		// If a peer has already tried 3 times to send the revocation cert, ignore it,
		// because it is probably evil.
		for (PeerNode peer : started) {
			if (!peer.isConnected()) {
				continue;
			}
			if (peer.countFailedRevocationTransfers() > 3) {
				continue;
			}
			return true;
		}
		for (PeerNode peer : transferring) {
			if (!peer.isConnected()) {
				continue;
			}
			if (peer.countFailedRevocationTransfers() > 3) {
				continue;
			}
			return true;
		}
		return false;
	}

	protected void maybeSendUOMAnnounceUpdateFile(PeerNode peer) {
		if (!this.broadcastUOMAnnounceUpdateFile) {
			if (logMINOR) {
				Logger.minor(this, "Not sending UOM (any) on connect: Nothing worth announcing yet");
			}
		}
	}

	public void maybeBroadcastUOMAnnounceUpdateFile() {
		if (logMINOR) {
			Logger.minor(this, "Maybe broadcast UOM announces new");
		}
		if (this.hasBeenBlown) {
			return;
		}
		if (this.peersSayBlown) {
			return;
		}
		if (logMINOR) {
			Logger.minor(this, "Maybe broadcast UOM announces new (2)");
		}
		// If the node has no peers, noRevocationFound will never be called.
		this.broadcastUOMAnnounceUpdateFile();
	}

	void broadcastUOMAnnounceUpdateFile() {
		if (logMINOR) {
			Logger.minor(this, "Broadcast UOM announcements (new)");
		}
		long size = this.canUOMAnnounceUpdateFile();
		Message msg;
		if (size <= 0 && !this.hasBeenBlown) {
			return;
		}
		synchronized (this.broadcastUOMAnnounceUpdateFileSync) {
			if (this.broadcastUOMAnnounceUpdateFile && !this.hasBeenBlown) {
				return;
			}
			this.broadcastUOMAnnounceUpdateFile = true;
			msg = this.getUOMAnnounceUpdateFile(size);
		}
		if (logMINOR) {
			Logger.minor(this, "Broadcasting UOM announcements (new)");
		}
		this.node.peers.localBroadcast(msg, true, true, this.ctr, 0, Integer.MAX_VALUE);
	}

	public void maybeSendUOMAnnounceManifest(PeerNode peer) {
		if (this.hasBeenBlown && !this.revocationChecker.hasBlown()) {
			if (logMINOR) {
				Logger.minor(this, "Not sending UOM (any) on connect: Local problem causing blown key");
			}
			// Local problem, don't broadcast.
			return;
		}
		long size = this.canUOMAnnounceUpdateFile();
		try {
			peer.sendAsync(this.getUOMAnnounceUpdateFile(size), null, this.ctr);
		}
		catch (NotConnectedException ignored) {
			// Sad, but ignore it
		}
	}

	/** Return the length of the data fetched for the current version, or -1. */
	protected long canUOMAnnounceUpdateFile() {
		Bucket data;
		synchronized (this) {
			if (this.hasNewFile && this.updateArmed) {
				if (logMINOR) {
					Logger.minor(this, "Will update soon, not offering UOM.");
				}
				return -1;
			}
			if (this.fetchedFileVersion <= 0) {
				if (logMINOR) {
					Logger.minor(this, "Not fetched yet");
				}
				return -1;
			}
			else if (this.fetchedFileVersion != Version.buildNumber()) {
				// Don't announce UOM unless we've successfully updated ored.
				if (logMINOR) {
					Logger.minor(this, "Downloaded a different version than the one we are running, not offering UOM.");
				}
				return -1;
			}
			data = this.fetchedFileData;
		}
		if (logMINOR) {
			Logger.minor(this, "Got data for UOM: " + data + " size " + data.size());
		}
		return data.size();
	}

	protected abstract Message getUOMAnnounceUpdateFile(long blobSize);

	protected abstract String getFileType();

}
