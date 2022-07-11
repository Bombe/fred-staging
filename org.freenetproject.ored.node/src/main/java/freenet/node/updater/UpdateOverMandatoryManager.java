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

package freenet.node.updater;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.WeakHashMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import freenet.bucket.ArrayBucket;
import freenet.bucket.Bucket;
import freenet.bucket.FileBucket;
import freenet.bucket.RandomAccessBucket;
import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.FetchException.FetchExceptionMode;
import freenet.client.FetchResult;
import freenet.client.InsertContext;
import freenet.client.InsertException;
import freenet.client.async.BaseClientPutter;
import freenet.client.async.BinaryBlob;
import freenet.client.async.BinaryBlobFormatException;
import freenet.client.async.BinaryBlobWriter;
import freenet.client.async.ClientContext;
import freenet.client.async.ClientGetCallback;
import freenet.client.async.ClientGetter;
import freenet.client.async.ClientPutCallback;
import freenet.client.async.ClientPutter;
import freenet.client.async.PersistenceDisabledException;
import freenet.client.async.SimpleBlockSet;
import freenet.client.request.PriorityClasses;
import freenet.client.request.RequestClient;
import freenet.clients.fcp.FCPUserAlert;
import freenet.io.comm.AsyncMessageCallback;
import freenet.io.comm.DMT;
import freenet.io.comm.DisconnectedException;
import freenet.io.comm.Message;
import freenet.io.comm.NotConnectedException;
import freenet.io.xfer.BulkReceiver;
import freenet.io.xfer.BulkTransmitter;
import freenet.io.xfer.PartiallyReceivedBulk;
import freenet.keys.FreenetURI;
import freenet.l10n.NodeL10n;
import freenet.lockablebuffer.ByteArrayRandomAccessBuffer;
import freenet.lockablebuffer.FileRandomAccessBuffer;
import freenet.node.Node;
import freenet.node.PeerNode;
import freenet.node.Version;
import freenet.node.event.EventBus;
import freenet.node.event.update.UOMManifestRequestSuccessEvent;
import freenet.node.updater.usk.ManifestUSKUpdateFileFetcher;
import freenet.node.useralerts.BaseNodeUserAlert;
import freenet.nodelogger.Logger;
import freenet.support.HTMLNode;
import freenet.support.HexUtil;
import freenet.support.ShortBuffer;
import freenet.support.SizeUtil;
import freenet.support.TimeUtil;
import freenet.support.WeakHashSet;
import freenet.support.api.RandomAccessBuffer;
import freenet.support.io.Closer;
import freenet.support.io.FileUtil;

/**
 * Co-ordinates update over mandatory. Update over mandatory = updating from your peers,
 * even though they may be so much newer than you that you can't route requests through
 * them. NodeDispatcher feeds UOMAnnouncement's received from peers to this class, and it
 * decides what to do about them.
 * <p/>
 * Sequence Diagram
 * <p/>
 *
 * <pre>
 * Node A (has Manifest file)
 * 1) UOMAnnounceManifest 3) UOMSendingManifest
 * Node B (requests Manifest file)
 * 2) UOMRequestManifest
 *</pre>
 *
 * @author toad
 */
public class UpdateOverMandatoryManager implements RequestClient {

	private static volatile boolean logMINOR;

	static {
		Logger.registerClass(UpdateOverMandatoryManager.class);
	}

	final NodeUpdateManager updateManager;

	// ** Grace time before we use UoM to update */
	public static final long GRACE_TIME = TimeUnit.HOURS.toMillis(3);

	private FCPUserAlert alert;

	private static final Pattern mainBuildNumberPattern = Pattern.compile("^main(?:-jar)?-(\\d+)\\.fblob$");

	private static final Pattern mainTempBuildNumberPattern = Pattern
			.compile("^main(?:-jar)?-(\\d+-)?(\\d+)\\.fblob\\.tmp*$");

	private static final Pattern revocationTempBuildNumberPattern = Pattern
			.compile("^revocation(?:-jar)?-(\\d+-)?(\\d+)\\.fblob\\.tmp*$");

	private boolean fetchingUOM;

	private final HashMap<ShortBuffer, File> dependencies;

	private final WeakHashMap<PeerNode, Integer> peersFetchingDependencies;

	private final HashMap<ShortBuffer, UOMDependencyFetcher> dependencyFetchers;

	public UpdateOverMandatoryManager(NodeUpdateManager manager) {
		this.updateManager = manager;
		this.dependencies = new HashMap<>();
		this.peersFetchingDependencies = new WeakHashMap<>();
		this.dependencyFetchers = new HashMap<>();
	}

	/**
	 * Handle a UOMAnnounceManifest message. A node has sent us a message offering us use
	 * of its update over mandatory facilities in some way.
	 * @param m The UOMAnnounceManifest message to handle.
	 * @param source The PeerNode which sent the message.
	 * @return True unless we don't want the message (in this case, always true).
	 */
	public boolean handleAnnounceManifest(Message m, final PeerNode source) {

		String mainManifestKey = m.getString(DMT.UPDATE_FILE_KEY);
		String revocationKey = m.getString(DMT.REVOCATION_KEY);
		boolean haveRevocationKey = m.getBoolean(DMT.HAVE_REVOCATION_KEY);
		long mainManifestVersion = m.getLong(DMT.UPDATE_FILE_VERSION);
		long revocationKeyLastTried = m.getLong(DMT.REVOCATION_KEY_TIME_LAST_TRIED);
		int revocationKeyDNFs = m.getInt(DMT.REVOCATION_KEY_DNF_COUNT);
		long revocationKeyFileLength = m.getLong(DMT.REVOCATION_KEY_FILE_LENGTH);
		long mainManifestFileLength = m.getLong(DMT.UPDATE_FILE_LENGTH);
		int pingTime = m.getInt(DMT.PING_TIME);
		int delayTime = m.getInt(DMT.BWLIMIT_DELAY_TIME);

		// Log it

		if (logMINOR) {
			Logger.minor(this,
					"Update Over Mandatory offer from node " + source.getPeer() + " : " + source.userToString() + ":");
			Logger.minor(this, "Main manifest key: " + mainManifestKey + " version=" + mainManifestVersion + " length="
					+ mainManifestFileLength);
			Logger.minor(this,
					"Revocation key: " + revocationKey + " found=" + haveRevocationKey + " length="
							+ revocationKeyFileLength + " last had 3 DNFs " + revocationKeyLastTried + " ms ago, "
							+ revocationKeyDNFs + " DNFs so far");
			Logger.minor(this, "Load stats: " + pingTime + "ms ping, " + delayTime + "ms bwlimit delay time");
		}

		// Now the core logic

		// First off, if a node says it has the revocation key, and its key is the same as
		// ours,
		// we should 1) suspend any auto-updates and tell the user, 2) try to download it,
		// and
		// 3) if the download fails, move the notification; if the download succeeds,
		// process it

		if (haveRevocationKey) {

			if (this.updateManager.isBlown()) {
				return true; // We already know
			}

			// First, is the key the same as ours?
			try {
				FreenetURI revocationURI = new FreenetURI(revocationKey);
				if (revocationURI.equals(this.updateManager.getRevocationURI())) {

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
					this.updateManager.peerClaimsKeyBlown();

					// Tell the user
					this.alertUser();

					System.err.println("Your peer " + source.userToString() + " (build #" + source.getSimpleVersion()
							+ ") says that the auto-update key is blown!");
					System.err.println("Attempting to fetch it...");

					this.tryFetchRevocation(source);

				}
				else {
					// Should probably also be a useralert?
					Logger.normal(this, "Node " + source
							+ " sent us a UOM claiming that the auto-update key was blown, but it used a different key to us: \nour key="
							+ this.updateManager.getRevocationURI() + "\nhis key=" + revocationURI);
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
				synchronized (UpdateOverMandatoryManager.this) {
					this.nodesSayKeyRevoked.remove(source);
					// Might be valid, but no way to tell except if other peers tell us.
					// And there's a good chance it isn't.
				}
				this.maybeNotRevoked();
			}

		}

		// TODO
		// this.tellFetchers(source);

		if (this.updateManager.isBlown()) {
			return true; // We already know
		}

		if (!this.updateManager.isEnabled()) {
			return true; // Don't care if not enabled, except for the revocation URI
		}

		long now = System.currentTimeMillis();

		this.handleManifestOffer(now, mainManifestFileLength, mainManifestVersion, source, mainManifestKey);

		return true;
	}

	private void tellFetchers(PeerNode source) {
		HashSet<UOMDependencyFetcher> fetchList;
		synchronized (this.dependencyFetchers) {
			fetchList = new HashSet<>(this.dependencyFetchers.values());
		}
		for (UOMDependencyFetcher f : fetchList) {
			if (source.isDarknet()) {
				f.peerMaybeFreeSlots(source);
			}
			f.start();
		}
	}

	private void tryFetchRevocation(final PeerNode source) throws NotConnectedException {
		// Try to transfer it.

		Message msg = DMT.createUOMRequestRevocationManifest(this.updateManager.node.random.nextLong());
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
				synchronized (UpdateOverMandatoryManager.this) {
					UpdateOverMandatoryManager.this.nodesSayKeyRevokedFailedTransfer.add(source);
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
		}, this.updateManager.ctr);

		this.updateManager.node.getTicker().queueTimedJob(() -> {
			if (UpdateOverMandatoryManager.this.updateManager.isBlown()) {
				return;
			}
			synchronized (UpdateOverMandatoryManager.this) {
				if (UpdateOverMandatoryManager.this.nodesSayKeyRevokedFailedTransfer.contains(source)) {
					return;
				}
				if (UpdateOverMandatoryManager.this.nodesSayKeyRevokedTransferring.contains(source)) {
					return;
				}
				UpdateOverMandatoryManager.this.nodesSayKeyRevoked.remove(source);
			}
			System.err.println("Peer " + source + " (build #" + source.getSimpleVersion()
					+ ") said that the auto-update key had been blown, but did not transfer the revocation certificate. The most likely explanation is that the key has not been blown (the node is buggy or malicious), so we are ignoring this.");
			UpdateOverMandatoryManager.this.maybeNotRevoked();
		}, TimeUnit.SECONDS.toMillis(60));

		// The reply message will start the transfer. It includes the revocation URI
		// so we can tell if anything wierd is happening.

	}

	private void handleManifestOffer(long now, long mainManifestFileLength, long mainManifestVersion, PeerNode source,
			String manifestKey) {

		long started = this.updateManager.getStartedFetchingNextManifestTimestamp();
		long whenToTakeOverTheNormalUpdater;
		if (started > 0) {
			whenToTakeOverTheNormalUpdater = started + GRACE_TIME;
		}
		else {
			whenToTakeOverTheNormalUpdater = System.currentTimeMillis() + GRACE_TIME;
		}
		boolean isOutdated = this.updateManager.node.isOudated();
		// if the new build is self-mandatory or if the "normal" updater has been trying
		// to update for more than one hour
		Logger.normal(this,
				"We received a valid UOMAnnounceManifest (main) : (isOutdated=" + isOutdated + " version="
						+ mainManifestVersion + " whenToTakeOverTheNormalUpdater="
						+ TimeUtil.formatTime(whenToTakeOverTheNormalUpdater - now) + ") file length "
						+ mainManifestFileLength + " updateManager version " + this.updateManager.getNewVersion());
		if (mainManifestVersion > Version.buildNumber() && mainManifestFileLength > 0
				&& mainManifestVersion > this.updateManager.getNewVersion()) {
			source.setManifestOfferedVersion(mainManifestVersion);
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
					FreenetURI manifestURI = new FreenetURI(manifestKey).setSuggestedEdition(mainManifestVersion);
					if (manifestURI
							.equals(this.updateManager.getUpdateURI().setSuggestedEdition(mainManifestVersion))) {
						this.sendUOMRequestManifest(source, true);
					}
					else {
						// FIXME don't log if it's the transitional version.
						System.err.println("Node " + source.userToString() + " offered us a new main jar (version "
								+ mainManifestVersion + ") but his key was different to ours:\n" + "our key: "
								+ this.updateManager.getUpdateURI() + "\nhis key:" + manifestURI);
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
					this.allNodesOfferedManifest.add(source);
				}
			}
			else {
				// Don't take up the offer. Add to nodesOfferedManifest, so that we know
				// where to fetch it from when we need it.
				synchronized (this) {
					this.nodesOfferedManifest.add(source);
					this.allNodesOfferedManifest.add(source);
				}
				this.updateManager.node.getTicker().queueTimedJob(new Runnable() {

					@Override
					public void run() {
						if (UpdateOverMandatoryManager.this.updateManager.isBlown()) {
							return;
						}
						if (!UpdateOverMandatoryManager.this.updateManager.isEnabled()) {
							return;
						}
						if (UpdateOverMandatoryManager.this.updateManager.isHasNewFile()) {
							return;
						}
						if (!UpdateOverMandatoryManager.this.updateManager.node.isOudated()) {
							Logger.error(this,
									"The update process seems to have been stuck for too long; let's switch to UoM! SHOULD NOT HAPPEN! (2) (ext)");
							System.out.println(
									"The update process seems to have been stuck for too long; let's switch to UoM! SHOULD NOT HAPPEN! (2) (ext)");
						}
						UpdateOverMandatoryManager.this.maybeRequestManifest();
					}
				}, whenToTakeOverTheNormalUpdater - now);
			}
		}
		else {
			// We may want the dependencies.
			// These may be similar even if his url is different, so add unconditionally.
			synchronized (this) {
				this.allNodesOfferedManifest.add(source);
			}
		}
		// TODO
		// this.startSomeDependencyFetchers();
	}

	private void sendUOMRequestManifest(final PeerNode source, boolean addOnFail) {
		final String name = "Main";
		String lname = "main";
		if (logMINOR) {
			Logger.minor(this, "sendUOMRequestManifest" + name + "(" + source + "," + addOnFail + ")");
		}
		if (!source.isConnected() || source.isSeed()) {
			if (logMINOR) {
				Logger.minor(this,
						"Not sending UOM " + lname + " request to " + source + " (disconnected or seednode)");
			}
			return;
		}
		final HashSet<PeerNode> sendingManifest = this.nodesSendingManifest;
		final HashSet<PeerNode> askedSendManifest = this.nodesAskedSendManifest;
		boolean wasFetchingUOM;
		synchronized (this) {
			long offeredVersion = source.getManifestOfferedVersion();
			long updateVersion = this.updateManager.getNewVersion();
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
			int curVersion = this.updateManager.getMainVersion();
			if (curVersion >= offeredVersion) {
				if (logMINOR) {
					Logger.minor(this, "Not fetching from " + source + " because current " + lname
							+ " manifest version " + curVersion + " is more recent than " + offeredVersion);
				}
				return;
			}
			if (askedSendManifest.contains(source)) {
				if (logMINOR) {
					Logger.minor(this, "Recently asked node " + source + " (" + lname + ") so not re-asking yet.");
				}
				return;
			}
			if (addOnFail && askedSendManifest.size() + sendingManifest.size() >= MAX_NODES_SENDING_MANIFEST) {
				if (this.nodesOfferedManifest.add(source)) {
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
			this.updateManager.onStartFetchingUOM();
		}

		Message msg = DMT.createUOMRequestManifest(this.updateManager.node.random.nextLong());

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
							"Disconnected from " + source.userToString() + " after sending UOMRequestManifest");
					synchronized (UpdateOverMandatoryManager.this) {
						sendingManifest.remove(source);
					}
					UpdateOverMandatoryManager.this.maybeRequestManifest();
				}

				@Override
				public void fatalError() {
					Logger.normal(this,
							"Fatal error from " + source.userToString() + " after sending UOMRequestManifest");
					synchronized (UpdateOverMandatoryManager.this) {
						askedSendManifest.remove(source);
					}
					UpdateOverMandatoryManager.this.maybeRequestManifest();
				}

				@Override
				public void sent() {
					// Timeout...
					UpdateOverMandatoryManager.this.updateManager.node.ticker.queueTimedJob(() -> {
						synchronized (UpdateOverMandatoryManager.this) {
							// free up a slot
							if (!askedSendManifest.remove(source)) {
								return;
							}
						}
						UpdateOverMandatoryManager.this.maybeRequestManifest();
					}, REQUEST_MANIFEST_TIMEOUT);
				}
			}, this.updateManager.ctr);
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
			if (this.nodesAskedSendManifest.size() + this.nodesSendingManifest.size() >= MAX_NODES_SENDING_MANIFEST) {
				return;
			}
			if (this.nodesOfferedManifest.isEmpty()) {
				return;
			}
			offers = this.nodesOfferedManifest.toArray(new PeerNode[0]);
		}
		for (PeerNode offer : offers) {
			if (!offer.isConnected()) {
				continue;
			}
			synchronized (this) {
				if (this.nodesAskedSendManifest.size()
						+ this.nodesSendingManifest.size() >= MAX_NODES_SENDING_MANIFEST) {
					return;
				}
				if (this.nodesSendingManifest.contains(offer)) {
					continue;
				}
				if (this.nodesAskedSendManifest.contains(offer)) {
					continue;
				}
			}
			this.sendUOMRequestManifest(offer, false);
		}
	}

	private void alertUser() {
		synchronized (this) {
			if (this.alert != null) {
				return;
			}
			this.alert = new PeersSayKeyBlownAlert();
		}
		this.updateManager.node.clientCore.alerts.register(this.alert);
	}

	public PeerNode[][] getNodesSayBlown() {
		List<PeerNode> nodesConnectedSayRevoked = new ArrayList<>();
		List<PeerNode> nodesDisconnectedSayRevoked = new ArrayList<>();
		List<PeerNode> nodesFailedSayRevoked = new ArrayList<>();
		synchronized (this) {
			PeerNode[] nodesSayRevoked = this.nodesSayKeyRevoked.toArray(new PeerNode[0]);
			for (PeerNode pn : nodesSayRevoked) {
				if (this.nodesSayKeyRevokedFailedTransfer.contains(pn)) {
					nodesFailedSayRevoked.add(pn);
				}
				else {
					nodesConnectedSayRevoked.add(pn);
				}
			}
		}
		for (int i = 0; i < nodesConnectedSayRevoked.size(); i++) {
			PeerNode pn = nodesConnectedSayRevoked.get(i);
			if (!pn.isConnected()) {
				nodesDisconnectedSayRevoked.add(pn);
				nodesConnectedSayRevoked.remove(i);
				i--;
			}
		}
		return new PeerNode[][] { nodesConnectedSayRevoked.toArray(new PeerNode[0]),
				nodesDisconnectedSayRevoked.toArray(new PeerNode[0]), nodesFailedSayRevoked.toArray(new PeerNode[0]), };
	}

	/**
	 * A peer node requests us to send the binary blob of the revocation key.
	 * @param m The message requesting the transfer.
	 * @param source The node requesting the transfer.
	 * @return True if we handled the message (i.e. always).
	 */
	public boolean handleRequestRevocationManifest(Message m, final PeerNode source) {
		// Do we have the data?

		final RandomAccessBuffer data = this.updateManager.revocationChecker.getBlobBuffer();

		if (data == null) {
			Logger.normal(this,
					"Peer " + source + " asked us for the blob file for the revocation key but we don't have it!");
			// Probably a race condition on reconnect, hopefully we'll be asked again
			return true;
		}

		final long uid = m.getLong(DMT.UID);

		final PartiallyReceivedBulk prb;
		long length;
		length = data.size();
		prb = new PartiallyReceivedBulk(this.updateManager.node.getUSM(), length, Node.PACKET_SIZE, data, true);

		final BulkTransmitter bt;
		try {
			bt = new BulkTransmitter(prb, source, uid, false, this.updateManager.ctr, true);
		}
		catch (DisconnectedException ex) {
			Logger.error(this,
					"Peer " + source + " asked us for the blob file for the revocation key, then disconnected: " + ex,
					ex);
			data.close();
			return true;
		}

		final Runnable r = new Runnable() {

			@Override
			public void run() {
				try {
					if (!bt.send()) {
						Logger.error(this, "Failed to send revocation key blob to " + source.userToString() + " : "
								+ bt.getCancelReason());
					}
					else {
						Logger.normal(this, "Sent revocation key blob to " + source.userToString());
					}
				}
				catch (DisconnectedException ignored) {
					// Not much we can do here either.
					Logger.warning(this, "Failed to send revocation key blob (disconnected) to " + source.userToString()
							+ " : " + bt.getCancelReason());
				}
				finally {
					data.close();
				}
			}
		};

		Message msg = DMT.createUOMSendingRevocationManifest(uid, length,
				this.updateManager.getRevocationURI().toString());

		try {
			source.sendAsync(msg, new AsyncMessageCallback() {

				@Override
				public void acknowledged() {
					if (logMINOR) {
						Logger.minor(this, "Sending data...");
					}
					// Send the data
					UpdateOverMandatoryManager.this.updateManager.node.executor.execute(r,
							"Revocation key send for " + uid + " to " + source.userToString());
				}

				@Override
				public void disconnected() {
					// Argh
					Logger.error(this, "Peer " + source
							+ " asked us for the blob file for the revocation key, then disconnected when we tried to send the UOMSendingRevocation");
				}

				@Override
				public void fatalError() {
					// Argh
					Logger.error(this, "Peer " + source
							+ " asked us for the blob file for the revocation key, then got a fatal error when we tried to send the UOMSendingRevocation");
				}

				@Override
				public void sent() {
					if (logMINOR) {
						Logger.minor(this, "Message sent, data soon");
					}
				}

				@Override
				public String toString() {
					return super.toString() + "(" + uid + ":" + source.getPeer() + ")";
				}
			}, this.updateManager.ctr);
		}
		catch (NotConnectedException ex) {
			Logger.error(this, "Peer " + source
					+ " asked us for the blob file for the revocation key, then disconnected when we tried to send the UOMSendingRevocation: "
					+ ex, ex);
			return true;
		}

		return true;
	}

	public boolean handleSendingRevocationManifest(Message m, final PeerNode source) {
		final long uid = m.getLong(DMT.UID);
		final long length = m.getLong(DMT.FILE_LENGTH);
		String key = m.getString(DMT.REVOCATION_KEY);

		FreenetURI revocationURI;
		try {
			revocationURI = new FreenetURI(key);
		}
		catch (MalformedURLException ex) {
			Logger.error(this, "Failed receiving recovation because URI not parsable: " + ex + " for " + key, ex);
			System.err.println("Failed receiving recovation because URI not parsable: " + ex + " for " + key);
			ex.printStackTrace();
			synchronized (this) {
				// Wierd case of a failed transfer
				// This is definitely not valid, don't add to
				// nodesSayKeyRevokedFailedTransfer.
				this.nodesSayKeyRevoked.remove(source);
				this.nodesSayKeyRevokedTransferring.remove(source);
			}
			this.cancelSend(source, uid);
			this.maybeNotRevoked();
			return true;
		}

		if (!revocationURI.equals(this.updateManager.getRevocationURI())) {
			System.err.println("Node sending us a revocation certificate from the wrong URI:\n" + "Node: "
					+ source.userToString() + "\n" + "Our   URI: " + this.updateManager.getRevocationURI() + "\n"
					+ "Their URI: " + revocationURI);
			synchronized (this) {
				// Wierd case of a failed transfer
				this.nodesSayKeyRevoked.remove(source);
				// This is definitely not valid, don't add to
				// nodesSayKeyRevokedFailedTransfer.
				this.nodesSayKeyRevokedTransferring.remove(source);
			}
			this.cancelSend(source, uid);
			this.maybeNotRevoked();
			return true;
		}

		if (this.updateManager.isBlown()) {
			if (logMINOR) {
				Logger.minor(this, "Already blown, so not receiving from " + source + "(" + uid + ")");
			}
			this.cancelSend(source, uid);
			return true;
		}

		if (length > NodeUpdateManager.MAX_REVOCATION_KEY_BLOB_LENGTH) {
			System.err.println("Node " + source.userToString() + " offered us a revocation certificate "
					+ SizeUtil.formatSize(length)
					+ " long. This is unacceptably long so we have refused the transfer. No real revocation cert would be this big.");
			Logger.error(this, "Node " + source.userToString() + " offered us a revocation certificate "
					+ SizeUtil.formatSize(length)
					+ " long. This is unacceptably long so we have refused the transfer. No real revocation cert would be this big.");
			synchronized (UpdateOverMandatoryManager.this) {
				this.nodesSayKeyRevoked.remove(source);
				this.nodesSayKeyRevokedTransferring.remove(source);
			}
			this.cancelSend(source, uid);
			this.maybeNotRevoked();
			return true;
		}

		if (length <= 0) {
			System.err.println("Revocation key is zero bytes from " + source
					+ " - ignoring as this is almost certainly a bug or an attack, it is definitely not valid.");
			synchronized (UpdateOverMandatoryManager.this) {
				this.nodesSayKeyRevoked.remove(source);
				// This is almost certainly not valid, don't add to
				// nodesSayKeyRevokedFailedTransfer.
				this.nodesSayKeyRevokedTransferring.remove(source);
			}
			this.cancelSend(source, uid);
			this.maybeNotRevoked();
			return true;
		}

		System.err.println("Transferring auto-updater revocation certificate length " + length + " from " + source);

		// Okay, we can receive it

		final File temp;

		try {
			temp = File.createTempFile("revocation-", ".fblob.tmp",
					this.updateManager.node.clientCore.getPersistentTempDir());
			temp.deleteOnExit();
		}
		catch (IOException ex) {
			System.err.println(
					"Cannot save revocation certificate to disk and therefore cannot fetch it from our peer!: " + ex);
			ex.printStackTrace();
			this.updateManager.blow(
					"Cannot fetch the revocation certificate from our peer because we cannot write it to disk: " + ex,
					true);
			this.cancelSend(source, uid);
			return true;
		}

		FileRandomAccessBuffer raf;
		try {
			raf = new FileRandomAccessBuffer(temp, length, false);
		}
		catch (FileNotFoundException ex) {
			Logger.error(this, "Peer " + source
					+ " asked us for the blob file for the revocation key, we have downloaded it but don't have the file even though we did have it when we checked!: "
					+ ex, ex);
			this.updateManager.blow(
					"Internal error after fetching the revocation certificate from our peer, maybe out of disk space, file disappeared "
							+ temp + " : " + ex,
					true);
			return true;
		}
		catch (IOException ex) {
			Logger.error(this, "Peer " + source
					+ " asked us for the blob file for the revocation key, we have downloaded it but now can't read the file due to a disk I/O error: "
					+ ex, ex);
			this.updateManager.blow(
					"Internal error after fetching the revocation certificate from our peer, maybe out of disk space or other disk I/O error, file disappeared "
							+ temp + " : " + ex,
					true);
			return true;
		}

		// It isn't starting, it's transferring.
		synchronized (this) {
			this.nodesSayKeyRevokedTransferring.add(source);
			this.nodesSayKeyRevoked.remove(source);
		}

		PartiallyReceivedBulk prb = new PartiallyReceivedBulk(this.updateManager.node.getUSM(), length,
				Node.PACKET_SIZE, raf, false);

		final BulkReceiver br = new BulkReceiver(prb, source, uid, this.updateManager.ctr);

		this.updateManager.node.executor.execute(new Runnable() {

			@Override
			public void run() {
				try {
					if (br.receive()) {
						// Success!
						UpdateOverMandatoryManager.this.processRevocationBlob(temp, source);
					}
					else {
						Logger.error(this, "Failed to transfer revocation certificate from " + source);
						System.err.println("Failed to transfer revocation certificate from " + source);
						source.failedRevocationTransfer();
						int count = source.countFailedRevocationTransfers();
						boolean retry = count < 3;
						synchronized (UpdateOverMandatoryManager.this) {
							UpdateOverMandatoryManager.this.nodesSayKeyRevokedFailedTransfer.add(source);
							UpdateOverMandatoryManager.this.nodesSayKeyRevokedTransferring.remove(source);
							if (retry) {
								if (UpdateOverMandatoryManager.this.nodesSayKeyRevoked.contains(source)) {
									retry = false;
								}
								else {
									UpdateOverMandatoryManager.this.nodesSayKeyRevoked.add(source);
								}
							}
						}
						UpdateOverMandatoryManager.this.maybeNotRevoked();
						if (retry) {
							UpdateOverMandatoryManager.this.tryFetchRevocation(source);
						}
					}
				}
				catch (Throwable ex) {
					Logger.error(this,
							"Caught error while transferring revocation certificate from " + source + " : " + ex, ex);
					System.err.println("Peer " + source
							+ " said that the revocation key has been blown, but we got an internal error while transferring it:");
					ex.printStackTrace();
					UpdateOverMandatoryManager.this.updateManager
							.blow("Internal error while fetching the revocation certificate from our peer " + source
									+ " : " + ex, true);
					synchronized (UpdateOverMandatoryManager.this) {
						UpdateOverMandatoryManager.this.nodesSayKeyRevokedTransferring.remove(source);
					}
				}
			}
		}, "Revocation key receive for " + uid + " from " + source.userToString());

		return true;
	}

	protected void maybeNotRevoked() {
		synchronized (this) {
			if (!this.updateManager.peersSayBlown()) {
				return;
			}
			if (this.mightBeRevoked()) {
				return;
			}
			this.updateManager.notPeerClaimsKeyBlown();
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

	void processRevocationBlob(final File temp, PeerNode source) {
		this.processRevocationBlob(new FileBucket(temp, true, false, false, true), source.userToString(), false);
	}

	/**
	 * Process a binary blob for a revocation certificate (the revocation key).
	 * @param temp The file it was written to.
	 */
	void processRevocationBlob(final Bucket temp, final String source, final boolean fromDisk) {

		SimpleBlockSet blocks = new SimpleBlockSet();

		try (DataInputStream dis = new DataInputStream(temp.getInputStream())) {
			BinaryBlob.readBinaryBlob(dis, blocks, true);
		}
		catch (FileNotFoundException ex) {
			Logger.error(this,
					"Somebody deleted " + temp + " ? We lost the revocation certificate from " + source + "!");
			System.err
					.println("Somebody deleted " + temp + " ? We lost the revocation certificate from " + source + "!");
			if (!fromDisk) {
				this.updateManager.blow(
						"Somebody deleted " + temp + " ? We lost the revocation certificate from " + source + "!",
						true);
			}
			return;
		}
		catch (EOFException ex) {
			Logger.error(this,
					"Peer " + source
							+ " sent us an invalid revocation certificate! (data too short, might be truncated): " + ex
							+ " (data in " + temp + ")",
					ex);
			System.err.println("Peer " + source
					+ " sent us an invalid revocation certificate! (data too short, might be truncated): " + ex
					+ " (data in " + temp + ")");
			// Probably malicious, might just be buggy, either way, it's not blown
			ex.printStackTrace();
			// FIXME file will be kept until exit for debugging purposes
			return;
		}
		catch (BinaryBlobFormatException ex) {
			Logger.error(this,
					"Peer " + source + " sent us an invalid revocation certificate!: " + ex + " (data in " + temp + ")",
					ex);
			System.err.println("Peer " + source + " sent us an invalid revocation certificate!: " + ex + " (data in "
					+ temp + ")");
			// Probably malicious, might just be buggy, either way, it's not blown
			ex.printStackTrace();
			// FIXME file will be kept until exit for debugging purposes
			return;
		}
		catch (IOException ex) {
			Logger.error(this,
					"Could not read revocation cert from temp file " + temp + " from node " + source + " ! : " + ex,
					ex);
			System.err.println(
					"Could not read revocation cert from temp file " + temp + " from node " + source + " ! : " + ex);
			ex.printStackTrace();
			if (!fromDisk) {
				this.updateManager.blow(
						"Could not read revocation cert from temp file " + temp + " from node " + source + " ! : " + ex,
						true);
			}
			// FIXME will be kept until exit for debugging purposes
			return;
		}
		// Ignore

		// Fetch our revocation key from the datastore plus the binary blob

		FetchContext seedContext = this.updateManager.node.clientCore.makeClient((short) 0, true, false)
				.getFetchContext();
		FetchContext tempContext = new FetchContext(seedContext, FetchContext.IDENTICAL_MASK, true, blocks);
		// If it is too big, we get a TOO_BIG. This is fatal so we will blow, which is the
		// right thing as it means the top block is valid.
		tempContext.maxOutputLength = NodeUpdateManager.MAX_REVOCATION_KEY_LENGTH;
		tempContext.maxTempLength = NodeUpdateManager.MAX_REVOCATION_KEY_TEMP_LENGTH;
		tempContext.localRequestOnly = true;

		final ArrayBucket cleanedBlob = new ArrayBucket();

		ClientGetCallback myCallback = new ClientGetCallback() {

			@Override
			public void onFailure(FetchException e, ClientGetter state) {
				if (e.mode == FetchExceptionMode.CANCELLED) {
					// Eh?
					Logger.error(this, "Cancelled fetch from store/blob of revocation certificate from " + source);
					System.err.println("Cancelled fetch from store/blob of revocation certificate from " + source
							+ " to " + temp + " - please report to developers");
					// Probably best to keep files around for now.
				}
				else if (e.isFatal()) {
					// Blown: somebody inserted a revocation message, but it was corrupt
					// as inserted
					// However it had valid signatures etc.

					System.err.println("Got revocation certificate from " + source
							+ " (fatal error i.e. someone with the key inserted bad data) : " + e);
					// Blow the update, and propagate the revocation certificate.
					UpdateOverMandatoryManager.this.updateManager.revocationChecker.onFailure(e, state, cleanedBlob);
					// Don't delete it if it's from disk, as it's already in the right
					// place.
					if (!fromDisk) {
						temp.free();
					}

					UpdateOverMandatoryManager.this.insertBlob(
							UpdateOverMandatoryManager.this.updateManager.revocationChecker.getBlobBucket(),
							"revocation", PriorityClasses.INTERACTIVE_PRIORITY_CLASS);
				}
				else {
					String message = "Failed to fetch revocation certificate from blob from " + source + " : " + e
							+ (fromDisk ? " : did you change the revocation key?"
									: " : this is almost certainly bogus i.e. the auto-update is fine but the node is broken.");
					Logger.error(this, message);
					System.err.println(message);
					// This is almost certainly bogus.
					// Delete it, even if it's fromDisk.
					temp.free();
					cleanedBlob.free();
				}
			}

			@Override
			public void onSuccess(FetchResult result, ClientGetter state) {
				System.err.println("Got revocation certificate from " + source);
				UpdateOverMandatoryManager.this.updateManager.revocationChecker.onSuccess(result, state, cleanedBlob);
				if (!fromDisk) {
					temp.free();
				}
				UpdateOverMandatoryManager.this.insertBlob(
						UpdateOverMandatoryManager.this.updateManager.revocationChecker.getBlobBucket(), "revocation",
						PriorityClasses.INTERACTIVE_PRIORITY_CLASS);
			}

			@Override
			public void onResume(ClientContext context) {
				// Not persistent.
			}

			@Override
			public RequestClient getRequestClient() {
				return UpdateOverMandatoryManager.this;
			}
		};

		ClientGetter cg = new ClientGetter(myCallback, this.updateManager.getRevocationURI(), tempContext, (short) 0,
				null, new BinaryBlobWriter(cleanedBlob), null);

		try {
			this.updateManager.node.clientCore.clientContext.start(cg);
		}
		catch (FetchException e1) {
			System.err.println("Failed to decode UOM blob: " + e1);
			e1.printStackTrace();
			myCallback.onFailure(e1, cg);
		}
		catch (PersistenceDisabledException ignored) {
			// Impossible
		}

	}

	protected void insertBlob(final RandomAccessBucket bucket, final String type, short priority) {
		ClientPutCallback callback = new ClientPutCallback() {

			@Override
			public void onFailure(InsertException e, BaseClientPutter state) {
				Logger.error(this, "Failed to insert " + type + " binary blob: " + e, e);
			}

			@Override
			public void onFetchable(BaseClientPutter state) {
				// Ignore
			}

			@Override
			public void onGeneratedURI(FreenetURI uri, BaseClientPutter state) {
				// Ignore
			}

			@Override
			public void onSuccess(BaseClientPutter state) {
				// All done. Cool.
				Logger.normal(this, "Inserted " + type + " binary blob");
			}

			@Override
			public void onGeneratedMetadata(Bucket metadata, BaseClientPutter state) {
				Logger.error(this, "Got onGeneratedMetadata inserting blob from " + state, new Exception("error"));
				metadata.free();
			}

			@Override
			public void onResume(ClientContext context) {
				// Not persistent.
			}

			@Override
			public RequestClient getRequestClient() {
				return UpdateOverMandatoryManager.this;
			}

		};
		// We are inserting a binary blob so we don't need to worry about
		// CompatibilityMode etc.
		InsertContext ctx = this.updateManager.node.clientCore
				.makeClient(PriorityClasses.INTERACTIVE_PRIORITY_CLASS, false, false).getInsertContext(true);
		ClientPutter putter = new ClientPutter(callback, bucket, FreenetURI.EMPTY_CHK_URI, null, ctx, priority, false,
				null, true, this.updateManager.node.clientCore.clientContext, null, -1);
		try {
			this.updateManager.node.clientCore.clientContext.start(putter);
		}
		catch (InsertException e1) {
			Logger.error(this, "Failed to start insert of " + type + " binary blob: " + e1, e1);
		}
		catch (PersistenceDisabledException ignored) {
			// Impossible
		}
	}

	private void cancelSend(PeerNode source, long uid) {
		Message msg = DMT.createFNPBulkReceiveAborted(uid);
		try {
			source.sendAsync(msg, null, this.updateManager.ctr);
		}
		catch (NotConnectedException e1) {
			// Ignore
		}
	}

	public void killAlert() {
		this.updateManager.node.clientCore.alerts.unregister(this.alert);
	}

	public boolean handleSendingManifest(Message m, final PeerNode source) {
		final long uid = m.getLong(DMT.UID);
		final long length = m.getLong(DMT.FILE_LENGTH);
		String key = m.getString(DMT.UPDATE_FILE_KEY);
		final int version = m.getInt(DMT.UPDATE_FILE_VERSION);
		final FreenetURI manifestURI;
		try {
			manifestURI = new FreenetURI(key).setSuggestedEdition(version);
		}
		catch (MalformedURLException ex) {
			Logger.error(this,
					"Failed receiving manifest " + version + " because URI not parsable: " + ex + " for " + key, ex);
			System.err.println(
					"Failed receiving manifest " + version + " because URI not parsable: " + ex + " for " + key);
			ex.printStackTrace();
			this.cancelSend(source, uid);
			synchronized (this) {
				this.nodesAskedSendManifest.remove(source);
			}
			return true;
		}

		if (!manifestURI.equals(this.updateManager.getUpdateURI().setSuggestedEdition(version))) {
			System.err.println("Node sending us a manifest update (" + version + ") from the wrong URI:\n" + "Node: "
					+ source.userToString() + "\n" + "Our   URI: " + this.updateManager.getUpdateURI() + "\n"
					+ "Their URI: " + manifestURI);
			this.cancelSend(source, uid);
			synchronized (this) {
				this.nodesAskedSendManifest.remove(source);
			}
			return true;
		}

		if (this.updateManager.isBlown()) {
			if (logMINOR) {
				Logger.minor(this, "Key blown, so not receiving manifest from " + source + "(" + uid + ")");
			}
			this.cancelSend(source, uid);
			synchronized (this) {
				this.nodesAskedSendManifest.remove(source);
			}
			return true;
		}

		if (length > ManifestUSKUpdateFileFetcher.MAX_MANIFEST_LENGTH) {
			System.err.println("Node " + source.userToString() + " offered us a manifest (" + version + ") "
					+ SizeUtil.formatSize(length)
					+ " long. This is unacceptably long so we have refused the transfer.");
			Logger.error(this,
					"Node " + source.userToString() + " offered us a manifest (" + version + ") "
							+ SizeUtil.formatSize(length)
							+ " long. This is unacceptably long so we have refused the transfer.");
			// If the transfer fails, we don't try again.
			this.cancelSend(source, uid);
			synchronized (this) {
				this.nodesAskedSendManifest.remove(source);
			}
			return true;
		}

		// Okay, we can receive it
		System.out.println("Receiving manifest " + version + " from " + source.userToString());

		final File temp;

		try {
			temp = File.createTempFile("manifest-", ".fblob.tmp",
					this.updateManager.node.clientCore.getPersistentTempDir());
			temp.deleteOnExit();
		}
		catch (IOException ex) {
			System.err.println("Cannot save new manifest to disk and therefore cannot fetch it from our peer!: " + ex);
			ex.printStackTrace();
			this.cancelSend(source, uid);
			synchronized (this) {
				this.nodesAskedSendManifest.remove(source);
			}
			return true;
		}

		FileRandomAccessBuffer raf;
		try {
			raf = new FileRandomAccessBuffer(temp, length, false);
		}
		catch (IOException ex) {
			Logger.error(this, "Peer " + source + " sending us a manifest binary blob, but we "
					+ ((ex instanceof FileNotFoundException) ? "lost the temp file " : "cannot read the temp file ")
					+ temp + " : " + ex, ex);
			synchronized (this) {
				this.nodesAskedSendManifest.remove(source);
			}
			return true;
		}

		PartiallyReceivedBulk prb = new PartiallyReceivedBulk(this.updateManager.node.getUSM(), length,
				Node.PACKET_SIZE, raf, false);

		final BulkReceiver br = new BulkReceiver(prb, source, uid, this.updateManager.ctr);

		this.updateManager.node.executor.execute(new Runnable() {

			@Override
			public void run() {
				boolean success = false;
				try {
					synchronized (UpdateOverMandatoryManager.class) {
						UpdateOverMandatoryManager.this.nodesAskedSendManifest.remove(source);
						UpdateOverMandatoryManager.this.nodesSendingManifest.add(source);
					}
					success = br.receive();
					if (success) {
						// Success!
						UpdateOverMandatoryManager.this.processManifestBlob(temp, source, version, manifestURI);
					}
					else {
						Logger.error(this, "Failed to transfer manifest " + version + " from " + source);
						System.err.println("Failed to transfer manifest " + version + " from " + source);
						// noinspection ResultOfMethodCallIgnored
						temp.delete();
					}
				}
				finally {
					synchronized (UpdateOverMandatoryManager.class) {
						UpdateOverMandatoryManager.this.nodesSendingManifest.remove(source);
						if (success) {
							UpdateOverMandatoryManager.this.nodesSentManifest.add(source);
						}
					}
				}
			}
		}, "Manifest (" + version + ") receive for " + uid + " from " + source.userToString());

		return true;
	}

	protected void processManifestBlob(final File temp, final PeerNode source, final int version, FreenetURI uri) {
		SimpleBlockSet blocks = new SimpleBlockSet();
		final String peer = (source != null) ? source.userToString() : "(local)";

		try (DataInputStream dis = new DataInputStream(new BufferedInputStream(new FileInputStream(temp)))) {
			BinaryBlob.readBinaryBlob(dis, blocks, true);
		}
		catch (FileNotFoundException ex) {
			Logger.error(this,
					"Somebody deleted " + temp + " ? We lost the manifest (" + version + ") from " + peer + "!");
			System.err.println(
					"Somebody deleted " + temp + " ? We lost the manifest (" + version + ") from " + peer + "!");
			return;
		}
		catch (IOException ex) {
			Logger.error(this,
					"Could not read manifest (" + version + ") from temp file " + temp + " from node " + peer + " !");
			System.err.println(
					"Could not read manifest (" + version + ") from temp file " + temp + " from node " + peer + " !");
			// FIXME will be kept until exit for debugging purposes
			return;
		}
		catch (BinaryBlobFormatException ex) {
			Logger.error(this, "Peer " + peer + " sent us an invalid manifest (" + version + ")!: " + ex, ex);
			System.err.println("Peer " + peer + " sent us an invalid manifest (" + version + ")!: " + ex);
			ex.printStackTrace();
			// FIXME will be kept until exit for debugging purposes
			return;
		}
		// Ignore

		// Fetch the manifest from the datastore plus the binary blob

		FetchContext seedContext = this.updateManager.node.clientCore.makeClient((short) 0, true, false)
				.getFetchContext();
		FetchContext tempContext = new FetchContext(seedContext, FetchContext.IDENTICAL_MASK, true, blocks);
		tempContext.localRequestOnly = true;

		File f;
		FileBucket b;
		try {
			f = File.createTempFile("manifest-", ".fblob.tmp",
					this.updateManager.node.clientCore.getPersistentTempDir());
			f.deleteOnExit();
			b = new FileBucket(f, false, false, true, true);
		}
		catch (IOException ex) {
			Logger.error(this, "Cannot share manifest from " + peer
					+ " with our peers because cannot write the cleaned version to disk: " + ex, ex);
			System.err.println("Cannot share manifest from " + peer
					+ " with our peers because cannot write the cleaned version to disk: " + ex);
			ex.printStackTrace();
			b = null;
			f = null;
		}
		final FileBucket cleanedBlob = b;
		final File cleanedBlobFile = f;

		ClientGetCallback myCallback = new ClientGetCallback() {

			@SuppressWarnings("ResultOfMethodCallIgnored")
			@Override
			public void onFailure(FetchException e, ClientGetter state) {
				if (e.mode == FetchExceptionMode.CANCELLED) {
					// Eh?
					Logger.error(this, "Cancelled fetch from store/blob of manifest (" + version + ") from " + peer);
					System.err.println("Cancelled fetch from store/blob of manifest (" + version + ") from " + peer
							+ " to " + temp + " - please report to developers");
					// Probably best to keep files around for now.
				}
				else if (e.newURI != null) {
					temp.delete();
					Logger.error(this, "URI changed fetching manifest " + version + " from " + peer);
					System.out.println("URI changed fetching manifest " + version + " from " + peer);
				}
				else if (e.isFatal()) {
					// Bogus as inserted. Ignore.
					temp.delete();
					Logger.error(this, "Failed to fetch manifest " + version + " from " + peer
							+ " : fatal error (update was probably inserted badly): " + e, e);
					System.err.println("Failed to fetch manifest " + version + " from " + peer
							+ " : fatal error (update was probably inserted badly): " + e);
				}
				else {
					Logger.error(this, "Failed to fetch manifest " + version + " from blob from " + peer);
					System.err.println("Failed to fetch manifest " + version + " from blob from " + peer);
				}
			}

			@Override
			public void onSuccess(FetchResult result, ClientGetter state) {
				System.err.println("Got manifest version " + version + " from " + peer);
				if (result.size() == 0) {
					System.err.println("Ignoring because 0 bytes long");
					return;
				}

				EventBus.get()
						.post(new UOMManifestRequestSuccessEvent(result, state, cleanedBlobFile, version, source));
				// noinspection ResultOfMethodCallIgnored
				temp.delete();
			}

			@Override
			public void onResume(ClientContext context) {
				// Not persistent.
			}

			@Override
			public RequestClient getRequestClient() {
				return UpdateOverMandatoryManager.this;
			}

		};

		ClientGetter cg = new ClientGetter(myCallback, uri, tempContext, (short) 0, null,
				new BinaryBlobWriter(cleanedBlob), null);

		try {
			this.updateManager.node.clientCore.clientContext.start(cg);
		}
		catch (FetchException e1) {
			myCallback.onFailure(e1, cg);
		}
		catch (PersistenceDisabledException ignored) {
			// Impossible
		}

	}

	protected void maybeProcessOldBlob(File oldBlob, FreenetURI uri, int currentVersion) {

		if (oldBlob.exists()) {
			File temp;
			try {
				temp = File.createTempFile("manifest" + currentVersion + "-", ".fblob.tmp",
						this.updateManager.node.clientCore.getPersistentTempDir());
			}
			catch (IOException ex) {
				Logger.error(this, "Unable to process old blob: " + ex, ex);
				return;
			}
			if (oldBlob.renameTo(temp)) {
				uri = uri.sskForUSK();
				try {
					this.processManifestBlob(temp, null, currentVersion, uri);
				}
				catch (Throwable ex) {
					// Don't disrupt startup.
					Logger.error(this, "Unable to process old blob, caught " + ex, ex);
				}
				// noinspection ResultOfMethodCallIgnored
				temp.delete();
			}
			else {
				Logger.error(this,
						"Unable to rename old blob file " + oldBlob + " to " + temp + " so can't process it.");
			}
		}

	}

	@SuppressWarnings("UnusedReturnValue")
	protected boolean removeOldTempFiles() {
		File oldTempFilesPeerDir = this.updateManager.node.clientCore.getPersistentTempDir();
		if (!oldTempFilesPeerDir.exists()) {
			return false;
		}
		if (!oldTempFilesPeerDir.isDirectory()) {
			Logger.error(this,
					"Persistent temporary files location is not a directory: " + oldTempFilesPeerDir.getPath());
			return false;
		}

		boolean gotError = false;
		File[] oldTempFiles = oldTempFilesPeerDir.listFiles(new FileFilter() {

			private final int lastGoodMainBuildNumber = Version.lastGoodBuild();

			@Override
			public boolean accept(File file) {
				String fileName = file.getName();

				if (fileName.startsWith("revocation-") && fileName.endsWith(".fblob.tmp")) {
					return true;
				}

				String buildNumberStr;
				int buildNumber;
				Matcher mainBuildNumberMatcher = mainBuildNumberPattern.matcher(fileName);
				Matcher mainTempBuildNumberMatcher = mainTempBuildNumberPattern.matcher(fileName);
				Matcher revocationTempBuildNumberMatcher = revocationTempBuildNumberPattern.matcher(fileName);

				// Temporary file, can be deleted
				if (mainBuildNumberMatcher.matches()) {
					try {
						buildNumberStr = mainBuildNumberMatcher.group(1);
						buildNumber = Integer.parseInt(buildNumberStr);
						if (buildNumber < this.lastGoodMainBuildNumber) {
							return true;
						}
					}
					catch (NumberFormatException ex) {
						Logger.error(this, "Wierd file in persistent temp: " + fileName);
						return false;
					}
				}
				else {
					return mainTempBuildNumberMatcher.matches() || revocationTempBuildNumberMatcher.matches();
				}

				return false;
			}
		});

		if (oldTempFiles != null) {
			for (File fileToDelete : oldTempFiles) {
				String fileToDeleteName = fileToDelete.getName();
				if (!fileToDelete.delete()) {
					if (fileToDelete.exists()) {
						Logger.error(this, "Cannot delete temporary persistent file " + fileToDeleteName
								+ " even though it exists: must be TOO persistent :)");
					}
					else {
						Logger.normal(this,
								"Temporary persistent file does not exist when deleting: " + fileToDeleteName);
					}
					gotError = true;
				}
			}
		}
		else {
			Logger.error(this, "Failed to list temporary persistent files");
			gotError = true;
		}

		return !gotError;
	}

	@Override
	public boolean persistent() {
		return false;
	}

	public void disconnected(PeerNode pn) {
		synchronized (this) {
			this.nodesSayKeyRevoked.remove(pn);
			this.nodesSayKeyRevokedFailedTransfer.remove(pn);
			this.nodesSayKeyRevokedTransferring.remove(pn);
			this.nodesOfferedManifest.remove(pn);
			this.allNodesOfferedManifest.remove(pn);
			this.nodesSentManifest.remove(pn);
			this.nodesAskedSendManifest.remove(pn);
			this.nodesSendingManifest.remove(pn);
		}
		this.maybeNotRevoked();
	}

	public boolean fetchingFromTwo() {
		synchronized (this) {
			return (this.nodesSendingManifest.size()) >= 2;
		}
	}

	@Override
	public boolean realTimeFlag() {
		return false;
	}

	public boolean isFetchingMain() {
		synchronized (this) {
			return this.nodesSendingManifest.size() > 0;
		}
	}

	public void addDependency(byte[] expectedHash, File filename) {
		if (logMINOR) {
			Logger.minor(this, "Add dependency: " + filename + " for " + HexUtil.bytesToHex(expectedHash));
		}
		synchronized (this.dependencies) {
			this.dependencies.put(new ShortBuffer(expectedHash), filename);
		}
	}

	static final int MAX_TRANSFERS_PER_PEER = 2;

	public void handleFetchPackage(Message m, final PeerNode source) {
		File data;
		final ShortBuffer buf = (ShortBuffer) m.getObject(DMT.EXPECTED_HASH);
		long length = m.getLong(DMT.FILE_LENGTH);
		long uid = m.getLong(DMT.UID);
		synchronized (this.dependencies) {
			data = this.dependencies.get(buf);
		}
		boolean fail = !this.incrementDependencies(source);
		FileRandomAccessBuffer raf;
		final BulkTransmitter bt;

		try {
			if (data != null) {
				raf = new FileRandomAccessBuffer(data, true);
			}
			else {
				Logger.error(this, "Dependency with hash " + HexUtil.bytesToHex(buf.getData()) + " not found!");
				fail = true;
				raf = null;
			}
		}
		catch (IOException ex) {
			Logger.error(this,
					"Peer " + source + " asked us for the dependency with hash " + HexUtil.bytesToHex(buf.getData())
							+ " jar, we have downloaded it but "
							+ ((ex instanceof FileNotFoundException) ? "don't have the file" : "can't read the file")
							+ " even though we did have it when we checked!: " + ex,
					ex);
			raf = null;
			fail = true;
		}

		PartiallyReceivedBulk prb;
		if (raf != null) {
			long thisLength = raf.size();
			prb = new PartiallyReceivedBulk(this.updateManager.node.getUSM(), thisLength, Node.PACKET_SIZE, raf, true);
			if (length != thisLength) {
				fail = true;
			}
		}
		else {
			prb = new PartiallyReceivedBulk(this.updateManager.node.getUSM(), 0, Node.PACKET_SIZE,
					new ByteArrayRandomAccessBuffer(new byte[0]), true);
		}

		try {
			bt = new BulkTransmitter(prb, source, uid, false, this.updateManager.ctr, true);
		}
		catch (DisconnectedException ex) {
			Logger.error(this, "Peer " + source + " asked us for the dependency with hash "
					+ HexUtil.bytesToHex(buf.getData()) + " jar then disconnected", ex);
			if (raf != null) {
				raf.close();
			}
			this.decrementDependencies(source);
			return;
		}

		if (fail) {
			this.cancelSend(source, uid);
			this.decrementDependencies(source);
		}
		else {
			FileRandomAccessBuffer finalRaf = raf;
			this.updateManager.node.executor.execute(new Runnable() {

				@Override
				public void run() {
					source.incrementUOMSends();
					try (FileRandomAccessBuffer ignored = finalRaf) {
						bt.send();
					}
					catch (DisconnectedException ex) {
						Logger.normal(this, "Disconnected while sending dependency with hash "
								+ HexUtil.bytesToHex(buf.getData()) + " to " + source);
					}
					finally {
						source.decrementUOMSends();
						UpdateOverMandatoryManager.this.decrementDependencies(source);
					}
				}

			});
		}
	}

	private void decrementDependencies(PeerNode source) {
		synchronized (this.peersFetchingDependencies) {
			Integer x = this.peersFetchingDependencies.get(source);
			if (x == null) {
				Logger.error(this, "Inconsistent dependency counting? Should not be null for " + source);
			}
			else if (x == 1) {
				this.peersFetchingDependencies.remove(source);
			}
			else if (x <= 0) {
				Logger.error(this, "Inconsistent dependency counting? Counter is " + x + " for " + source);
				this.peersFetchingDependencies.remove(source);
			}
			else {
				this.peersFetchingDependencies.put(source, x - 1);
			}
		}
	}

	/**
	 * @return False if we cannot accept any more transfers from this node. True to accept
	 * the transfer.
	 */
	private boolean incrementDependencies(PeerNode source) {
		synchronized (this.peersFetchingDependencies) {
			Integer x = this.peersFetchingDependencies.get(source);
			if (x == null) {
				x = 0;
			}
			x++;
			if (x > MAX_TRANSFERS_PER_PEER) {
				Logger.normal(this, "Too many dependency transfers for peer " + source + " - rejecting");
				return false;
			}
			else {
				this.peersFetchingDependencies.put(source, x);
			}
			return true;
		}
	}

	boolean fetchingUOM() {
		return this.fetchingUOM;
	}

	/**
	 * Try to fetch a dependency by hash.
	 * @param expectedHash The hash of the expected file. Will be checked.
	 * @param size The length of the expected file.
	 * @param saveTo The file will be overwritten only if the download is successful and
	 * the hash is correct.
	 * @param cb Callback to call when done.
	 */
	public UOMDependencyFetcher fetchDependency(byte[] expectedHash, long size, File saveTo, boolean executable,
			UOMDependencyFetcherCallback cb) {
		final UOMDependencyFetcher f = new UOMDependencyFetcher(expectedHash, size, saveTo, executable, cb);
		synchronized (this) {
			this.dependencyFetchers.put(f.expectedHashBuffer, f);
		}
		this.updateManager.node.executor.execute(f::start);
		f.start();
		return f;
	}

	protected void startSomeDependencyFetchers() {
		UOMDependencyFetcher[] fetchers;
		synchronized (this) {
			fetchers = this.dependencyFetchers.values().toArray(new UOMDependencyFetcher[0]);
		}
		for (UOMDependencyFetcher f : fetchers) {
			f.start();
		}
	}

	/**
	 * A download succeeded from a peer. Reconsider all the other downloads that failed
	 * from it. E.g. when we have one darknet connection and a transfer fails due to a
	 * transfer glitch.
	 */
	protected void peerMaybeFreeAllSlots(PeerNode fetchFrom) {
		UOMDependencyFetcher[] fetchers;
		synchronized (this) {
			fetchers = this.dependencyFetchers.values().toArray(new UOMDependencyFetcher[0]);
		}
		for (UOMDependencyFetcher f : fetchers) {
			f.peerMaybeFreeSlots(fetchFrom);
		}
	}

	final class UOMDependencyFetcher {

		final byte[] expectedHash;

		final ShortBuffer expectedHashBuffer;

		final long size;

		final File saveTo;

		final boolean executable;

		private boolean completed;

		private final UOMDependencyFetcherCallback cb;

		private final WeakHashSet<PeerNode> peersFailed;

		private final HashSet<PeerNode> peersFetching;

		private UOMDependencyFetcher(byte[] expectedHash, long size, File saveTo, boolean executable,
				UOMDependencyFetcherCallback callback) {
			this.expectedHash = expectedHash;
			this.expectedHashBuffer = new ShortBuffer(expectedHash);
			this.size = size;
			this.executable = executable;
			this.saveTo = saveTo;
			this.cb = callback;
			this.peersFailed = new WeakHashSet<>();
			this.peersFetching = new HashSet<>();
		}

		/** If a transfer has failed from this peer, retry it. */
		private void peerMaybeFreeSlots(PeerNode fetchFrom) {
			synchronized (this) {
				if (!this.peersFailed.remove(fetchFrom)) {
					return;
				}
				if (this.completed) {
					return;
				}
			}
			this.start();
		}

		private boolean maybeFetch() {
			boolean tryEverything = false;
			PeerNode chosen;
			while (true) {
				synchronized (this) {
					if (this.peersFetching.size() >= MAX_NODES_SENDING_MANIFEST) {
						if (logMINOR) {
							Logger.minor(this, "Already fetching jar from 2 peers " + this.peersFetching);
						}
						return false;
					}
					if (this.completed) {
						return false;
					}
				}
				HashSet<PeerNode> uomPeers;
				synchronized (UpdateOverMandatoryManager.this) {
					uomPeers = new HashSet<>(UpdateOverMandatoryManager.this.nodesSentManifest);
				}
				chosen = this.chooseRandomPeer(uomPeers);
				if (chosen != null) {
					break;
				}
				synchronized (UpdateOverMandatoryManager.this) {
					uomPeers = new HashSet<>(UpdateOverMandatoryManager.this.nodesSendingManifest);
				}
				chosen = this.chooseRandomPeer(uomPeers);
				if (chosen != null) {
					break;
				}
				synchronized (UpdateOverMandatoryManager.this) {
					uomPeers = new HashSet<>(UpdateOverMandatoryManager.this.allNodesOfferedManifest);
				}
				chosen = this.chooseRandomPeer(uomPeers);
				if (chosen != null) {
					break;
				}
				if (tryEverything) {
					Logger.minor(this, "Could not find a peer to send request to for " + this.saveTo);
					return false;
				}
				synchronized (this) {
					if (this.peersFailed.size() != 0) {
						System.out.println("UOM trying peers which have failed downloads for " + this.saveTo.getName()
								+ " because nowhere else to go ...");
						this.peersFailed.clear();
						tryEverything = true;
					}
				}
				if (!tryEverything) {
					Logger.minor(this, "Could not find a peer to send request to for " + this.saveTo);
					return false;
				}
			}

			final PeerNode fetchFrom = chosen;
			UpdateOverMandatoryManager.this.updateManager.node.executor.execute(new Runnable() {

				@Override
				public void run() {
					boolean failed = false;
					File tmp = null;
					FileRandomAccessBuffer raf = null;
					try {
						System.out.println("Fetching " + UOMDependencyFetcher.this.saveTo + " from " + fetchFrom);
						long uid = UpdateOverMandatoryManager.this.updateManager.node.fastWeakRandom.nextLong();
						fetchFrom.sendAsync(
								DMT.createUOMFetchPackage(uid, UOMDependencyFetcher.this.expectedHash,
										UOMDependencyFetcher.this.size),
								null, UpdateOverMandatoryManager.this.updateManager.ctr);
						tmp = FileUtil.createTempFile(UOMDependencyFetcher.this.saveTo.getName(),
								NodeUpdateManager.TEMP_FILE_SUFFIX, UOMDependencyFetcher.this.saveTo.getParentFile());
						raf = new FileRandomAccessBuffer(tmp, UOMDependencyFetcher.this.size, false);
						PartiallyReceivedBulk prb = new PartiallyReceivedBulk(
								UpdateOverMandatoryManager.this.updateManager.node.getUSM(),
								UOMDependencyFetcher.this.size, Node.PACKET_SIZE, raf, false);
						BulkReceiver br = new BulkReceiver(prb, fetchFrom, uid,
								UpdateOverMandatoryManager.this.updateManager.ctr);
						failed = !br.receive();
						raf.close();
						raf = null;
						if (!failed) {
							// Check the hash.
							if (MainJarDependenciesChecker.validFile(tmp, UOMDependencyFetcher.this.expectedHash,
									UOMDependencyFetcher.this.size, UOMDependencyFetcher.this.executable)) {
								if (FileUtil.renameTo(tmp, UOMDependencyFetcher.this.saveTo)) {
									synchronized (UOMDependencyFetcher.this) {
										if (UOMDependencyFetcher.this.completed) {
											return;
										}
										UOMDependencyFetcher.this.completed = true;
									}
									synchronized (UpdateOverMandatoryManager.this) {
										UpdateOverMandatoryManager.this.dependencyFetchers
												.remove(UOMDependencyFetcher.this.expectedHashBuffer);
									}
									UOMDependencyFetcher.this.cb.onSuccess();
								}
								else {
									synchronized (UOMDependencyFetcher.this) {
										if (UOMDependencyFetcher.this.completed) {
											return;
										}
									}
									failed = true;
									System.err.println("Update failing: Saved dependency to " + tmp + " for "
											+ UOMDependencyFetcher.this.saveTo
											+ " but cannot rename it! Permissions problems?");
								}
								UpdateOverMandatoryManager.this.peerMaybeFreeAllSlots(fetchFrom);
							}
							else {
								synchronized (UOMDependencyFetcher.this) {
									if (UOMDependencyFetcher.this.completed) {
										return;
									}
								}
								failed = true;
								System.err.println("Update failing: Downloaded file " + UOMDependencyFetcher.this.saveTo
										+ " from " + fetchFrom + " but file does not match expected hash.");
								// Wrong length -> transfer would have failed.
							}
						}
						else {
							System.out.println(
									"Download failed: " + UOMDependencyFetcher.this.saveTo + " from " + fetchFrom);
						}
					}
					catch (NotConnectedException ex) {
						// Not counting this as a failure.
						System.out.println("Disconnected while downloading " + UOMDependencyFetcher.this.saveTo
								+ " from " + fetchFrom);
					}
					catch (IOException ex) {
						// This isn't their fault either.
						// User might be able to understand and fix this.
						System.out.println("IOException while downloading " + UOMDependencyFetcher.this.saveTo
								+ " from " + fetchFrom + " : " + ex);
						Logger.error(this, "IOException while downloading " + UOMDependencyFetcher.this.saveTo
								+ " from " + fetchFrom + " : " + ex, ex);
					}
					catch (RuntimeException | Error ex) {
						Logger.error(this, "Caught fetching " + UOMDependencyFetcher.this.saveTo + " from " + fetchFrom
								+ " : " + ex, ex);
						System.err.println("Fetch failed due to internal error (bug or severe local problem?): " + ex);
						ex.printStackTrace();
					}
					finally {
						boolean connected = fetchFrom.isConnected();
						boolean addFailed = failed && connected;
						synchronized (UOMDependencyFetcher.this) {
							if (addFailed) {
								UOMDependencyFetcher.this.peersFailed.add(fetchFrom);
							}
							UOMDependencyFetcher.this.peersFetching.remove(fetchFrom);
						}
						Closer.close(raf);
						if (tmp != null) {
							// noinspection ResultOfMethodCallIgnored
							tmp.delete();
						}
						if (failed) {
							UOMDependencyFetcher.this.start();
							if (fetchFrom.isConnected() && fetchFrom.isDarknet()) {
								// Darknet peers only: Try again in an hour.
								// On opennet we'll just keep announcing until we succeed.
								UpdateOverMandatoryManager.this.updateManager.node.getTicker().queueTimedJob(
										() -> UOMDependencyFetcher.this.peerMaybeFreeSlots(fetchFrom),
										TimeUnit.HOURS.toMillis(1));
							}
						}
					}
				}

			});
			return true;
		}

		private synchronized PeerNode chooseRandomPeer(HashSet<PeerNode> uomPeers) {
			if (this.completed) {
				return null;
			}
			if (this.peersFetching.size() >= MAX_NODES_SENDING_MANIFEST) {
				if (logMINOR) {
					Logger.minor(this, "Already fetching jar from 2 peers " + this.peersFetching);
				}
				return null;
			}
			if (logMINOR) {
				Logger.minor(this, "Trying to choose peer from " + uomPeers.size());
			}
			ArrayList<PeerNode> notTried = null;
			for (PeerNode pn : uomPeers) {
				if (this.peersFetching.contains(pn)) {
					if (logMINOR) {
						Logger.minor(this, "Already fetching from " + pn);
					}
					continue;
				}
				if (this.peersFailed.contains(pn)) {
					if (logMINOR) {
						Logger.minor(this, "Peer already failed for " + this.saveTo + " : " + pn);
					}
					continue;
				}
				if (!pn.isConnected()) {
					if (logMINOR) {
						Logger.minor(this, "Peer not connected: " + pn);
					}
					continue;
				}
				if (notTried == null) {
					notTried = new ArrayList<>();
				}
				notTried.add(pn);
			}
			if (notTried == null) {
				if (logMINOR) {
					Logger.minor(this, "No peers to ask for " + this.saveTo);
				}
				return null;
			}
			PeerNode fetchFrom = notTried
					.get(UpdateOverMandatoryManager.this.updateManager.node.fastWeakRandom.nextInt(notTried.size()));
			this.peersFetching.add(fetchFrom);
			return fetchFrom;
		}

		void start() {
			// noinspection StatementWithEmptyBody
			while (this.maybeFetch()) {
				// Do nothing
			}
		}

		void cancel() {
			synchronized (this) {
				this.completed = true;
			}
			synchronized (UpdateOverMandatoryManager.this) {
				UpdateOverMandatoryManager.this.dependencyFetchers.remove(this.expectedHashBuffer);
			}
		}

	}

	private class PeersSayKeyBlownAlert extends BaseNodeUserAlert {

		PeersSayKeyBlownAlert() {
			super(false, null, null, null, null, FCPUserAlert.WARNING, true, null, false, null);
		}

		@Override
		public HTMLNode getHTMLText() {
			HTMLNode div = new HTMLNode("div");

			div.addChild("p").addChild("#", this.l10n("intro"));

			PeerNode[][] nodes = UpdateOverMandatoryManager.this.getNodesSayBlown();
			PeerNode[] nodesSayBlownConnected = nodes[0];
			PeerNode[] nodesSayBlownDisconnected = nodes[1];
			PeerNode[] nodesSayBlownFailedTransfer = nodes[2];

			if (nodesSayBlownConnected.length > 0) {
				div.addChild("p").addChild("#", this.l10n("fetching"));
			}
			else {
				div.addChild("p").addChild("#", this.l10n("failedFetch"));
			}

			if (nodesSayBlownConnected.length > 0) {
				div.addChild("p").addChild("#", this.l10n("connectedSayBlownLabel"));
				HTMLNode list = div.addChild("ul");
				for (PeerNode pn : nodesSayBlownConnected) {
					list.addChild("li", pn.userToString() + " (" + pn.getPeer() + ")");
				}
			}

			if (nodesSayBlownDisconnected.length > 0) {
				div.addChild("p").addChild("#", this.l10n("disconnectedSayBlownLabel"));
				HTMLNode list = div.addChild("ul");
				for (PeerNode pn : nodesSayBlownDisconnected) {
					list.addChild("li", pn.userToString() + " (" + pn.getPeer() + ")");
				}
			}

			if (nodesSayBlownFailedTransfer.length > 0) {
				div.addChild("p").addChild("#", this.l10n("failedTransferSayBlownLabel"));
				HTMLNode list = div.addChild("ul");
				for (PeerNode pn : nodesSayBlownFailedTransfer) {
					list.addChild("li", pn.userToString() + " (" + pn.getPeer() + ")");
				}
			}

			return div;
		}

		private String l10n(String key) {
			return NodeL10n.getBase().getString("PeersSayKeyBlownAlert." + key);
		}

		private String l10n(String key, String pattern, String value) {
			return NodeL10n.getBase().getString("PeersSayKeyBlownAlert." + key, pattern, value);
		}

		@Override
		public String getText() {
			StringBuilder sb = new StringBuilder();
			sb.append(this.l10n("intro")).append("\n\n");
			PeerNode[][] nodes = UpdateOverMandatoryManager.this.getNodesSayBlown();
			PeerNode[] nodesSayBlownConnected = nodes[0];
			PeerNode[] nodesSayBlownDisconnected = nodes[1];
			PeerNode[] nodesSayBlownFailedTransfer = nodes[2];

			if (nodesSayBlownConnected.length > 0) {
				sb.append(this.l10n("fetching")).append("\n\n");
			}
			else {
				sb.append(this.l10n("failedFetch")).append("\n\n");
			}

			if (nodesSayBlownConnected.length > 0) {
				sb.append(this.l10n("connectedSayBlownLabel")).append("\n\n");
				for (PeerNode pn : nodesSayBlownConnected) {
					sb.append(pn.userToString()).append(" (").append(pn.getPeer()).append(")").append("\n");
				}
				sb.append("\n");
			}

			if (nodesSayBlownDisconnected.length > 0) {
				sb.append(this.l10n("disconnectedSayBlownLabel"));

				for (PeerNode pn : nodesSayBlownDisconnected) {
					sb.append(pn.userToString()).append(" (").append(pn.getPeer()).append(")").append("\n");
				}
				sb.append("\n");
			}

			if (nodesSayBlownFailedTransfer.length > 0) {
				sb.append(this.l10n("failedTransferSayBlownLabel"));

				for (PeerNode pn : nodesSayBlownFailedTransfer) {
					sb.append(pn.userToString()).append(" (").append(pn.getPeer()).append(")").append('\n');
				}
				sb.append("\n");
			}

			return sb.toString();
		}

		@Override
		public String getTitle() {
			return this.l10n("titleWithCount", "count",
					Integer.toString(UpdateOverMandatoryManager.this.nodesSayKeyRevoked.size()));
		}

		@Override
		public void isValid(boolean validity) {
			// Do nothing
		}

		@Override
		public boolean isValid() {
			if (UpdateOverMandatoryManager.this.updateManager.isBlown()) {
				return false;
			}
			return UpdateOverMandatoryManager.this.mightBeRevoked();
		}

		@Override
		public String getShortText() {
			return this.l10n("short");
		}

	}

	public interface UOMDependencyFetcherCallback {

		void onSuccess();

	}

}
