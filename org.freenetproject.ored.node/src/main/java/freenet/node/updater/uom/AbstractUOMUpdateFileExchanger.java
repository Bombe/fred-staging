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

import java.util.HashSet;

import freenet.bucket.Bucket;
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

	public AbstractUOMUpdateFileExchanger(Node node, String fileType, int currentVersion, int minDeployVersion,
			int maxDeployVersion, FreenetURI updateURI, FreenetURI revocationURI, RevocationChecker revocationChecker,
			NodeStats nodeStats) {

		super(node, fileType, currentVersion, minDeployVersion, maxDeployVersion);

		this.updateURI = updateURI;

		this.nodesOffered = new HashSet<>();
		this.nodesAskedSend = new HashSet<>();
		this.nodesSending = new HashSet<>();
		this.nodesSent = new HashSet<>();
		this.allNodesOffered = new HashSet<>();
		this.revocationURI = revocationURI;
		this.revocationChecker = revocationChecker;
		this.nodeStats = nodeStats;
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
		if (this.hasBeenBlown && !this.updateManager.revocationChecker.hasBlown()) {
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
			if (this.manifestUSKUpdater.isHasNewFile() && this.armed) {
				if (logMINOR) {
					Logger.minor(this, "Will update soon, not offering UOM.");
				}
				return -1;
			}
			if (this.manifestUSKUpdater.getFetchedFileVersion() <= 0) {
				if (logMINOR) {
					Logger.minor(this, "Not fetched yet");
				}
				return -1;
			}
			else if (this.manifestUSKUpdater.getFetchedFileVersion() != Version.buildNumber()) {
				// Don't announce UOM unless we've successfully updated ored.
				if (logMINOR) {
					Logger.minor(this, "Downloaded a different version than the one we are running, not offering UOM.");
				}
				return -1;
			}
			data = this.manifestUSKUpdater.getFetchedFileData();
		}
		if (logMINOR) {
			Logger.minor(this, "Got data for UOM: " + data + " size " + data.size());
		}
		return data.size();
	}

	protected abstract Message getUOMAnnounceUpdateFile(long blobSize);

	protected abstract String getFileType();

}
