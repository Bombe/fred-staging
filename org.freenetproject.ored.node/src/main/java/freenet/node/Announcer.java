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

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.TimeUnit;

import freenet.clients.fcp.FCPUserAlert;
import freenet.io.comm.PeerParseException;
import freenet.io.comm.ReferenceSignatureVerificationException;
import freenet.l10n.NodeL10n;
import freenet.node.useralerts.BaseNodeUserEvent;
import freenet.node.useralerts.SimpleUserAlert;
import freenet.node.useralerts.UserEvent;
import freenet.nodelogger.Logger;
import freenet.support.ByteArrayWrapper;
import freenet.support.HTMLNode;
import freenet.support.ListUtils;
import freenet.support.Logger.LogLevel;
import freenet.support.SimpleFieldSet;
import freenet.support.TimeUtil;
import freenet.support.node.FSParseException;
import freenet.support.transport.ip.IPUtil;

/**
 * Decide whether to announce, and announce if necessary to a node in the routing table,
 * or to a seednode.
 *
 * @author toad
 */
public class Announcer {

	private static boolean logMINOR;

	private final Node node;

	private final OpennetManager om;

	private static final int STATUS_LOADING = 0;

	private static final int STATUS_CONNECTING_SEEDNODES = 1;

	private static final int STATUS_NO_SEEDNODES = -1;

	private int runningAnnouncements;

	/** We want to announce to 5 different seednodes. */
	private static final int WANT_ANNOUNCEMENTS = 5;

	private int sentAnnouncements;

	private long startTime;

	private long timeAddedSeeds;

	private static final long MIN_ADDED_SEEDS_INTERVAL = TimeUnit.SECONDS.toMillis(60);

	/**
	 * After we have sent 3 announcements, wait for 30 seconds before sending 3 more if we
	 * still have no connections.
	 */
	static final long COOLING_OFF_PERIOD = TimeUnit.SECONDS.toMillis(30);

	/** Pubkey hashes of nodes we have announced to */
	private final HashSet<ByteArrayWrapper> announcedToIdentities;

	/**
	 * IPs of nodes we have announced to. Maybe this should be first-two-bytes, but I'm
	 * not sure how to do that with IPv6.
	 */
	private final HashSet<InetAddress> announcedToIPs;

	/** How many nodes to connect to at once? */
	private static final int CONNECT_AT_ONCE = 15;

	/** Do not announce if there are more than this many opennet peers connected */
	private static final int MIN_OPENNET_CONNECTED_PEERS = 10;

	private static final long NOT_ALL_CONNECTED_DELAY = TimeUnit.SECONDS.toMillis(60);

	private static final long RETRY_MISSING_SEEDNODES_DELAY = TimeUnit.SECONDS.toMillis(30);

	/** Total nodes added by announcement so far */
	private int announcementAddedNodes;

	/** Total nodes that didn't want us so far */
	private int announcementNotWantedNodes;

	Announcer(OpennetManager om) {
		this.om = om;
		this.node = om.node;
		this.announcedToIdentities = new HashSet<>();
		this.announcedToIPs = new HashSet<>();
		logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
	}

	protected void start() {
		if (!this.node.isOpennetEnabled()) {
			return;
		}
		int darkPeers = this.node.peers.getDarknetPeers().length;
		int openPeers = this.node.peers.getOpennetPeers().length;
		int oldOpenPeers = this.om.countOldOpennetPeers();
		if (darkPeers + openPeers + oldOpenPeers == 0) {
			// We know opennet is enabled.
			// We have no peers AT ALL.
			// So lets connect to a few seednodes, and attempt an announcement.
			System.err.println("Attempting announcement to seednodes...");
			synchronized (this) {
				this.registerEvent(STATUS_LOADING);
				this.started = true;
			}
			this.connectSomeSeednodes();
		}
		else {
			System.out.println("Not attempting immediate announcement: dark peers=" + darkPeers + " open peers="
					+ openPeers + " old open peers=" + oldOpenPeers + " - will wait 1 minute...");
			// Wait a minute, then check whether we need to seed.
			this.node.getTicker().queueTimedJob(new Runnable() {
				@Override
				public void run() {
					synchronized (Announcer.this) {
						Announcer.this.started = true;
					}
					try {
						Announcer.this.maybeSendAnnouncement();
					}
					catch (Throwable ex) {
						Logger.error(this, "Caught " + ex + " trying to send announcements", ex);
					}
				}
			}, MIN_ADDED_SEEDS_INTERVAL);
		}
	}

	private void registerEvent(int eventStatus) {
		this.node.clientCore.alerts.register(new AnnouncementUserEvent(eventStatus));
	}

	private void connectSomeSeednodes() {
		if (!this.node.isOpennetEnabled()) {
			return;
		}
		boolean announceNow = false;
		if (logMINOR) {
			Logger.minor(this, "Connecting some seednodes...");
		}
		List<SimpleFieldSet> seeds = Announcer.readSeednodes(NodeFile.Seednodes.getFile(this.node));
		if (seeds.isEmpty()) {
			System.out.println("File seednodes.fref does not exist or is empty. Loading builtin seednodes...");
			seeds = Announcer.readBuiltinSeednodes();
		}
		System.out.println("Trying to connect to " + seeds.size() + " seednodes...");
		long now = System.currentTimeMillis();
		synchronized (this) {
			if (now - this.timeAddedSeeds < MIN_ADDED_SEEDS_INTERVAL) {
				return;
			}
			this.timeAddedSeeds = now;
			if (seeds.size() == 0) {
				this.registerEvent(STATUS_NO_SEEDNODES);
				/*
				 * Developers might run nodes in empty directories instead of one made by
				 * an installer. They can copy in the seed nodes file, so check for it
				 * periodically to support loading it without the need to restart the
				 * node.
				 *
				 * TODO: If the seed nodes file is found it does not unregister the
				 * STATUS_NO_SEEDNODES event.
				 */
				this.node.getTicker().queueTimedJob(Announcer.this::maybeSendAnnouncement,
						Announcer.RETRY_MISSING_SEEDNODES_DELAY);
				return;
			}
			else {
				this.registerEvent(STATUS_CONNECTING_SEEDNODES);
			}
		}
		// Try to connect to some seednodes.
		// Once they are connected they will report back and we can attempt an
		// announcement.

		int count = this.connectSomeNodesInner(seeds);
		boolean stillConnecting = false;
		List<SeedServerPeerNode> tryingSeeds = this.node.peers.getSeedServerPeersVector();
		synchronized (this) {
			for (SeedServerPeerNode seed : tryingSeeds) {
				if (!this.announcedToIdentities.contains(new ByteArrayWrapper(seed.peerECDSAPubKeyHash))) {
					// Either:
					// a) we are still trying to connect to this node,
					// b) there is a race condition and we haven't sent the announcement
					// yet despite connecting, or
					// c) something is severely broken and we didn't send an announcement.
					// In any of these cases, we want to delay for 1 minute before
					// resetting the connection process and connecting to everyone.
					stillConnecting = true;
					break;
				}
			}
			if (logMINOR) {
				Logger.minor(this, "count = " + count + " announced = " + this.announcedToIdentities.size()
						+ " running = " + this.runningAnnouncements + " still connecting " + stillConnecting);
			}
			if (count == 0 && this.runningAnnouncements == 0) {
				// No more peers to connect to, and no announcements running.
				// Are there any peers which we are still trying to connect to?
				if (stillConnecting) {
					// Give them another minute.
					if (logMINOR) {
						Logger.minor(this, "Will clear announced-to in 1 minute...");
					}
					this.node.getTicker().queueTimedJob(new Runnable() {
						@Override
						public void run() {
							if (logMINOR) {
								Logger.minor(this, "Clearing old announced-to list");
							}
							synchronized (Announcer.this) {
								if (Announcer.this.runningAnnouncements != 0) {
									return;
								}
								Announcer.this.announcedToIdentities.clear();
								Announcer.this.announcedToIPs.clear();
							}
							Announcer.this.maybeSendAnnouncement();
						}
					}, NOT_ALL_CONNECTED_DELAY);
				}
				else {
					// We connected to all the seeds.
					// No point waiting!
					this.announcedToIdentities.clear();
					this.announcedToIPs.clear();
					announceNow = true;
				}
			}
		}
		this.node.dnsr.forceRun();
		// If none connect in a minute, try some more.
		this.node.getTicker().queueTimedJob(new Runnable() {
			@Override
			public void run() {
				try {
					Announcer.this.maybeSendAnnouncement();
				}
				catch (Throwable ex) {
					Logger.error(this, "Caught " + ex + " trying to send announcements", ex);
				}
			}
		}, announceNow ? 0 : MIN_ADDED_SEEDS_INTERVAL);
	}

	// Synchronize to protect announcedToIdentities and prevent running in parallel.
	private synchronized int connectSomeNodesInner(List<SimpleFieldSet> seeds) {
		if (logMINOR) {
			Logger.minor(this, "Connecting some seednodes from " + seeds.size());
		}
		int count = 0;
		while (count < CONNECT_AT_ONCE) {
			if (seeds.isEmpty()) {
				break;
			}
			SimpleFieldSet fs = ListUtils.removeRandomBySwapLastSimple(this.node.random, seeds);
			try {
				SeedServerPeerNode seed = new SeedServerPeerNode(fs, this.node, this.om.crypto, false);
				if (this.node.wantAnonAuth(true)
						&& Arrays.equals(this.node.getOpennetPubKeyHash(), seed.peerECDSAPubKeyHash)) {
					if (logMINOR) {
						Logger.minor("Not adding: I am a seednode attempting to connect to myself!",
								seed.userToString());
					}
					continue;
				}
				if (this.announcedToIdentities.contains(new ByteArrayWrapper(seed.peerECDSAPubKeyHash))) {
					if (logMINOR) {
						Logger.minor(this, "Not adding: already announced-to: " + seed.userToString());
					}
					continue;
				}
				if (logMINOR) {
					Logger.minor(this, "Trying to connect to seednode " + seed);
				}
				if (this.node.peers.addPeer(seed)) {
					count++;
					if (logMINOR) {
						Logger.minor(this, "Connecting to seednode " + seed);
					}
				}
				else {
					if (logMINOR) {
						Logger.minor(this, "Not connecting to seednode " + seed);
					}
				}
			}
			catch (FSParseException | PeerParseException | ReferenceSignatureVerificationException
					| PeerTooOldException ex) {
				Logger.error(this, "Invalid seed in file: " + ex + " for\n" + fs, ex);
			}
		}
		if (logMINOR) {
			Logger.minor(this, "connectSomeNodesInner() returning " + count);
		}
		return count;
	}

	public static List<SimpleFieldSet> readSeednodes(File file) {
		List<SimpleFieldSet> list = new ArrayList<>();
		try (FileInputStream fis = new FileInputStream(file)) {
			list = Announcer.readSeednodes(fis);
		}
		catch (IOException ex) {
			Logger.error(Announcer.class, "Unexpected error while reading seednodes from " + file, ex);
		}
		return list;
	}

	public static List<SimpleFieldSet> readSeednodes(InputStream is) throws IOException {
		List<SimpleFieldSet> list = new ArrayList<>();

		BufferedInputStream bis = new BufferedInputStream(is);
		InputStreamReader isr = new InputStreamReader(bis, StandardCharsets.UTF_8);
		BufferedReader br = new BufferedReader(isr);
		while (true) {
			try {
				SimpleFieldSet fs = new SimpleFieldSet(br, false, false, true, false);
				if (!fs.isEmpty()) {
					list.add(fs);
				}
			}
			catch (EOFException ignored) {
				return list;
			}
			catch (IOException ex) {
				Logger.error(Announcer.class, "Error while reading seednodes data", ex);
				// Continue reading. If this entry failed, we still want the following
				// noderefs.
				// Read a line to advance the parsing position and avoid an endless
				// loop.
				br.readLine();
			}
		}
	}

	public static List<SimpleFieldSet> readBuiltinSeednodes() {
		List<SimpleFieldSet> list = new ArrayList<>();

		try (InputStream is = Announcer.class.getResourceAsStream("/seednodes.fref")) {
			list = Announcer.readSeednodes(is);
		}
		catch (IOException ex) {
			Logger.error(Announcer.class, "Unexpected error while reading seednodes from builtin file", ex);
		}

		return list;
	}

	protected void stop() {
		// Do nothing at present
	}

	private long timeGotEnoughPeers = -1;

	private final Object timeGotEnoughPeersLock = new Object();

	private boolean killedAnnouncementTooOld;

	public int getAnnouncementThreshold() {
		// First, do we actually need to announce?
		return Math.min(MIN_OPENNET_CONNECTED_PEERS, this.om.getNumberOfConnectedPeersToAimIncludingDarknet() / 2);
	}

	private final SimpleUserAlert announcementDisabledAlert = new SimpleUserAlert(false,
			this.l10n("announceDisabledTooOldTitle"), this.l10n("announceDisabledTooOld"),
			this.l10n("announceDisabledTooOldShort"), FCPUserAlert.CRITICAL_ERROR) {

		@Override
		public HTMLNode getHTMLText() {
			HTMLNode div = new HTMLNode("div");
			div.addChild("#", Announcer.this.l10n("announceDisabledTooOld"));
			if (!Announcer.this.node.nodeUpdater.isEnabled()) {
				div.addChild("#", " ");
				NodeL10n.getBase().addL10nSubstitution(div, "Announcer.announceDisabledTooOldUpdateDisabled",
						new String[] { "config" }, new HTMLNode[] { HTMLNode.link("/config/node.updater") });
			}
			// No point with !armed() or blown() because they have their own messages.
			return div;
		}

		@Override
		public String getText() {
			StringBuilder sb = new StringBuilder();
			sb.append(Announcer.this.l10n("announceDisabledTooOld"));
			sb.append(" ");
			if (!Announcer.this.node.nodeUpdater.isEnabled()) {
				sb.append(Announcer.this.l10n("announceDisabledTooOldUpdateDisabled",
						new String[] { "config", "/config" }, new String[] { "", "" }));
			}
			return sb.toString();
		}

		@Override
		public boolean isValid() {
			if (Announcer.this.node.nodeUpdater.isEnabled()) {
				return false;
			}
			// If it is enabled but not armed there will be a message from the updater.
			synchronized (Announcer.this) {
				return Announcer.this.killedAnnouncementTooOld;
			}
		}

	};

	/**
	 * @return True if we have enough peers that we don't need to announce.
	 */
	boolean enoughPeers() {
		if (this.om.stopping()) {
			return true;
		}
		// Do we want to send an announcement to the node?
		int opennetCount = this.node.peers.countConnectedPeers();
		int target = this.getAnnouncementThreshold();
		if (opennetCount >= target) {
			if (logMINOR) {
				Logger.minor(this, "We have enough opennet peers: " + opennetCount + " > " + target + " since "
						+ (System.currentTimeMillis() - this.timeGotEnoughPeers) + " ms");
			}
			synchronized (this.timeGotEnoughPeersLock) {
				if (this.timeGotEnoughPeers <= 0) {
					this.timeGotEnoughPeers = System.currentTimeMillis();
				}
			}
			return true;
		}
		boolean killAnnouncement = false;
		if ((!this.node.nodeUpdater.isEnabled())
				|| (this.node.nodeUpdater.canUpdateNow() && !this.node.nodeUpdater.isArmed())) {
			// If we also have 10 TOO_NEW peers, we should shut down the announcement,
			// because we're obviously broken and would only be spamming the seednodes
			synchronized (this) {
				// Once we have shut down announcement, this persists until the
				// auto-updater
				// is enabled.
				if (this.killedAnnouncementTooOld) {
					return true;
				}
			}
			if (this.node.peers.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_TOO_NEW, false) > 10) {
				synchronized (this) {
					if (this.killedAnnouncementTooOld) {
						return true;
					}
					this.killedAnnouncementTooOld = true;
					killAnnouncement = true;
				}
				Logger.error(this,
						"Shutting down announcement as we are older than the current mandatory build and auto-update is disabled or waiting for user input.");
				System.err.println(
						"Shutting down announcement as we are older than the current mandatory build and auto-update is disabled or waiting for user input.");
				if (this.node.clientCore != null) {
					this.node.clientCore.alerts.register(this.announcementDisabledAlert);
				}
			}

		}

		if (killAnnouncement) {
			this.node.executor.execute(() -> {
				for (OpennetPeerNode pn : Announcer.this.node.peers.getOpennetPeers()) {
					Announcer.this.node.peers.disconnectAndRemove(pn, true, true, true);
				}
				for (SeedServerPeerNode pn : Announcer.this.node.peers.getSeedServerPeersVector()) {
					Announcer.this.node.peers.disconnectAndRemove(pn, true, true, true);
				}
			});
			return true;
		}
		else {
			synchronized (this) {
				this.killedAnnouncementTooOld = false;
			}
			if (this.node.clientCore != null) {
				this.node.clientCore.alerts.unregister(this.announcementDisabledAlert);
			}
			if (this.node.nodeUpdater.isEnabled() && this.node.nodeUpdater.isArmed()
					&& this.node.nodeUpdater.uom.fetchingFromTwo()
					&& this.node.peers.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_TOO_NEW, false) > 5) {
				// No point announcing at the moment, but we might need to if a transfer
				// falls through.
				return true;
			}
		}

		synchronized (this.timeGotEnoughPeersLock) {
			this.timeGotEnoughPeers = -1;
		}
		return false;
	}

	/**
	 * Get the earliest time at which we had enough opennet peers. This is reset when we
	 * drop below the threshold.
	 */
	long timeGotEnoughPeers() {
		synchronized (this.timeGotEnoughPeersLock) {
			return this.timeGotEnoughPeers;
		}
	}

	/**
	 * 1 minute after we have enough peers, remove all seednodes left (presumably
	 * disconnected ones)
	 */
	private static final long FINAL_DELAY = TimeUnit.SECONDS.toMillis(60);

	/**
	 * But if we don't have enough peers at that point, wait another minute and if the
	 * situation has not improved, reannounce.
	 */
	static final long RETRY_DELAY = TimeUnit.SECONDS.toMillis(60);

	private boolean started = false;

	private final Runnable checker = () -> {
		int running;
		synchronized (Announcer.this) {
			running = Announcer.this.runningAnnouncements;
		}
		if (Announcer.this.enoughPeers()) {
			for (SeedServerPeerNode pn : Announcer.this.node.peers.getConnectedSeedServerPeersVector(null)) {
				Announcer.this.node.peers.disconnectAndRemove(pn, true, true, false);
			}
			// Re-check every minute. Something bad might happen (e.g. cpu
			// starvation), causing us to have to reseed.
			Announcer.this.node.getTicker().queueTimedJob(Announcer.this::maybeSendAnnouncement,
					"Check whether we need to announce", RETRY_DELAY, false, true);
		}
		else {
			Announcer.this.node.getTicker().queueTimedJob(Announcer.this::maybeSendAnnouncement,
					"Check whether we need to announce", RETRY_DELAY, false, true);
			if (running != 0) {
				Announcer.this.maybeSendAnnouncement();
			}
		}
	};

	public void maybeSendAnnouncementOffThread() {
		if (this.enoughPeers()) {
			return;
		}
		this.node.getTicker().queueTimedJob(Announcer.this::maybeSendAnnouncement, 0);
	}

	protected void maybeSendAnnouncement() {
		synchronized (this) {
			if (!this.started) {
				return;
			}
		}
		logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
		if (logMINOR) {
			Logger.minor(this, "maybeSendAnnouncement()");
		}
		long now = System.currentTimeMillis();
		if (!this.node.isOpennetEnabled()) {
			return;
		}
		if (this.enoughPeers()) {
			// Check again in 60 seconds.
			this.node.getTicker().queueTimedJob(this.checker, "Announcement checker", FINAL_DELAY, false, true);
			return;
		}
		synchronized (this) {
			// Double check after taking the lock.
			if (this.enoughPeers()) {
				// Check again in 60 seconds.
				this.node.getTicker().queueTimedJob(this.checker, "Announcement checker", FINAL_DELAY, false, true);
				return;
			}
			// Second, do we have many announcements running?
			if (this.runningAnnouncements > WANT_ANNOUNCEMENTS) {
				if (logMINOR) {
					Logger.minor(this, "Running announcements already");
				}
				return;
			}
			// In cooling-off period?
			if (System.currentTimeMillis() < this.startTime) {
				if (logMINOR) {
					Logger.minor(this, "In cooling-off period for next "
							+ TimeUtil.formatTime(this.startTime - System.currentTimeMillis()));
				}
				return;
			}
			if (this.sentAnnouncements >= WANT_ANNOUNCEMENTS) {
				if (logMINOR) {
					Logger.minor(this, "Sent enough announcements");
				}
				return;
			}
			// Now find a node to announce to
			List<SeedServerPeerNode> seeds = this.node.peers
					.getConnectedSeedServerPeersVector(this.announcedToIdentities);
			while (this.sentAnnouncements < WANT_ANNOUNCEMENTS) {
				if (seeds.isEmpty()) {
					if (logMINOR) {
						Logger.minor(this, "No more seednodes, announcedTo = " + this.announcedToIdentities.size());
					}
					break;
				}
				final SeedServerPeerNode seed = ListUtils.removeRandomBySwapLastSimple(this.node.random, seeds);
				assert seed != null;
				InetAddress[] addrs = seed.getInetAddresses();
				if (!this.newAnnouncedIPs(addrs)) {
					if (logMINOR) {
						Logger.minor(this, "Not announcing to " + seed + " because already used those IPs");
					}
					continue;
				}
				this.addAnnouncedIPs(addrs);
				// If it throws, we do not want to increment, so call it first.
				if (this.sendAnnouncement(seed)) {
					this.sentAnnouncements++;
					this.runningAnnouncements++;
					this.announcedToIdentities.add(new ByteArrayWrapper(seed.peerECDSAPubKeyHash));
				}
			}
			if (this.runningAnnouncements >= WANT_ANNOUNCEMENTS) {
				if (logMINOR) {
					Logger.minor(this, "Running " + this.runningAnnouncements + " announcements");
				}
				return;
			}
			// Do we want to connect some more seednodes?
			if (now - this.timeAddedSeeds < MIN_ADDED_SEEDS_INTERVAL) {
				// Don't connect seednodes yet
				Logger.minor(this, "Waiting for MIN_ADDED_SEEDS_INTERVAL");
				this.node.getTicker().queueTimedJob(new Runnable() {
					@Override
					public void run() {
						try {
							Announcer.this.maybeSendAnnouncement();
						}
						catch (Throwable ex) {
							Logger.error(this, "Caught " + ex + " trying to send announcements", ex);
						}
					}
				}, (this.timeAddedSeeds + MIN_ADDED_SEEDS_INTERVAL) - now);
				return;
			}
		}
		this.connectSomeSeednodes();
	}

	private synchronized void addAnnouncedIPs(InetAddress[] addrs) {
		Collections.addAll(this.announcedToIPs, addrs);
	}

	/**
	 * Have we already announced to this node? Return true if the node has new non-local
	 * addresses we haven't announced to. Return false if the node has non-local addresses
	 * we have announced to. Return true if the node has no non-local addresses.
	 * @param addrs array of addresses
	 * @return true if addresses do not contain non local addresses
	 */
	private synchronized boolean newAnnouncedIPs(InetAddress[] addrs) {
		boolean hasNonLocalAddresses = false;
		for (InetAddress addr : addrs) {
			if (!IPUtil.isValidAddress(addr, false)) {
				continue;
			}
			hasNonLocalAddresses = true;
			if (!this.announcedToIPs.contains(addr)) {
				return true;
			}
		}
		return !hasNonLocalAddresses;
	}

	protected boolean sendAnnouncement(final SeedServerPeerNode seed) {
		if (!this.node.isOpennetEnabled()) {
			if (logMINOR) {
				Logger.minor(this, "Not announcing to " + seed + " because opennet is disabled");
			}
			return false;
		}
		System.out.println("Announcement to " + seed.userToString() + " starting...");
		if (logMINOR) {
			Logger.minor(this, "Announcement to " + seed.userToString() + " starting...");
		}
		AnnounceSender sender = new AnnounceSender(this.node.getLocation(), this.om, this.node,
				new AnnouncementCallback() {
					private int totalAdded;

					private int totalNotWanted;

					private boolean acceptedSomewhere;

					@Override
					public synchronized void acceptedSomewhere() {
						this.acceptedSomewhere = true;
					}

					@Override
					public void addedNode(PeerNode pn) {
						synchronized (Announcer.this) {
							Announcer.this.announcementAddedNodes++;
							this.totalAdded++;
						}
						Logger.normal(this,
								"Announcement to " + seed.userToString() + " added node " + pn + " for a total of "
										+ Announcer.this.announcementAddedNodes + " (" + this.totalAdded
										+ " from this announcement)");
						System.out.println(
								"Announcement to " + seed.userToString() + " added node " + pn.userToString() + '.');
					}

					@Override
					public void bogusNoderef(String reason) {
						Logger.normal(this, "Announcement to " + seed.userToString() + " got bogus noderef: " + reason,
								new Exception("debug"));
					}

					@Override
					public void completed() {
						boolean announceNow = false;
						synchronized (Announcer.this) {
							Announcer.this.runningAnnouncements--;
							Logger.normal(this, "Announcement to " + seed.userToString() + " completed, now running "
									+ Announcer.this.runningAnnouncements + " announcements");
							if (Announcer.this.runningAnnouncements == 0 && Announcer.this.announcementAddedNodes > 0) {
								// No point waiting if no nodes have been added!
								Announcer.this.startTime = System.currentTimeMillis() + COOLING_OFF_PERIOD;
								Announcer.this.sentAnnouncements = 0;
								// Wait for COOLING_OFF_PERIOD before trying again
								Announcer.this.node.getTicker().queueTimedJob(Announcer.this::maybeSendAnnouncement,
										COOLING_OFF_PERIOD);
							}
							else if (Announcer.this.runningAnnouncements == 0) {
								Announcer.this.sentAnnouncements = 0;
								announceNow = true;
							}
						}
						// If it takes more than COOLING_OFF_PERIOD to disconnect, we
						// might not be
						// able to reannounce to this
						// node. However, we can't reannounce to it anyway until
						// announcedTo is
						// cleared, which probably will
						// be more than that period in the future.
						Announcer.this.node.peers.disconnectAndRemove(seed, true, false, false);
						int shallow = Announcer.this.node.maxHTL() - (this.totalAdded + this.totalNotWanted);
						if (this.acceptedSomewhere) {
							System.out.println("Announcement to " + seed.userToString() + " completed ("
									+ this.totalAdded + " added, " + this.totalNotWanted + " not wanted, " + shallow
									+ " shallow)");
						}
						else {
							System.out.println("Announcement to " + seed.userToString() + " not accepted (version "
									+ seed.getVersionNumber() + ") .");
						}
						if (announceNow) {
							Announcer.this.maybeSendAnnouncement();
						}
					}

					@Override
					public void nodeFailed(PeerNode pn, String reason) {
						Logger.normal(this, "Announcement to node " + pn.userToString() + " failed: " + reason);
					}

					@Override
					public void noMoreNodes() {
						Logger.normal(this,
								"Announcement to " + seed.userToString() + " ran out of nodes (route not found)");
					}

					@Override
					public void nodeNotWanted() {
						synchronized (Announcer.this) {
							Announcer.this.announcementNotWantedNodes++;
							this.totalNotWanted++;
						}
						Logger.normal(this,
								"Announcement to " + seed.userToString() + " returned node not wanted for a total of "
										+ Announcer.this.announcementNotWantedNodes + " (" + this.totalNotWanted
										+ " from this announcement)");
					}

					@Override
					public void nodeNotAdded() {
						Logger.normal(this, "Announcement to " + seed.userToString()
								+ " : node not wanted (maybe already have it, opennet just turned off, etc)");
					}

					@Override
					public void relayedNoderef() {
						Logger.error(this, "Announcement to " + seed.userToString() + " : RELAYED ?!?!?!");
					}
				}, seed);
		this.node.executor.execute(sender, "Announcer to " + seed);
		return true;
	}

	private String l10n(String key) {
		return NodeL10n.getBase().getString("Announcer." + key);
	}

	protected String l10n(String key, String[] patterns, String[] values) {
		return NodeL10n.getBase().getString("Announcer." + key, patterns, values);
	}

	private String l10n(String key, String pattern, String value) {
		return NodeL10n.getBase().getString("Announcer." + key, pattern, value);
	}

	public void reannounce() {
		System.out.println("Re-announcing...");
		this.maybeSendAnnouncementOffThread();
	}

	public boolean isWaitingForUpdater() {
		synchronized (this) {
			return this.killedAnnouncementTooOld;
		}
	}

	class AnnouncementUserEvent extends BaseNodeUserEvent {

		private final int status;

		AnnouncementUserEvent(int status) {
			this.status = status;
		}

		@Override
		public String dismissButtonText() {
			return NodeL10n.getBase().getString("UserAlert.hide");
		}

		@Override
		public HTMLNode getHTMLText() {
			return new HTMLNode("#", this.getText());
		}

		@Override
		public short getPriorityClass() {
			return FCPUserAlert.ERROR;
		}

		@Override
		public String getText() {
			StringBuilder sb = new StringBuilder();
			sb.append(Announcer.this.l10n("announceAlertIntro"));
			if (this.status == STATUS_NO_SEEDNODES) {
				return Announcer.this.l10n("announceAlertNoSeednodes");
			}
			if (this.status == STATUS_LOADING) {
				return Announcer.this.l10n("announceLoading");
			}
			if (Announcer.this.node.clientCore.isAdvancedModeEnabled()) {
				// Detail
				sb.append(' ');
				int addedNodes;
				int refusedNodes;
				int recentSentAnnouncements;
				int runningAnnouncements;
				int connectedSeednodes = 0;
				int disconnectedSeednodes = 0;
				long coolingOffSeconds = Math.max(0, Announcer.this.startTime - System.currentTimeMillis()) / 1000;
				synchronized (this) {
					addedNodes = Announcer.this.announcementAddedNodes;
					refusedNodes = Announcer.this.announcementNotWantedNodes;
					recentSentAnnouncements = Announcer.this.sentAnnouncements;
					runningAnnouncements = Announcer.this.runningAnnouncements;

				}
				List<SeedServerPeerNode> nodes = Announcer.this.node.peers.getSeedServerPeersVector();
				for (SeedServerPeerNode seed : nodes) {
					if (seed.isConnected()) {
						connectedSeednodes++;
					}
					else {
						disconnectedSeednodes++;
					}
				}
				sb.append(Announcer.this.l10n("announceDetails",
						new String[] { "addedNodes", "refusedNodes", "recentSentAnnouncements", "runningAnnouncements",
								"connectedSeednodes", "disconnectedSeednodes" },
						new String[] { Integer.toString(addedNodes), Integer.toString(refusedNodes),
								Integer.toString(recentSentAnnouncements), Integer.toString(runningAnnouncements),
								Integer.toString(connectedSeednodes), Integer.toString(disconnectedSeednodes) }));
				if (coolingOffSeconds > 0) {
					sb.append(' ');
					sb.append(Announcer.this.l10n("coolingOff", "time", Long.toString(coolingOffSeconds)));
				}
			}
			return sb.toString();
		}

		@Override
		public String getTitle() {
			return Announcer.this.l10n("announceAlertTitle");
		}

		@Override
		public boolean isValid() {
			return (!Announcer.this.enoughPeers()) && Announcer.this.node.isOpennetEnabled();
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
			return true;
		}

		@Override
		public boolean userCanDismiss() {
			return true;
		}

		@Override
		public String anchor() {
			return "announcer:" + this.hashCode();
		}

		@Override
		public String getShortText() {
			return Announcer.this.l10n("announceAlertShort");
		}

		@Override
		public boolean isEventNotification() {
			return false;
		}

		@Override
		public Type getEventType() {
			return UserEvent.Type.Announcer;
		}

	}

}
