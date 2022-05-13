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

import java.util.HashSet;

import freenet.io.comm.ByteCounter;
import freenet.io.comm.DMT;
import freenet.io.comm.DisconnectedException;
import freenet.io.comm.Message;
import freenet.io.comm.MessageFilter;
import freenet.io.comm.NotConnectedException;
import freenet.io.comm.PeerParseException;
import freenet.io.comm.ReferenceSignatureVerificationException;
import freenet.nodelogger.Logger;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger.LogLevel;
import freenet.support.SimpleFieldSet;
import freenet.support.io.NativeThread;
import freenet.support.node.FSParseException;
import freenet.support.node.PrioRunnable;

public class AnnounceSender implements PrioRunnable, ByteCounter {

	private static volatile boolean logMINOR;

	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback() {
			@Override
			public void shouldUpdate() {
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}

	// Constants
	static final int ACCEPTED_TIMEOUT = 10000;
	static final int ANNOUNCE_TIMEOUT = 120000; // longer than a regular request as have
												// to transfer noderefs hop by hop etc
	static final int END_TIMEOUT = 30000; // After received the completion message, wait
											// 30 seconds for any late reordered replies

	private final PeerNode source;

	private final long uid;

	private final OpennetManager om;

	private final Node node;

	private final long xferUID;

	private final int noderefLength;

	private final int paddedLength;

	private byte[] noderefBuf;

	private short htl;

	private final double target;

	private final AnnouncementCallback cb;

	private final PeerNode onlyNode;

	private int forwardedRefs;

	public AnnounceSender(double target, short htl, long uid, PeerNode source, OpennetManager om, Node node,
			long xferUID, int noderefLength, int paddedLength, AnnouncementCallback cb) {
		this.source = source;
		this.uid = uid;
		this.om = om;
		this.node = node;
		this.onlyNode = null;
		this.htl = htl;
		this.xferUID = xferUID;
		this.paddedLength = paddedLength;
		this.noderefLength = noderefLength;
		this.target = target;
		this.cb = cb;
	}

	public AnnounceSender(double target, OpennetManager om, Node node, AnnouncementCallback cb, PeerNode onlyNode) {
		this.source = null;
		this.uid = node.random.nextLong();
		// Prevent it being routed back to us.
		node.tracker.completed(this.uid);
		this.om = om;
		this.node = node;
		this.htl = node.maxHTL();
		this.target = target;
		this.cb = cb;
		this.onlyNode = onlyNode;
		this.noderefBuf = om.crypto.myCompressedFullRef();
		this.xferUID = 0;
		this.paddedLength = 0;
		this.noderefLength = 0;
	}

	@Override
	public void run() {
		try {
			this.realRun();
			this.node.nodeStats.reportAnnounceForwarded(this.forwardedRefs, this.source);
		}
		catch (Throwable ex) {
			Logger.error(this, "Caught " + ex + " announcing " + this.uid + " from " + this.source, ex);
		}
		finally {
			if (this.source != null) {
				this.source.completedAnnounce(this.uid);
			}
			this.node.tracker.completed(this.uid);
			if (this.cb != null) {
				this.cb.completed();
			}
			this.node.nodeStats.endAnnouncement(this.uid);
		}
	}

	private void realRun() {
		boolean hasForwarded = false;
		if (this.source != null) {
			try {
				this.source.sendAsync(DMT.createFNPAccepted(this.uid), null, this);
			}
			catch (NotConnectedException ex) {
				return;
			}
			if (!this.transferNoderef()) {
				return;
			}
		}

		// Now route it.

		HashSet<PeerNode> nodesRoutedTo = new HashSet<>();
		PeerNode next = null;
		while (true) {
			if (logMINOR) {
				Logger.minor(this, "htl=" + this.htl);
			}
			/*
			 * If we haven't routed to any node yet, decrement according to the source. If
			 * we have, decrement according to the node which just failed. Because: 1) If
			 * we always decrement according to source then we can be at max or min HTL
			 * for a long time while we visit *every* peer node. This is BAD! 2) The node
			 * which just failed can be seen as the requestor for our purposes.
			 */
			// Decrement at this point so we can DNF immediately on reaching HTL 0.
			if (this.onlyNode == null) {
				this.htl = this.node.decrementHTL(hasForwarded ? next : this.source, this.htl);
			}

			if (this.htl == 0) {
				// No more nodes.
				this.complete();
				return;
			}

			if (!this.node.isOpennetEnabled()) {
				this.complete();
				return;
			}

			if (this.onlyNode == null) {
				// Route it
				next = this.node.peers.closerPeer(this.source, nodesRoutedTo, this.target, true,
						this.node.isAdvancedModeEnabled(), -1, null, null, this.htl, 0, this.source == null, false,
						false);
			}
			else {
				next = this.onlyNode;
				if (nodesRoutedTo.contains(this.onlyNode)) {
					this.rnf(this.onlyNode);
					return;
				}
			}

			if (next == null) {
				// Backtrack
				this.rnf(null);
				return;
			}
			if (logMINOR) {
				Logger.minor(this, "Routing request to " + next);
			}
			if (this.onlyNode == null) {
				next.reportRoutedTo(this.target, this.source == null, false, this.source, nodesRoutedTo, this.htl);
			}
			nodesRoutedTo.add(next);

			long xferUID = this.sendTo(next);
			if (xferUID == -1) {
				continue;
			}

			hasForwarded = true;

			Message msg = null;

			while (true) {

				/*
				 * What are we waiting for? FNPAccepted - continue FNPRejectedLoop - go to
				 * another node FNPRejectedOverload - go to another node
				 */

				MessageFilter mfAccepted = MessageFilter.create().setSource(next).setField(DMT.UID, this.uid)
						.setTimeout(ACCEPTED_TIMEOUT).setType(DMT.FNPAccepted);
				MessageFilter mfRejectedLoop = MessageFilter.create().setSource(next).setField(DMT.UID, this.uid)
						.setTimeout(ACCEPTED_TIMEOUT).setType(DMT.FNPRejectedLoop);
				MessageFilter mfRejectedOverload = MessageFilter.create().setSource(next).setField(DMT.UID, this.uid)
						.setTimeout(ACCEPTED_TIMEOUT).setType(DMT.FNPRejectedOverload);
				MessageFilter mfOpennetDisabled = MessageFilter.create().setSource(next).setField(DMT.UID, this.uid)
						.setTimeout(ACCEPTED_TIMEOUT).setType(DMT.FNPOpennetDisabled);

				// mfRejectedOverload must be the last thing in the or
				// So its or pointer remains null
				// Otherwise we need to recreate it below
				MessageFilter mf = mfAccepted.or(mfRejectedLoop.or(mfRejectedOverload.or(mfOpennetDisabled)));

				try {
					msg = this.node.usm.waitFor(mf, this);
					if (logMINOR) {
						Logger.minor(this, "first part got " + msg);
					}
				}
				catch (DisconnectedException ex) {
					Logger.normal(this, "Disconnected from " + next + " while waiting for Accepted on " + this.uid);
					break;
				}

				if (msg == null) {
					if (logMINOR) {
						Logger.minor(this, "Timeout waiting for Accepted");
					}
					// Try next node
					break;
				}

				if (msg.getSpec() == DMT.FNPRejectedLoop) {
					if (logMINOR) {
						Logger.minor(this, "Rejected loop");
					}
					// Find another node to route to
					msg = null;
					break;
				}

				if (msg.getSpec() == DMT.FNPRejectedOverload) {
					if (logMINOR) {
						Logger.minor(this, "Rejected: overload");
					}
					// Give up on this one, try another
					msg = null;
					break;
				}

				if (msg.getSpec() == DMT.FNPOpennetDisabled) {
					if (logMINOR) {
						Logger.minor(this, "Opennet disabled");
					}
					msg = null;
					break;
				}

				if (msg.getSpec() != DMT.FNPAccepted) {
					Logger.error(this, "Unrecognized message: " + msg);
					continue;
				}

				break;
			}

			if ((msg == null) || (msg.getSpec() != DMT.FNPAccepted)) {
				// Try another node
				continue;
			}

			if (logMINOR) {
				Logger.minor(this, "Got Accepted");
			}

			if (this.cb != null) {
				this.cb.acceptedSomewhere();
			}

			// Send the rest

			try {
				this.sendRest(next, xferUID);
			}
			catch (NotConnectedException e1) {
				if (logMINOR) {
					Logger.minor(this, "Not connected while sending noderef on " + next);
				}
				continue;
			}

			// Otherwise, must be Accepted

			// So wait...

			while (true) {

				MessageFilter mfAnnounceCompleted = MessageFilter.create().setSource(next).setField(DMT.UID, this.uid)
						.setTimeout(ANNOUNCE_TIMEOUT).setType(DMT.FNPOpennetAnnounceCompleted);
				MessageFilter mfRouteNotFound = MessageFilter.create().setSource(next).setField(DMT.UID, this.uid)
						.setTimeout(ANNOUNCE_TIMEOUT).setType(DMT.FNPRouteNotFound);
				MessageFilter mfRejectedOverload = MessageFilter.create().setSource(next).setField(DMT.UID, this.uid)
						.setTimeout(ANNOUNCE_TIMEOUT).setType(DMT.FNPRejectedOverload);
				MessageFilter mfAnnounceReply = MessageFilter.create().setSource(next).setField(DMT.UID, this.uid)
						.setTimeout(ANNOUNCE_TIMEOUT).setType(DMT.FNPOpennetAnnounceReply);
				MessageFilter mfOpennetDisabled = MessageFilter.create().setSource(next).setField(DMT.UID, this.uid)
						.setTimeout(ANNOUNCE_TIMEOUT).setType(DMT.FNPOpennetDisabled);
				MessageFilter mfNotWanted = MessageFilter.create().setSource(next).setField(DMT.UID, this.uid)
						.setTimeout(ANNOUNCE_TIMEOUT).setType(DMT.FNPOpennetAnnounceNodeNotWanted);
				MessageFilter mfOpennetNoderefRejected = MessageFilter.create().setSource(next)
						.setField(DMT.UID, this.uid).setTimeout(ANNOUNCE_TIMEOUT)
						.setType(DMT.FNPOpennetNoderefRejected);
				MessageFilter mf = mfAnnounceCompleted.or(mfRouteNotFound.or(mfRejectedOverload
						.or(mfAnnounceReply.or(mfOpennetDisabled.or(mfNotWanted.or(mfOpennetNoderefRejected))))));

				try {
					msg = this.node.usm.waitFor(mf, this);
				}
				catch (DisconnectedException ex) {
					Logger.normal(this, "Disconnected from " + next + " while waiting for announcement");
					break;
				}

				if (logMINOR) {
					Logger.minor(this, "second part got " + msg);
				}

				if (msg == null) {
					// Fatal timeout, must be terminal (IS_LOCAL==true)
					this.timedOut(next);
					return;
				}

				if (msg.getSpec() == DMT.FNPOpennetNoderefRejected) {
					int reason = msg.getInt(DMT.REJECT_CODE);
					Logger.normal(this, "Announce rejected by " + next + " : " + DMT.getOpennetRejectedCode(reason));
					break;
				}

				if (msg.getSpec() == DMT.FNPOpennetAnnounceCompleted) {
					// Send the completion on immediately. We don't want to accumulate 30
					// seconds per hop!
					this.complete();
					mfAnnounceReply.setTimeout(END_TIMEOUT).setTimeoutRelativeToCreation(true);
					mfNotWanted.setTimeout(END_TIMEOUT).setTimeoutRelativeToCreation(true);
					mfAnnounceReply.clearOr();
					mfNotWanted.clearOr();
					mf = mfAnnounceReply.or(mfNotWanted);
					while (true) {
						try {
							msg = this.node.usm.waitFor(mf, this);
						}
						catch (DisconnectedException ignored) {
							return;
						}
						if (msg == null) {
							return;
						}
						if (msg.getSpec() == DMT.FNPOpennetAnnounceReply) {
							this.validateForwardReply(msg, next);
							continue;
						}
						if (msg.getSpec() == DMT.FNPOpennetAnnounceNodeNotWanted) {
							if (this.cb != null) {
								this.cb.nodeNotWanted();
							}
							if (this.source != null) {
								try {
									this.sendNotWanted();
								}
								catch (NotConnectedException ignored) {
									Logger.warning(this, "Lost connection to source (announce completed)");
									return;
								}
							}
						}
					}
				}

				if (msg.getSpec() == DMT.FNPRouteNotFound) {
					// Backtrack within available hops
					short newHtl = msg.getShort(DMT.HTL);
					if (newHtl < 0) {
						newHtl = 0;
					}
					if (newHtl < this.htl) {
						this.htl = newHtl;
					}
					break;
				}

				if (msg.getSpec() == DMT.FNPRejectedOverload) {
					// Give up on this one, try another
					break;
				}

				if (msg.getSpec() == DMT.FNPOpennetDisabled) {
					Logger.minor(this, "Opennet disabled");
					break;
				}

				if (msg.getSpec() == DMT.FNPOpennetAnnounceReply) {
					this.validateForwardReply(msg, next);
					continue; // There may be more
				}

				if (msg.getSpec() == DMT.FNPOpennetAnnounceNodeNotWanted) {
					if (this.cb != null) {
						this.cb.nodeNotWanted();
					}
					if (this.source != null) {
						try {
							this.sendNotWanted();
						}
						catch (NotConnectedException ignored) {
							Logger.warning(this, "Lost connection to source (announce not wanted)");
							return;
						}
					}
					continue; // This message is propagated, they will send a Completed or
								// RNF
				}

				Logger.error(this, "Unexpected message: " + msg);
			}
		}
	}

	private int waitingForTransfers = 0;

	/**
	 * Validate a reply, and relay it back to the source.
	 * @param msg The AnnouncementReply message.
	 */
	private void validateForwardReply(Message msg, final PeerNode next) {
		final long xferUID = msg.getLong(DMT.TRANSFER_UID);
		final int noderefLength = msg.getInt(DMT.NODEREF_LENGTH);
		final int paddedLength = msg.getInt(DMT.PADDED_LENGTH);
		synchronized (this) {
			this.waitingForTransfers++;
		}
		Runnable r = new Runnable() {

			@Override
			public void run() {
				try {
					byte[] noderefBuf = OpennetManager.innerWaitForOpennetNoderef(xferUID, paddedLength, noderefLength,
							next, false, AnnounceSender.this.uid, true, AnnounceSender.this, AnnounceSender.this.node);
					if (noderefBuf == null) {
						return; // Don't relay
					}
					SimpleFieldSet fs = OpennetManager.validateNoderef(noderefBuf, 0, noderefLength, next, false);
					if (fs == null) {
						if (AnnounceSender.this.cb != null) {
							AnnounceSender.this.cb.bogusNoderef("invalid noderef");
						}
						return; // Don't relay
					}
					if (AnnounceSender.this.source != null) {
						// Now relay it
						try {
							AnnounceSender.this.forwardedRefs++;
							AnnounceSender.this.om.sendAnnouncementReply(AnnounceSender.this.uid,
									AnnounceSender.this.source, noderefBuf, AnnounceSender.this);
							if (AnnounceSender.this.cb != null) {
								AnnounceSender.this.cb.relayedNoderef();
							}
						}
						catch (NotConnectedException ignored) {
							// Hmmm...!
							return;
						}
					}
					else {
						// Add it
						try {
							OpennetPeerNode pn = AnnounceSender.this.node.addNewOpennetNode(fs,
									OpennetManager.ConnectionType.ANNOUNCE);
							if (AnnounceSender.this.cb != null) {
								if (pn != null) {
									AnnounceSender.this.cb.addedNode(pn);
								}
								else {
									AnnounceSender.this.cb.nodeNotAdded();
								}
							}
						}
						catch (FSParseException | PeerParseException | ReferenceSignatureVerificationException ex) {
							Logger.normal(this, "Failed to parse reply: " + ex, ex);
							if (AnnounceSender.this.cb != null) {
								AnnounceSender.this.cb.bogusNoderef("parse failed: " + ex);
							}
						}
					}
				}
				finally {
					synchronized (AnnounceSender.this) {
						AnnounceSender.this.waitingForTransfers--;
						AnnounceSender.this.notifyAll();
					}
				}
			}

		};
		try {
			this.node.executor.execute(r);
		}
		catch (Throwable ignored) {
			synchronized (this) {
				this.waitingForTransfers--;
			}
		}
	}

	/**
	 * Send an AnnouncementRequest.
	 * @param next The node to send the announcement to.
	 * @return True if the announcement was successfully sent.
	 */
	private long sendTo(PeerNode next) {
		try {
			return this.om.startSendAnnouncementRequest(this.uid, next, this.noderefBuf, this, this.target, this.htl);
		}
		catch (NotConnectedException ignored) {
			if (logMINOR) {
				Logger.minor(this, "Disconnected");
			}
			return -1;
		}
	}

	/**
	 * Send an AnnouncementRequest.
	 * @param next The node to send the announcement to.
	 */
	private void sendRest(PeerNode next, long xferUID) throws NotConnectedException {
		this.om.finishSentAnnouncementRequest(next, this.noderefBuf, this, xferUID);
	}

	private void timedOut(PeerNode next) {
		Message msg = DMT.createFNPRejectedOverload(this.uid, true, false, false);
		if (this.source != null) {
			try {
				this.source.sendAsync(msg, null, this);
			}
			catch (NotConnectedException ignored) {
				// Ok
			}
		}
		if (this.cb != null) {
			this.cb.nodeFailed(next, "timed out");
		}
	}

	private synchronized void waitForRunningTransfers() {
		while (this.waitingForTransfers > 0) {
			try {
				this.wait();
			}
			catch (InterruptedException ignored) {
				// Ignore.
			}
		}
	}

	private void rnf(PeerNode next) {
		this.waitForRunningTransfers();
		Message msg = DMT.createFNPRouteNotFound(this.uid, this.htl);
		if (this.source != null) {
			try {
				this.source.sendAsync(msg, null, this);
			}
			catch (NotConnectedException ignored) {
				// Ok
			}
		}
		if (this.cb != null) {
			if (next != null) {
				this.cb.nodeFailed(next, "route not found");
			}
			else {
				this.cb.noMoreNodes();
			}
		}
	}

	private void complete() {
		this.waitForRunningTransfers();
		Message msg = DMT.createFNPOpennetAnnounceCompleted(this.uid);
		if (this.source != null) {
			try {
				this.source.sendAsync(msg, null, this);
			}
			catch (NotConnectedException ignored) {
				// Oh well.
			}
		}
	}

	/**
	 * @return True unless the noderef is bogus.
	 */
	private boolean transferNoderef() {
		this.noderefBuf = OpennetManager.innerWaitForOpennetNoderef(this.xferUID, this.paddedLength, this.noderefLength,
				this.source, false, this.uid, true, this, this.node);
		if (this.noderefBuf == null) {
			return false;
		}
		SimpleFieldSet fs = OpennetManager.validateNoderef(this.noderefBuf, 0, this.noderefLength, this.source, false);
		if (fs == null) {
			OpennetManager.rejectRef(this.uid, this.source, DMT.NODEREF_REJECTED_INVALID, this);
			return false;
		}
		// If we want it, add it and send it.
		try {
			// Allow reconnection - sometimes one side has the ref and the other side
			// doesn't.
			if (this.om.addNewOpennetNode(fs, OpennetManager.ConnectionType.ANNOUNCE, true) != null) {
				this.sendOurRef(this.source, this.om.crypto.myCompressedFullRef());
			}
			else {
				if (logMINOR) {
					Logger.minor(this, "Don't need the node");
				}
				this.sendNotWanted();
				// Okay, just route it.
			}
		}
		catch (FSParseException | PeerParseException | ReferenceSignatureVerificationException ex) {
			Logger.warning(this, "Rejecting noderef: " + ex, ex);
			OpennetManager.rejectRef(this.uid, this.source, DMT.NODEREF_REJECTED_INVALID, this);
			return false;
		}
		catch (NotConnectedException ex) {
			Logger.normal(this, "Could not receive noderef, disconnected");
			return false;
		}
		return true;
	}

	private void sendNotWanted() throws NotConnectedException {
		Message msg = DMT.createFNPOpennetAnnounceNodeNotWanted(this.uid);
		this.source.sendAsync(msg, null, this);
	}

	private void sendOurRef(PeerNode next, byte[] ref) throws NotConnectedException {
		this.om.sendAnnouncementReply(this.uid, next, ref, this);
	}

	@Override
	public void sentBytes(int x) {
		this.node.nodeStats.announceByteCounter.sentBytes(x);
	}

	@Override
	public void receivedBytes(int x) {
		this.node.nodeStats.announceByteCounter.receivedBytes(x);
	}

	@Override
	public void sentPayload(int x) {
		this.node.nodeStats.announceByteCounter.sentPayload(x);
		// Doesn't count.
	}

	@Override
	public int getPriority() {
		return NativeThread.HIGH_PRIORITY;
	}

}
