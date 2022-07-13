/*
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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

import freenet.client.request.PriorityClasses;
import freenet.io.comm.AsyncMessageCallback;
import freenet.io.comm.DMT;
import freenet.io.comm.DisconnectedException;
import freenet.io.comm.Message;
import freenet.io.comm.NotConnectedException;
import freenet.io.xfer.BulkTransmitter;
import freenet.io.xfer.PartiallyReceivedBulk;
import freenet.keys.FreenetURI;
import freenet.lockablebuffer.FileRandomAccessBuffer;
import freenet.node.Node;
import freenet.node.PeerNode;
import freenet.node.Version;
import freenet.node.event.update.UOMManifestRequestSuccessEvent;
import freenet.node.updater.RevocationChecker;
import freenet.node.updater.UpdateOverMandatoryManager;
import freenet.node.updater.usk.ManifestUSKUpdateFileFetcher;
import freenet.nodelogger.Logger;
import org.greenrobot.eventbus.Subscribe;

public class ManifestUOMUpdateFileExchanger extends AbstractUOMUpdateFileExchanger {

	private static volatile boolean logMINOR;

	static {
		Logger.registerClass(UpdateOverMandatoryManager.class);
	}

	public ManifestUOMUpdateFileExchanger(Node node, int currentVersion, int minDeployVersion, int maxDeployVersion,
			FreenetURI updateURI, FreenetURI revocationURI, RevocationChecker revocationChecker) {

		super(node, "manifest", currentVersion, minDeployVersion, maxDeployVersion, updateURI, revocationURI,
				revocationChecker);
	}

	/**
	 * The event is fired in {@link UpdateOverMandatoryManager#processManifestBlob} after
	 * UoM has successfully fetched manifest file and ClientGetter got it from local
	 * datastore.
	 */
	@Subscribe
	public void onUOMManifestRequestSuccess(UOMManifestRequestSuccessEvent event) {
		if (this.isRunning) {
			this.onSuccess(event.getResult(), event.getState(), event.getCleanedBlobFile(), event.getVersion());
		}
		else {
			System.err.println("Not updating because updater is disabled!");
		}

		this.maybeInsertManifest(event.getSource(), event.getVersion());
	}

	protected Message getUOMAnnounceUpdateFile(long blobSize) {
		int fetchedVersion = (blobSize <= 0) ? -1 : Version.buildNumber();
		return DMT.createUOMAnnounceUpdateFile(this.getFileType(), this.updateURI.toString(),
				this.revocationURI.toString(), this.revocationChecker.hasBlown(), fetchedVersion,
				this.revocationChecker.lastSucceededDelta(), this.revocationChecker.getRevocationDNFCounter(),
				this.revocationChecker.getBlobSize(), blobSize, (int) this.nodeStats.getNodeAveragePingTime(),
				(int) this.nodeStats.getBwlimitDelayTime());
	}

	@Override
	public void start() {
		this.manager.uom.maybeProcessOldBlob(this.getBlobFile(), this.updateURI, this.currentVersion);
		super.start();
	}

	@Override
	protected String getFileType() {
		return "manifest";
	}

	public void onStartFetchingUOM() {
		// TODO: fetch package files
	}

	/** Maybe insert the main jar blob. If so, compute the appropriate priority. */
	protected void maybeInsertManifest(PeerNode source, int version) {
		short priority = PriorityClasses.BULK_SPLITFILE_PRIORITY_CLASS;
		if (source != null) {
			// We got it from another node.
			priority = PriorityClasses.IMMEDIATE_SPLITFILE_PRIORITY_CLASS;
		}
		else if (this.node.lastVersion > 0 && this.node.lastVersion != version) {
			// We just restarted after updating.
			priority = PriorityClasses.IMMEDIATE_SPLITFILE_PRIORITY_CLASS;
		}
		else if (this.node.fastWeakRandom.nextInt(RANDOM_INSERT_BLOB) != 0) {
			// 1 in RANDOM_INSERT_BLOB chance of inserting anyway at bulk priority.
			return;
		}
		this.manager.uom.insertBlob(this.getBlobBucket(version), "manifest", priority);
	}

	public void handleRequestManifest(Message message, final PeerNode source) {
		Message msg;
		final BulkTransmitter bt;
		final FileRandomAccessBuffer raf;

		if (source.isOpennet() && this.manager.dontAllowUOM()) {
			Logger.normal(this,
					"Peer " + source + " asked us for the blob file for manifest; We are a seenode, so we ignore it!");
			return;
		}
		// Do we have the data?

		File blobFile = this.getCurrentVersionBlobFile();
		int version = Version.buildNumber();
		FreenetURI uri = this.manager.getURI();

		if (blobFile == null) {
			Logger.normal(this,
					"Peer " + source + " asked us for the blob file for the manifest but we don't have it!");
			// Probably a race condition on reconnect, hopefully we'll be asked again
			return;
		}

		final long uid = message.getLong(DMT.UID);

		if (!source.sendingUOMManifest()) {
			Logger.error(this, "Peer " + source + " asked for UOM manifest twice");
			return;
		}

		try {

			try {
				raf = new FileRandomAccessBuffer(blobFile, true);
			}
			catch (FileNotFoundException ex) {
				Logger.error(this, "Peer " + source
						+ " asked us for the blob file for the manifest, we have downloaded it but don't have the file even though we did have it when we checked!: "
						+ ex, ex);
				return;
			}
			catch (IOException ex) {
				Logger.error(this, "Peer " + source
						+ " asked us for the blob file for the manifest, we have downloaded it but can't read the file due to a disk I/O error: "
						+ ex, ex);
				return;
			}

			final PartiallyReceivedBulk prb;
			long length;
			length = raf.size();
			prb = new PartiallyReceivedBulk(this.node.getUSM(), length, Node.PACKET_SIZE, raf, true);

			try {
				bt = new BulkTransmitter(prb, source, uid, false, this.manager.ctr, true);
			}
			catch (DisconnectedException ex) {
				Logger.error(this,
						"Peer " + source + " asked us for the blob file for the manifest, then disconnected: " + ex,
						ex);
				raf.close();
				return;
			}

			msg = DMT.createUOMSendingManifest(uid, length, uri.toString(), version);

		}
		catch (RuntimeException | Error ex) {
			source.finishedSendingUOMManifest();
			throw ex;
		}

		final Runnable r = new Runnable() {

			@Override
			public void run() {
				try {
					if (!bt.send()) {
						Logger.error(this, "Failed to send manifest blob to " + source.userToString() + " : "
								+ bt.getCancelReason());
					}
					else {
						Logger.normal(this, "Sent manifest blob to " + source.userToString());
					}
					raf.close();
				}
				catch (DisconnectedException ignored) {
					// Not much we can do.
				}
				finally {
					source.finishedSendingUOMManifest();
					raf.close();
				}
			}
		};

		try {
			source.sendAsync(msg, new AsyncMessageCallback() {

				@Override
				public void acknowledged() {
					if (logMINOR) {
						Logger.minor(this, "Sending data...");
					}
					// Send the data

					ManifestUSKUpdateFileFetcher.this.node.executor.execute(r,
							"manifest send for " + uid + " to " + source.userToString());
				}

				@Override
				public void disconnected() {
					// Argh
					Logger.error(this, "Peer " + source
							+ " asked us for the blob file for the manifest, then disconnected when we tried to send the UOMSendingMainJar");
					source.finishedSendingUOMManifest();
				}

				@Override
				public void fatalError() {
					// Argh
					Logger.error(this, "Peer " + source
							+ " asked us for the blob file for the manifest, then got a fatal error when we tried to send the UOMSendingMainJar");
					source.finishedSendingUOMManifest();
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
			}, this.manager.ctr);
		}
		catch (NotConnectedException ex) {
			Logger.error(this, "Peer " + source
					+ " asked us for the blob file for the manifest, then disconnected when we tried to send the UOMSendingMainJar: "
					+ ex, ex);
		}
		catch (RuntimeException | Error ex) {
			source.finishedSendingUOMManifest();
			throw ex;
		}

	}

	public synchronized File getCurrentVersionBlobFile() {
		// TODO
		if (this.isHasNewFile()) {
			return null;
		}
		if (this.manager.isDeployingUpdate()) {
			return null;
		}
		if (this.fetchedVersion != Version.buildNumber()) {
			return null;
		}
		return this.currentVersionBlobFile;
	}

}
