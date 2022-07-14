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

package freenet.node.updater.usk;

import java.io.File;
import java.net.MalformedURLException;
import java.util.concurrent.TimeUnit;

import freenet.bucket.Bucket;
import freenet.bucket.FileBucket;
import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.FetchException.FetchExceptionMode;
import freenet.client.FetchResult;
import freenet.client.async.BinaryBlobWriter;
import freenet.client.async.ClientContext;
import freenet.client.async.ClientGetCallback;
import freenet.client.async.ClientGetter;
import freenet.client.async.PersistenceDisabledException;
import freenet.client.async.USKCallback;
import freenet.client.async.USKManager;
import freenet.client.request.PriorityClasses;
import freenet.client.request.RequestClient;
import freenet.keys.FreenetURI;
import freenet.keys.USK;
import freenet.node.Node;
import freenet.node.NodeClientCore;
import freenet.node.Version;
import freenet.node.updater.AbstractUpdateFileFetcher;
import freenet.nodelogger.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.Ticker;

// Was NodeUpdater
public abstract class AbstractUSKUpdateFileFetcher extends AbstractUpdateFileFetcher
		implements ClientGetCallback, USKCallback, RequestClient {

	private static boolean logMINOR;

	public final NodeClientCore core;

	private final FetchContext ctx;

	private final Ticker ticker;

	/**
	 * The temporary blob file that stores fetched data. If it's a valid file, it will be
	 * moved to blob file returned by {@link #getBlobFile()} in
	 * {@link #onSuccess(FetchResult, ClientGetter, File, int)}.
	 */
	protected File tempBlobFile;

	private ClientGetter cg;

	/**
	 * The available version found by fetching
	 * {@link AbstractUSKUpdateFileFetcher#updateURI}. It's updated each time a newer
	 * version is found by {@link USKManager}.
	 */
	private int realAvailableVersion;

	AbstractUSKUpdateFileFetcher(Node node, String fileType, int currentVersion, int minDeployVersion,
			int maxDeployVersion, FreenetURI updateURI) {

		super(node, fileType, currentVersion, minDeployVersion, maxDeployVersion);

		logMINOR = Logger.shouldLog(LogLevel.MINOR, this);

		this.updateURI = updateURI.setSuggestedEdition(Version.buildNumber() + 1);
		this.ticker = this.node.ticker;
		this.core = this.node.clientCore;
		this.availableVersion = -1;
		this.isRunning = true;
		this.cg = null;

		FetchContext tempContext = this.core.makeClient((short) 0, true, false).getFetchContext();
		tempContext.allowSplitfiles = true;
		tempContext.dontEnterImplicitArchives = false;
		this.ctx = tempContext;

	}

	public void start() {
		try {
			// because of UoM, this version is actually worth having as well
			USK myUsk = USK.create(this.updateURI.setSuggestedEdition(this.currentVersion));
			this.core.uskManager.subscribe(myUsk, this, true, this.getRequestClient());
			this.isRunning = true;
		}
		catch (MalformedURLException ignored) {
			Logger.error(this, "The auto-update URI isn't valid and can't be used");
			this.blow("The auto-update URI isn't valid and can't be used", true);
		}
	}

	private void finishOnFoundEdition(int found) {
		// leave some time in case we get later editions
		this.ticker.queueTimedJob(AbstractUSKUpdateFileFetcher.this::maybeFetch, TimeUnit.SECONDS.toMillis(60));
		// LOCKING: Always take the AbstractUSKUpdateFileFetcher lock *BEFORE* the
		// NodeUpdateManager lock
		if (found <= this.currentVersion) {
			System.err.println(
					"Cancelling fetch for " + found + ": not newer than current version " + this.currentVersion);
			return;
		}
		this.onStartFetching();
		Logger.minor(this, "Fetching " + this.getFileName() + " update edition " + found);
	}

	public void maybeFetch() {
		ClientGetter toStart = null;
		if (!this.updateEnabled) {
			return;
		}
		if (this.updateBlown) {
			return;
		}
		ClientGetter cancelled = null;
		synchronized (this) {
			if (logMINOR) {
				Logger.minor(this, "maybeUpdate: isFetching=" + this.isFetching + ", isRunning=" + this.isRunning
						+ ", availableVersion=" + this.availableVersion);
			}
			if (!this.isRunning) {
				return;
			}
			// Currently we're fetching this available version. No need to fetch again.
			if (this.isFetching && this.availableVersion == this.fetchingVersion) {
				return;
			}
			// Fetched version is the most up-to-date version
			if (this.availableVersion <= this.fetchedVersion) {
				return;
			}
			// Minimum deploy version or current version has changed. We don't need to
			// continue fetching the old version.
			if (this.fetchingVersion < this.minDeployVersion || this.fetchingVersion == this.currentVersion) {
				Logger.normal(this, "Cancelling previous fetch");
				cancelled = this.cg;
				this.cg = null;
			}
			this.fetchingVersion = this.availableVersion;

			if (this.availableVersion > this.currentVersion) {
				Logger.normal(this, "Starting the update process (" + this.availableVersion + ')');
				System.err.println("Starting the update process: found the update (" + this.availableVersion
						+ "), now fetching it.");
			}
			if (logMINOR) {
				Logger.minor(this, "Starting the update process (" + this.availableVersion + ')');
			}
			// We fetch it
			try {
				if ((this.cg == null) || this.cg.isCancelled()) {
					if (logMINOR) {
						Logger.minor(this,
								"Scheduling request for " + this.updateURI.setSuggestedEdition(this.availableVersion));
					}
					if (this.availableVersion > this.currentVersion) {
						System.err.println("Starting " + this.getFileName() + " fetch for " + this.availableVersion);
					}
					this.tempBlobFile = File.createTempFile(this.fileType + this.availableVersion + "-", ".fblob.tmp",
							this.node.clientCore.getPersistentTempDir());
					FreenetURI uri = this.updateURI.setSuggestedEdition(this.availableVersion);
					uri = uri.sskForUSK();
					this.cg = new ClientGetter(this, uri, this.ctx, PriorityClasses.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
							null, new BinaryBlobWriter(new FileBucket(this.tempBlobFile, false, false, false, false)),
							null);
					toStart = this.cg;
				}
				else {
					System.err.println("Already fetching " + this.getFileName() + " fetch for " + this.fetchingVersion
							+ " want " + this.availableVersion);
				}
				this.isFetching = true;
			}
			catch (Exception ex) {
				Logger.error(this, "Error while starting the fetching: " + ex, ex);
				this.isFetching = false;
			}
		}
		if (toStart != null) {
			try {
				this.node.clientCore.clientContext.start(toStart);
			}
			catch (FetchException ex) {
				Logger.error(this, "Error while starting the fetching: " + ex, ex);
				synchronized (this) {
					this.isFetching = false;
				}
			}
			catch (PersistenceDisabledException ignored) {
				// Impossible
			}
		}
		if (cancelled != null) {
			cancelled.cancel(this.core.clientContext);
		}
	}

	/**
	 * Called when we have fetched the file successfully.
	 * <p>
	 * It can be called by {@link ClientGetCallback#onSuccess} or
	 * {@link ManifestUSKUpdateFileFetcher#onUOMManifestRequestSuccess}.
	 * @param result fetch result
	 * @param state client getter state
	 * @param tempBlobFile temporary blob file
	 * @param fetchedVersion the version fetched
	 */
	@SuppressWarnings("ResultOfMethodCallIgnored")
	void onSuccess(FetchResult result, ClientGetter state, File tempBlobFile, int fetchedVersion) {
		logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
		File blobFile;
		synchronized (this) {
			if (fetchedVersion <= this.fetchedVersion) {
				tempBlobFile.delete();
				if (result != null) {
					Bucket toFree = result.asBucket();
					if (toFree != null) {
						toFree.free();
					}
				}
				return;
			}
			if (result == null || result.asBucket() == null || result.asBucket().size() == 0) {
				tempBlobFile.delete();
				Logger.error(this, "Cannot update: result either null or empty for " + this.availableVersion);
				System.err.println("Cannot update: result either null or empty for " + this.availableVersion);
				// Try again
				if (result == null || result.asBucket() == null || this.availableVersion > fetchedVersion) {
					this.node.ticker.queueTimedJob(AbstractUSKUpdateFileFetcher.this::maybeFetch, 0);
				}
				return;
			}
			blobFile = this.getBlobFile(fetchedVersion);
			if (!tempBlobFile.renameTo(blobFile)) {
				blobFile.delete();
				if (!tempBlobFile.renameTo(blobFile)) {
					if (blobFile.exists() && tempBlobFile.exists() && blobFile.length() == tempBlobFile.length()) {
						Logger.minor(this, "Can't rename " + tempBlobFile + " over " + blobFile + " for "
								+ fetchedVersion + " - probably not a big deal though as the files are the same size");
					}
					else {
						Logger.error(this, "Not able to rename binary blob for node updater: " + tempBlobFile + " -> "
								+ blobFile + " - may not be able to tell other peers about this build");
						blobFile = null;
					}
				}
			}
			this.fetchedVersion = fetchedVersion;
			System.out.println("Found " + this.getFileName() + " version " + fetchedVersion);
			if (fetchedVersion > this.currentVersion) {
				Logger.normal(this,
						"Found version " + fetchedVersion + ", setting up a new UpdatedVersionAvailableUserAlert");
			}
			this.cg = null;
			this.processSuccess(fetchedVersion, result, blobFile);
		}
	}

	/** Called before kill(). Don't do anything that will involve taking locks. */
	public void preKill() {
		this.isRunning = false;
	}

	public void kill() {
		try {
			ClientGetter c;
			synchronized (this) {
				this.isRunning = false;
				USK myUsk = USK.create(this.updateURI.setSuggestedEdition(this.currentVersion));
				this.core.uskManager.unsubscribe(myUsk, this);
				c = this.cg;
				this.cg = null;
			}
			c.cancel(this.core.clientContext);
		}
		catch (Exception ex) {
			Logger.minor(this, "Cannot kill USKUpdateFileFetcher", ex);
		}
	}

	public void cleanup() {
	}

	// TODO: move to?
	public synchronized boolean canUpdateNow() {
		return this.fetchedVersion > this.currentVersion;
	}

	/**
	 * Called when the fetch URI has changed. No major locks are held by caller.
	 * @param uri The new URI.
	 */
	public void onChangeURI(FreenetURI uri) {
		this.kill();
		this.updateURI = uri;
		this.maybeFetch();
	}

	// region ClientGetCallback methods
	// ================================================================================
	@Override
	public void onSuccess(FetchResult result, ClientGetter state) {
		this.onSuccess(result, state, this.tempBlobFile, this.fetchingVersion);
	}

	@Override
	public void onFailure(FetchException e, ClientGetter state) {
		logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
		if (!this.isRunning) {
			return;
		}
		FetchExceptionMode errorCode = e.getMode();
		// noinspection ResultOfMethodCallIgnored
		this.tempBlobFile.delete();

		if (logMINOR) {
			Logger.minor(this, "onFailure(" + e + ',' + state + ')');
		}
		synchronized (this) {
			this.cg = null;
			this.isFetching = false;
		}
		if (errorCode == FetchExceptionMode.CANCELLED || !e.isFatal()) {
			Logger.normal(this, "Rescheduling new request");
			this.ticker.queueTimedJob(AbstractUSKUpdateFileFetcher.this::maybeFetch, 0);
		}
		else {
			Logger.error(this, "Canceling fetch : " + e.getMessage());
			System.err.println("Unexpected error fetching update: " + e.getMessage());
			if (!e.isFatal()) {
				this.ticker.queueTimedJob(AbstractUSKUpdateFileFetcher.this::maybeFetch, TimeUnit.HOURS.toMillis(1));
			}
			// else wait for the next version
		}
	}

	@Override
	public void onResume(ClientContext context) {
		// Do nothing. Not persistent.
	}

	public RequestClient getRequestClient() {
		return this;
	}
	// ================================================================================
	// endregion

	// region USKCallback methods
	// ================================================================================
	@Override
	public void onFoundEdition(long l, USK key, ClientContext context, boolean wasMetadata, short codec, byte[] data,
			boolean newKnownGood, boolean newSlotToo) {
		if (newKnownGood && !newSlotToo) {
			return;
		}
		logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
		if (logMINOR) {
			Logger.minor(this, "Found edition " + l);
		}
		int found;
		synchronized (this) {
			if (!this.isRunning) {
				return;
			}
			found = (int) key.suggestedEdition;

			this.realAvailableVersion = found;
			if (found > this.maxDeployVersion) {
				System.err.println("Ignoring " + this.getFileName() + " update edition " + l + ": version too new (min "
						+ this.minDeployVersion + " max " + this.maxDeployVersion + ")");
				found = this.maxDeployVersion;
			}

			if (found <= this.availableVersion) {
				return;
			}
			System.err.println("Found " + this.getFileName() + " update edition " + found);
			Logger.minor(this, "Updating availableVersion from " + this.availableVersion + " to " + found
					+ " and queueing an update");
			this.availableVersion = found;
		}
		this.finishOnFoundEdition(found);
	}

	@Override
	public short getPollingPriorityNormal() {
		return PriorityClasses.IMMEDIATE_SPLITFILE_PRIORITY_CLASS;
	}

	@Override
	public short getPollingPriorityProgress() {
		return PriorityClasses.INTERACTIVE_PRIORITY_CLASS;
	}

	// ================================================================================
	// endregion

	// region RequestClient methods
	// ================================================================================
	@Override
	public boolean persistent() {
		return false;
	}

	@Override
	public boolean realTimeFlag() {
		return false;
	}
	// ================================================================================
	// endregion

}
