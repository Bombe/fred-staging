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

import java.io.File;
import java.net.MalformedURLException;
import java.util.concurrent.TimeUnit;

import freenet.bucket.Bucket;
import freenet.bucket.FileBucket;
import freenet.bucket.RandomAccessBucket;
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
import freenet.nodelogger.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.Ticker;

// Was NodeUpdater
public abstract class AbstractFileUpdater implements ClientGetCallback, USKCallback, RequestClient {

	private static boolean logMINOR;

	private final FetchContext ctx;

	private ClientGetter cg;

	protected FreenetURI URI;

	private final Ticker ticker;

	public final NodeClientCore core;

	protected final Node node;

	public final NodeUpdateManager manager;

	/** Current version we have. Usually it should be ored's build number. */
	protected final int currentVersion;

	/**
	 * The available version found by fetching {@link AbstractFileUpdater#URI}. It's
	 * updated each time a newer version is found by {@link USKManager}.
	 */
	private int realAvailableVersion;

	/**
	 * The newest (largest) available version found by fetching
	 * {@link AbstractFileUpdater#URI}.
	 */
	protected int availableVersion;

	/**
	 * The newest (largest) available version found by fetching
	 * {@link AbstractFileUpdater#URI} and is currently being fetched.
	 */
	private int fetchingVersion;

	/**
	 * The newest (largest) version that has been fetched. The value is 0 if no version
	 * has been fetched yet.
	 */
	protected int fetchedVersion;

	/** Maximum version that current version can be updated to */
	private final int maxDeployVersion;

	/** Minimum version that current version can be updated to */
	private final int minDeployVersion;

	/** Is the Updater running? */
	private boolean isRunning;

	/** Is the Updater fetching file? */
	private boolean isFetching;

	protected final String blobFilenamePrefix;

	protected File tempBlobFile;

	/** Is there a new file ready to deploy? */
	private volatile boolean hasNewFile;

	/** If another file is being fetched, when did the fetch start? */
	private long startedFetchingNextFile;

	/** Time when we got the file */
	private long gotFileTime;

	/** The version we have fetched and will deploy. */
	private int fetchedFileVersion;

	/** The jar of the version we have fetched and will deploy. */
	private Bucket fetchedFileData;

	/**
	 * The version we have fetched and aren't using because we are already deploying.
	 */
	private int maybeNextFileVersion;

	/**
	 * The version we have fetched and aren't using because we are already deploying.
	 */
	private Bucket maybeNextFileData;

	/** The blob file for the current version, for UOM */
	private File currentVersionBlobFile;

	public abstract String fileName();

	AbstractFileUpdater(NodeUpdateManager manager, FreenetURI URI, int current, int min, int max,
			String blobFilenamePrefix) {
		logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
		this.manager = manager;
		this.node = manager.node;
		this.URI = URI.setSuggestedEdition(Version.buildNumber() + 1);
		this.ticker = this.node.ticker;
		this.core = this.node.clientCore;
		this.currentVersion = current;
		this.availableVersion = -1;
		this.isRunning = true;
		this.cg = null;
		this.isFetching = false;
		this.blobFilenamePrefix = blobFilenamePrefix;
		this.maxDeployVersion = max;
		this.minDeployVersion = min;

		FetchContext tempContext = this.core.makeClient((short) 0, true, false).getFetchContext();
		tempContext.allowSplitfiles = true;
		tempContext.dontEnterImplicitArchives = false;
		this.ctx = tempContext;

	}

	void start() {
		try {
			// because of UoM, this version is actually worth having as well
			USK myUsk = USK.create(this.URI.setSuggestedEdition(this.currentVersion));
			this.core.uskManager.subscribe(myUsk, this, true, this.getRequestClient());
		}
		catch (MalformedURLException ignored) {
			Logger.error(this, "The auto-update URI isn't valid and can't be used");
			this.manager.blow("The auto-update URI isn't valid and can't be used", true);
		}
	}

	public RequestClient getRequestClient() {
		return this;
	}

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
				System.err.println("Ignoring " + this.fileName() + " update edition " + l + ": version too new (min "
						+ this.minDeployVersion + " max " + this.maxDeployVersion + ")");
				found = this.maxDeployVersion;
			}

			if (found <= this.availableVersion) {
				return;
			}
			System.err.println("Found " + this.fileName() + " update edition " + found);
			Logger.minor(this, "Updating availableVersion from " + this.availableVersion + " to " + found
					+ " and queueing an update");
			this.availableVersion = found;
		}
		this.finishOnFoundEdition(found);
	}

	private void finishOnFoundEdition(int found) {
		// leave some time in case we get later editions
		this.ticker.queueTimedJob(AbstractFileUpdater.this::maybeUpdate, TimeUnit.SECONDS.toMillis(60));
		// LOCKING: Always take the NodeUpdater lock *BEFORE* the NodeUpdateManager lock
		if (found <= this.currentVersion) {
			System.err.println(
					"Cancelling fetch for " + found + ": not newer than current version " + this.currentVersion);
			return;
		}
		this.onStartFetching();
		Logger.minor(this, "Fetching " + this.fileName() + " update edition " + found);
	}

	protected void onStartFetching() {
		long now = System.currentTimeMillis();
		synchronized (this) {
			this.startedFetchingNextFile = now;
		}
	}

	public void maybeUpdate() {
		ClientGetter toStart = null;
		if (!this.manager.isEnabled()) {
			return;
		}
		if (this.manager.isBlown()) {
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
								"Scheduling request for " + this.URI.setSuggestedEdition(this.availableVersion));
					}
					if (this.availableVersion > this.currentVersion) {
						System.err.println("Starting " + this.fileName() + " fetch for " + this.availableVersion);
					}
					this.tempBlobFile = File.createTempFile(this.blobFilenamePrefix + this.availableVersion + "-",
							".fblob.tmp", this.manager.node.clientCore.getPersistentTempDir());
					FreenetURI uri = this.URI.setSuggestedEdition(this.availableVersion);
					uri = uri.sskForUSK();
					this.cg = new ClientGetter(this, uri, this.ctx, PriorityClasses.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
							null, new BinaryBlobWriter(new FileBucket(this.tempBlobFile, false, false, false, false)),
							null);
					toStart = this.cg;
				}
				else {
					System.err.println("Already fetching " + this.fileName() + " fetch for " + this.fetchingVersion
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

	final File getBlobFile(int availableVersion) {
		return new File(this.node.clientCore.getPersistentTempDir(),
				this.blobFilenamePrefix + availableVersion + ".fblob");
	}

	RandomAccessBucket getBlobBucket(int availableVersion) {
		File f = this.getBlobFile(availableVersion);
		return new FileBucket(f, true, false, false, false);
	}

	@Override
	public void onSuccess(FetchResult result, ClientGetter state) {
		this.onSuccess(result, state, this.tempBlobFile, this.fetchingVersion);
	}

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
					this.node.ticker.queueTimedJob(AbstractFileUpdater.this::maybeUpdate, 0);
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
			System.out.println("Found " + this.fileName() + " version " + fetchedVersion);
			if (fetchedVersion > this.currentVersion) {
				Logger.normal(this,
						"Found version " + fetchedVersion + ", setting up a new UpdatedVersionAvailableUserAlert");
			}
			this.cg = null;
		}
		this.processSuccess(fetchedVersion, result, blobFile);
	}

	/** We have fetched the file! Do something after onSuccess(). Called unlocked. */
	protected void processSuccess(int fetched, FetchResult result, File blobFile) {
		if (fetched > Version.buildNumber()) {
			this.hasNewFile = true;
			this.startedFetchingNextFile = -1;
			this.gotFileTime = System.currentTimeMillis();
			if (logMINOR) {
				Logger.minor(this, "Got main jar: " + fetched);
			}
		}
		Bucket delete1 = null;
		Bucket delete2 = null;

		synchronized (this.manager) {
			synchronized (this) {
				if (!this.manager.isDeployingUpdate()) {
					delete1 = this.fetchedFileData;
					this.fetchedFileVersion = fetched;
					this.fetchedFileData = result.asBucket();
					if (fetched == Version.buildNumber()) {
						if (blobFile != null) {
							this.currentVersionBlobFile = blobFile;
						}
						else {
							Logger.error(this, "No blob file for latest version?!", new Exception("error"));
						}
					}
				}
				else {
					delete2 = this.maybeNextFileData;
					this.maybeNextFileVersion = fetched;
					this.maybeNextFileData = result.asBucket();
					System.out.println("Already deploying update, not using new main jar #" + fetched);
				}
			}
		}
		if (delete1 != null) {
			delete1.free();
		}
		if (delete2 != null) {
			delete2.free();
		}

		// TODO: deploy
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
			this.ticker.queueTimedJob(AbstractFileUpdater.this::maybeUpdate, 0);
		}
		else {
			Logger.error(this, "Canceling fetch : " + e.getMessage());
			System.err.println("Unexpected error fetching update: " + e.getMessage());
			if (!e.isFatal()) {
				this.ticker.queueTimedJob(AbstractFileUpdater.this::maybeUpdate, TimeUnit.HOURS.toMillis(1));
			}
			// else wait for the next version
		}
	}

	/** Called before kill(). Don't do anything that will involve taking locks. */
	public void preKill() {
		this.isRunning = false;
	}

	void kill() {
		try {
			ClientGetter c;
			synchronized (this) {
				this.isRunning = false;
				USK myUsk = USK.create(this.URI.setSuggestedEdition(this.currentVersion));
				this.core.uskManager.unsubscribe(myUsk, this);
				c = this.cg;
				this.cg = null;
			}
			c.cancel(this.core.clientContext);
		}
		catch (Exception ex) {
			Logger.minor(this, "Cannot kill NodeUpdater", ex);
		}
	}

	public abstract void cleanup();

	public FreenetURI getUpdateKey() {
		return this.URI;
	}

	public synchronized boolean canUpdateNow() {
		return this.fetchedVersion > this.currentVersion;
	}

	/**
	 * Called when the fetch URI has changed. No major locks are held by caller.
	 * @param uri The new URI.
	 */
	public void onChangeURI(FreenetURI uri) {
		this.kill();
		this.URI = uri;
		this.maybeUpdate();
	}

	public int getFetchedVersion() {
		return this.fetchedVersion;
	}

	public boolean isFetching() {
		return this.availableVersion > this.fetchedVersion && this.availableVersion > this.currentVersion;
	}

	public int fetchingVersion() {
		// We will not deploy currentVersion...
		if (this.fetchingVersion <= this.currentVersion) {
			return this.availableVersion;
		}
		else {
			return this.fetchingVersion;
		}
	}

	public long getBlobSize() {
		return this.getBlobFile(this.getFetchedVersion()).length();
	}

	public File getBlobFile() {
		return this.getBlobFile(this.getFetchedVersion());
	}

	@Override
	public short getPollingPriorityNormal() {
		return PriorityClasses.IMMEDIATE_SPLITFILE_PRIORITY_CLASS;
	}

	@Override
	public short getPollingPriorityProgress() {
		return PriorityClasses.INTERACTIVE_PRIORITY_CLASS;
	}

	@Override
	public boolean persistent() {
		return false;
	}

	@Override
	public boolean realTimeFlag() {
		return false;
	}

	@Override
	public void onResume(ClientContext context) {
		// Do nothing. Not persistent.
	}

	public boolean isHasNewFile() {
		return this.hasNewFile;
	}

	public long getStartedFetchingNextFile() {
		return this.startedFetchingNextFile;
	}

	public long getGotFileTime() {
		return this.gotFileTime;
	}

	public void setGotFileTime(long gotFileTime) {
		this.gotFileTime = gotFileTime;
	}

	public int getFetchedFileVersion() {
		return this.fetchedFileVersion;
	}

	public void setFetchedFileVersion(int fetchedFileVersion) {
		this.fetchedFileVersion = fetchedFileVersion;
	}

	public Bucket getFetchedFileData() {
		return this.fetchedFileData;
	}

	public void setFetchedFileData(Bucket fetchedFileData) {
		this.fetchedFileData = fetchedFileData;
	}

	public int getMaybeNextFileVersion() {
		return this.maybeNextFileVersion;
	}

	public void setMaybeNextFileVersion(int maybeNextFileVersion) {
		this.maybeNextFileVersion = maybeNextFileVersion;
	}

	public Bucket getMaybeNextFileData() {
		return this.maybeNextFileData;
	}

	public void setMaybeNextFileData(Bucket maybeNextFileData) {
		this.maybeNextFileData = maybeNextFileData;
	}

}
