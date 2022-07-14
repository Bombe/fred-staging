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

package freenet.node.updater;

import java.io.File;

import freenet.bucket.Bucket;
import freenet.bucket.FileBucket;
import freenet.bucket.RandomAccessBucket;
import freenet.client.FetchResult;
import freenet.keys.FreenetURI;
import freenet.node.Node;
import freenet.node.Version;
import freenet.node.event.EventBus;
import freenet.node.event.update.BlownEvent;
import freenet.node.event.update.UpdateFileFetchedEvent;
import freenet.node.event.update.UpdateManagerStatusUpdatedEvent;
import freenet.node.event.update.UpdateManagerStatusUpdatedEvent.StatusType;
import freenet.node.updater.usk.AbstractUSKUpdateFileFetcher;
import freenet.nodelogger.Logger;
import org.greenrobot.eventbus.Subscribe;

public abstract class AbstractUpdateFileFetcher {

	private static boolean logMINOR;

	protected final Node node;

	protected FreenetURI updateURI;

	/** Maximum version that current version can be updated to */
	protected final int maxDeployVersion;

	/** Minimum version that current version can be updated to */
	protected final int minDeployVersion;

	/**
	 * The newest (largest) available version found.
	 */
	protected int availableVersion;

	/**
	 * The newest (largest) version that has been fetched. The value is 0 if no version
	 * has been fetched yet.
	 * <p>
	 * Note the difference between {@link #fetchedVersion} and
	 * {@link #fetchedFileVersion}: {@link #fetchedVersion} is always set to the latest
	 * known version. {@link #fetchedFileVersion} is set to the latest version only if the
	 * node is not deploying the update. Otherwise {@link #maybeNextFileVersion} is set to
	 * the latest version.
	 */
	protected int fetchedVersion;

	/**
	 * The newest (largest) available version found by fetching
	 * {@link AbstractUSKUpdateFileFetcher#updateURI} and is currently being fetched.
	 */
	protected int fetchingVersion;

	/** Is the Updater fetching file? */
	protected boolean isFetching;

	/** Is the Fetcher running? */
	protected boolean isRunning;

	/** Current version we have. Usually it should be ored's build number. */
	protected final int currentVersion;

	protected final UpdateFileType fileType;

	/** Is there a new update file ready to deploy? */
	protected volatile boolean hasNewFile;

	/**
	 * The version we have fetched and will deploy. If currently the node is deploying the
	 * update, this field won't be updated to the latest version got from USK. Instead,
	 * the latest version will be assigned to {@link #maybeNextFileVersion}.
	 * <p>
	 * Note the difference between {@link #fetchedVersion} and
	 * {@link #fetchedFileVersion}: {@link #fetchedVersion} is always set to the latest
	 * known version. {@link #fetchedFileVersion} is set to the latest version only if the
	 * node is not deploying the update. Otherwise {@link #maybeNextFileVersion} is set to
	 * the latest version.
	 */
	protected int fetchedFileVersion;

	/** The update file of the version we have fetched and will deploy. */
	protected Bucket fetchedFileData;

	/** If another file is being fetched, when did the fetch start? */
	protected long startedFetchingNextFile;

	/** Time when we got the file */
	private long gotFileTime;

	/**
	 * The version we have fetched and aren't using because we are already deploying.
	 */
	private int maybeNextFileVersion;

	/**
	 * The version we have fetched and aren't using because we are already deploying.
	 */
	private Bucket maybeNextFileData;

	/** Whether update is enabled. */
	protected volatile boolean updateEnabled;

	/** Whether this version of update has been blown. */
	protected volatile boolean updateBlown;

	/** Whether update is being deployed. */
	protected volatile boolean updateDeploying;

	/** Whether user triggered the update. */
	protected volatile boolean updateArmed;

	protected AbstractUpdateFileFetcher(Node node, UpdateFileType fileType, int currentVersion, int minDeployVersion,
			int maxDeployVersion) {

		this.node = node;
		this.fileType = fileType;
		this.currentVersion = currentVersion;
		this.minDeployVersion = minDeployVersion;
		this.maxDeployVersion = maxDeployVersion;
		this.isFetching = false;
		EventBus.get().register(this);
	}

	// region EventBus
	// ================================================================================
	/**
	 * An event is received when {@link NodeUpdateManager} changes its status.
	 */
	@Subscribe(sticky = true)
	public void onUpdateManagerStatusUpdated(UpdateManagerStatusUpdatedEvent event) {
		this.updateEnabled = event.getStatus(StatusType.ENABLED);
		this.updateBlown = event.getStatus(StatusType.BLOWN);
		this.updateDeploying = event.getStatus(StatusType.DEPLOYING);
		this.updateArmed = event.getStatus(StatusType.ARMED);
	}

	/**
	 * An event is received when a Fetcher finished fetching an update file.
	 */
	@Subscribe
	public void onUpdateFileFetched(UpdateFileFetchedEvent event) {
		AbstractUpdateFileFetcher fetcher = event.getFetcher();
		if (fetcher == this) {
			// Do nothing if the event is posted by this fetcher
			return;
		}

		if (fetcher.getFileName().equals(this.getFileName()) && fetcher.getFetchedFileVersion() > this.fetchedVersion) {
			// Update fetchedFileVersion so that this fetcher will stop current work and
			// wait for a newer version if this fetcher is fetching an older version
			this.fetchedVersion = fetcher.getFetchedFileVersion();
		}
	}

	protected void blow(String message, boolean disabledNotBlown) {
		EventBus.get().post(new BlownEvent(message, disabledNotBlown));
	}

	protected void fileFetched() {
		EventBus.get().post(new UpdateFileFetchedEvent(this));
	}

	// ================================================================================
	// endregion

	/**
	 * Called when we have fetched the file! Do something after onSuccess(). Called
	 * unlocked.
	 * @param fetched the version fetched
	 * @param result fetch result
	 * @param blobFile fetched blob file
	 */
	protected void processSuccess(int fetched, FetchResult result, File blobFile) {
		if (fetched > Version.buildNumber()) {
			this.hasNewFile = true;
			this.startedFetchingNextFile = -1;
			this.gotFileTime = System.currentTimeMillis();
			if (logMINOR) {
				Logger.minor(this, "Got update file: " + fetched);
			}
		}
		Bucket delete1 = null;
		Bucket delete2 = null;

		synchronized (this) {
			if (!this.updateDeploying) {
				delete1 = this.fetchedFileData;
				this.fetchedFileVersion = fetched;
				this.fetchedFileData = result.asBucket();
				if (fetched == Version.buildNumber()) {
					if (blobFile != null) {
						// TODO: move to NodeUpdateManager
						// this.currentVersionBlobFile = blobFile;
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
				System.out.println("Already deploying update, not using the latest version of installer #" + fetched);
			}
		}
		if (delete1 != null) {
			delete1.free();
		}
		if (delete2 != null) {
			delete2.free();
		}

		this.fileFetched();
	}

	protected void onStartFetching() {
		long now = System.currentTimeMillis();
		synchronized (this) {
			this.startedFetchingNextFile = now;
		}
	}

	/**
	 * Called when the fetch URI has changed. No major locks are held by caller.
	 * @param uri The new URI.
	 */
	public abstract void onChangeURI(FreenetURI uri);

	public abstract String getFileName();

	public void preKill() {
		this.isRunning = false;
	}

	public abstract void kill();

	// region Getter/Setter
	// ================================================================================
	/** Return whether there a new file ready to deploy. */
	public boolean isHasNewFile() {
		return this.hasNewFile;
	}

	/** Return the version we have fetched and will deploy. */
	public int getFetchedFileVersion() {
		return this.fetchedFileVersion;
	}

	/** Retrun the update file of the version we have fetched and will deploy. */
	public Bucket getFetchedFileData() {
		return this.fetchedFileData;
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

	public final File getBlobFile(int availableVersion) {
		return new File(this.node.clientCore.getPersistentTempDir(), this.fileType.label + availableVersion + ".fblob");
	}

	RandomAccessBucket getBlobBucket(int availableVersion) {
		File f = this.getBlobFile(availableVersion);
		return new FileBucket(f, true, false, false, false);
	}

	public void setFetchedFileVersion(int fetchedFileVersion) {
		this.fetchedFileVersion = fetchedFileVersion;
	}

	public void setFetchedFileData(Bucket fetchedFileData) {
		this.fetchedFileData = fetchedFileData;
	}
	// ================================================================================
	// endregion

}
