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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

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
import freenet.support.io.Closer;
import freenet.support.io.FileUtil;
import freenet.support.io.NullOutputStream;

public abstract class NodeUpdater implements ClientGetCallback, USKCallback, RequestClient {

	private static boolean logMINOR;

	private final FetchContext ctx;

	private ClientGetter cg;

	private FreenetURI URI;

	private final Ticker ticker;

	public final NodeClientCore core;

	protected final Node node;

	public final NodeUpdateManager manager;

	private final int currentVersion;

	private int realAvailableVersion;

	private int availableVersion;

	private int fetchingVersion;

	protected int fetchedVersion;

	private int maxDeployVersion;

	private int minDeployVersion;

	private boolean isRunning;

	private boolean isFetching;

	private final String blobFilenamePrefix;

	protected File tempBlobFile;

	public abstract String jarName();

	NodeUpdater(NodeUpdateManager manager, FreenetURI URI, int current, int min, int max, String blobFilenamePrefix) {
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

	protected void maybeProcessOldBlob() {
		File oldBlob = this.getBlobFile(this.currentVersion);
		if (oldBlob.exists()) {
			File temp;
			try {
				temp = File.createTempFile(this.blobFilenamePrefix + this.availableVersion + "-", ".fblob.tmp",
						this.manager.node.clientCore.getPersistentTempDir());
			}
			catch (IOException ex) {
				Logger.error(this, "Unable to process old blob: " + ex, ex);
				return;
			}
			if (oldBlob.renameTo(temp)) {
				FreenetURI uri = this.URI.setSuggestedEdition(this.currentVersion);
				uri = uri.sskForUSK();
				try {
					this.manager.uom.processMainJarBlob(temp, null, this.currentVersion, uri);
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
				System.err.println("Ignoring " + this.jarName() + " update edition " + l + ": version too new (min "
						+ this.minDeployVersion + " max " + this.maxDeployVersion + ")");
				found = this.maxDeployVersion;
			}

			if (found <= this.availableVersion) {
				return;
			}
			System.err.println("Found " + this.jarName() + " update edition " + found);
			Logger.minor(this, "Updating availableVersion from " + this.availableVersion + " to " + found
					+ " and queueing an update");
			this.availableVersion = found;
		}
		this.finishOnFoundEdition(found);
	}

	private void finishOnFoundEdition(int found) {
		// leave some time in case we get later editions
		this.ticker.queueTimedJob(NodeUpdater.this::maybeUpdate, TimeUnit.SECONDS.toMillis(60));
		// LOCKING: Always take the NodeUpdater lock *BEFORE* the NodeUpdateManager lock
		if (found <= this.currentVersion) {
			System.err.println(
					"Cancelling fetch for " + found + ": not newer than current version " + this.currentVersion);
			return;
		}
		this.onStartFetching();
		Logger.minor(this, "Fetching " + this.jarName() + " update edition " + found);
	}

	protected abstract void onStartFetching();

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
			if (this.isFetching && this.availableVersion == this.fetchingVersion) {
				return;
			}
			if (this.availableVersion <= this.fetchedVersion) {
				return;
			}
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
						System.err.println("Starting " + this.jarName() + " fetch for " + this.availableVersion);
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
					System.err.println("Already fetching " + this.jarName() + " fetch for " + this.fetchingVersion
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
					this.node.ticker.queueTimedJob(NodeUpdater.this::maybeUpdate, 0);
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
			System.out.println("Found " + this.jarName() + " version " + fetchedVersion);
			if (fetchedVersion > this.currentVersion) {
				Logger.normal(this,
						"Found version " + fetchedVersion + ", setting up a new UpdatedVersionAvailableUserAlert");
			}
			this.maybeParseManifest(result, fetchedVersion);
			this.cg = null;
		}
		this.processSuccess(fetchedVersion, result, blobFile);
	}

	/** We have fetched the jar! Do something after onSuccess(). Called unlocked. */
	protected abstract void processSuccess(int fetched, FetchResult result, File blobFile);

	/**
	 * Called with locks held
	 * @param result
	 */
	protected abstract void maybeParseManifest(FetchResult result, int build);

	protected void parseManifest(FetchResult result) {
		InputStream is = null;
		try {
			is = result.asBucket().getInputStream();
			ZipInputStream zis = new ZipInputStream(is);
			try {
				ZipEntry ze;
				while (true) {
					ze = zis.getNextEntry();
					if (ze == null) {
						break;
					}
					if (ze.isDirectory()) {
						continue;
					}
					String name = ze.getName();

					if (name.equals("META-INF/MANIFEST.MF")) {
						if (logMINOR) {
							Logger.minor(this, "Found manifest");
						}
						long size = ze.getSize();
						if (logMINOR) {
							Logger.minor(this, "Manifest size: " + size);
						}
						if (size > MAX_MANIFEST_SIZE) {
							Logger.error(this,
									"Manifest is too big: " + size + " bytes, limit is " + MAX_MANIFEST_SIZE);
							break;
						}
						byte[] buf = new byte[(int) size];
						DataInputStream dis = new DataInputStream(zis);
						dis.readFully(buf);
						ByteArrayInputStream bais = new ByteArrayInputStream(buf);
						InputStreamReader isr = new InputStreamReader(bais, StandardCharsets.UTF_8);
						BufferedReader br = new BufferedReader(isr);
						String line;
						while ((line = br.readLine()) != null) {
							this.parseManifestLine(line);
						}
					}
					else {
						zis.closeEntry();
					}
				}
			}
			finally {
				Closer.close(zis);
			}
		}
		catch (IOException ex) {
			Logger.error(this, "IOException trying to read manifest on update");
		}
		catch (Throwable ex) {
			Logger.error(this, "Failed to parse update manifest: " + ex, ex);
		}
		finally {
			Closer.close(is);
		}
	}

	static final String DEPENDENCIES_FILE = "dependencies.properties";

	/**
	 * Read the jar file. Parse the Properties. Read every file in the ZIP; if it is
	 * corrupted, we will get a CRC error and therefore an IOException, and so the update
	 * won't be deployed. This is not entirely foolproof because ZipInputStream doesn't
	 * check the CRC for stored files, only for deflated files, and it's only a CRC32
	 * anyway. But it should reduce the chances of accidental corruption breaking an
	 * update.
	 * @param is The InputStream for the jar file.
	 * @param filename The filename of the manifest file containing the properties
	 * (normally META-INF/MANIFEST.MF).
	 * @throws IOException If there is a temporary files error or the jar is corrupted.
	 */
	static Properties parseProperties(InputStream is, String filename) throws IOException {
		Properties props = new Properties();
		ZipInputStream zis = new ZipInputStream(is);
		try {
			ZipEntry ze;
			while (true) {
				ze = zis.getNextEntry();
				if (ze == null) {
					break;
				}
				if (ze.isDirectory()) {
					continue;
				}
				String name = ze.getName();

				if (name.equals(filename)) {
					if (logMINOR) {
						Logger.minor(NodeUpdater.class, "Found manifest");
					}
					long size = ze.getSize();
					if (logMINOR) {
						Logger.minor(NodeUpdater.class, "Manifest size: " + size);
					}
					if (size > MAX_MANIFEST_SIZE) {
						Logger.error(NodeUpdater.class,
								"Manifest is too big: " + size + " bytes, limit is " + MAX_MANIFEST_SIZE);
						break;
					}
					byte[] buf = new byte[(int) size];
					DataInputStream dis = new DataInputStream(zis);
					dis.readFully(buf);
					ByteArrayInputStream bais = new ByteArrayInputStream(buf);
					props.load(bais);
				}
				else {
					// Read the file. Throw if there is a CRC error.
					// Note that java.util.zip.ZipInputStream only checks the CRC for
					// compressed
					// files, so this is not entirely foolproof.
					long size = ze.getSize();
					FileUtil.copy(zis, new NullOutputStream(), size);
					zis.closeEntry();
				}
			}
		}
		finally {
			Closer.close(zis);
		}
		return props;
	}

	protected void parseDependencies(FetchResult result, int build) {
		InputStream is = null;
		try {
			is = result.asBucket().getInputStream();
			this.parseDependencies(parseProperties(is, DEPENDENCIES_FILE), build);
		}
		catch (IOException ignored) {
			Logger.error(this, "IOException trying to read manifest on update");
		}
		catch (Throwable ex) {
			Logger.error(this, "Failed to parse update manifest: " + ex, ex);
		}
		finally {
			Closer.close(is);
		}
	}

	/** Override if you want to deal with the file dependencies.properties */
	protected void parseDependencies(Properties props, int build) {
		// Do nothing
	}

	protected void parseManifestLine(String line) {
		// Do nothing by default, only some NodeUpdater's will use this, those that don't
		// won't call parseManifest().
	}

	private static final int MAX_MANIFEST_SIZE = 1024 * 1024;

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
			this.ticker.queueTimedJob(NodeUpdater.this::maybeUpdate, 0);
		}
		else {
			Logger.error(this, "Canceling fetch : " + e.getMessage());
			System.err.println("Unexpected error fetching update: " + e.getMessage());
			if (e.isFatal()) {
				// Wait for the next version
			}
			else {
				this.ticker.queueTimedJob(NodeUpdater.this::maybeUpdate, TimeUnit.HOURS.toMillis(1));
			}
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

	/**
	 ** Called by NodeUpdateManager to re-set the min/max versions for ext when a new
	 * freenet.jar has been downloaded. This is to try to avoid the node installing
	 * incompatible versions of main and ext.
	 */
	public void setMinMax(int requiredExt, int recommendedExt) {
		int callFinishedFound = -1;
		synchronized (this) {
			if (recommendedExt > -1) {
				this.maxDeployVersion = recommendedExt;
			}
			if (requiredExt > -1) {
				this.minDeployVersion = requiredExt;
				if (this.realAvailableVersion != this.availableVersion && this.availableVersion < requiredExt
						&& this.realAvailableVersion >= requiredExt) {
					// We found a revision but didn't fetch it because it wasn't within
					// the range for the old jar.
					// The new one requires it, however.
					System.err.println("Previously out-of-range edition " + this.realAvailableVersion
							+ " is now needed by the new jar; scheduling fetch.");
					callFinishedFound = this.realAvailableVersion;
					this.availableVersion = this.realAvailableVersion;
				}
				else if (this.availableVersion < requiredExt) {
					// Including if it hasn't been found at all
					// Just try it ...
					callFinishedFound = requiredExt;
					this.availableVersion = requiredExt;
					System.err.println("Need minimum edition " + requiredExt + " for new jar, found "
							+ this.availableVersion + "; scheduling fetch.");
				}
			}
		}
		if (callFinishedFound > -1) {
			this.finishOnFoundEdition(callFinishedFound);
		}
	}

	@Override
	public boolean realTimeFlag() {
		return false;
	}

	@Override
	public void onResume(ClientContext context) {
		// Do nothing. Not persistent.
	}

}
