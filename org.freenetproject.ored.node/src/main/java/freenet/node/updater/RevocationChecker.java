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
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

import freenet.bucket.ArrayBucket;
import freenet.bucket.Bucket;
import freenet.bucket.BucketTools;
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
import freenet.client.request.PriorityClasses;
import freenet.client.request.RequestClient;
import freenet.l10n.NodeL10n;
import freenet.lockablebuffer.ByteArrayRandomAccessBuffer;
import freenet.lockablebuffer.FileRandomAccessBuffer;
import freenet.node.NodeClientCore;
import freenet.nodelogger.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.MediaType;
import freenet.support.api.RandomAccessBuffer;
import freenet.support.io.FileUtil;

/**
 * Fetches the revocation key. Each time it starts, it will try to fetch it until it has 3
 * DNFs. If it ever finds it, it will be immediately fed to the NodeUpdateManager.
 */
public class RevocationChecker implements ClientGetCallback, RequestClient {

	public static final int REVOCATION_DNF_MIN = 3;

	private boolean logMINOR;

	private final NodeUpdateManager manager;

	private final NodeClientCore core;

	private int revocationDNFCounter;

	private final FetchContext ctxRevocation;

	private ClientGetter revocationGetter;

	private boolean wasAggressive;

	/** Last time at which we got 3 DNFs on the revocation key */
	private long lastSucceeded;

	// Kept separately from NodeUpdateManager.hasBeenBlown because there are local
	// problems that can blow the key.
	private volatile boolean blown;

	private final File blobFile;

	/** The original binary blob bucket. */
	private ArrayBucket blobBucket;

	public RevocationChecker(NodeUpdateManager manager, File blobFile) {
		this.manager = manager;
		this.core = manager.node.clientCore;
		this.revocationDNFCounter = 0;
		this.blobFile = blobFile;
		this.logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
		this.ctxRevocation = this.core.makeClient((short) 0, true, false).getFetchContext();
		// Do not allow redirects etc.
		// If we allow redirects then it will take too long to download the revocation.
		// Anyone inserting it should be aware of this fact!
		// You must insert with no content type, and be less than the size limit, and less
		// than the block size after compression!
		// If it doesn't fit, we'll still tell the user, but the message may not be easily
		// readable.
		this.ctxRevocation.allowSplitfiles = false;
		this.ctxRevocation.maxArchiveLevels = 0;
		this.ctxRevocation.followRedirects = false;
		// big enough ?
		this.ctxRevocation.maxOutputLength = NodeUpdateManager.MAX_REVOCATION_KEY_LENGTH;
		this.ctxRevocation.maxTempLength = NodeUpdateManager.MAX_REVOCATION_KEY_TEMP_LENGTH;
		this.ctxRevocation.maxSplitfileBlockRetries = -1; // if we find content, try
															// forever to
															// get it; not used because of
															// the
															// above size limits.
		this.ctxRevocation.maxNonSplitfileRetries = 0; // but return quickly normally
	}

	public int getRevocationDNFCounter() {
		return this.revocationDNFCounter;
	}

	public void start(boolean aggressive) {
		this.start(aggressive, true);
		if (this.blobFile.exists()) {
			ArrayBucket bucket = new ArrayBucket();
			try {
				BucketTools.copy(new FileBucket(this.blobFile, true, false, false, true), bucket);
				// Allow to free if bogus.
				this.manager.uom.processRevocationBlob(bucket, "disk", true);
			}
			catch (IOException ex) {
				Logger.error(this, "Failed to read old revocation blob: " + ex, ex);
				System.err.println(
						"We may have downloaded an old revocation blob before restarting but it cannot be read: " + ex);
				ex.printStackTrace();
			}
		}
	}

	/**
	 * Start a fetch.
	 * @param aggressive If set to true, then we have just fetched an update, and
	 * therefore can increase the priority of the fetch to maximum.
	 * @return True if the checker was already running and the counter was not reset.
	 */
	public boolean start(boolean aggressive, boolean reset) {

		if (this.manager.isBlown()) {
			Logger.error(this, "Not starting revocation checker: key already blown!");
			return false;
		}
		boolean wasRunning = false;
		this.logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
		ClientGetter cg = null;
		try {
			ClientGetter toCancel = null;
			synchronized (this) {
				if (aggressive && !this.wasAggressive) {
					// Ignore old one.
					toCancel = this.revocationGetter;
					if (this.logMINOR) {
						Logger.minor(this, "Ignoring old request, because was low priority");
					}
					this.revocationGetter = null;
					if (toCancel != null) {
						wasRunning = true;
					}
				}
				this.wasAggressive = aggressive;
				if (this.revocationGetter != null
						&& !(this.revocationGetter.isCancelled() || this.revocationGetter.isFinished())) {
					if (this.logMINOR) {
						Logger.minor(this, "Not queueing another revocation fetcher yet, old one still running");
					}
				}
				else {
					if (reset) {
						if (this.logMINOR) {
							Logger.minor(this, "Resetting DNF count from " + this.revocationDNFCounter,
									new Exception("debug"));
						}
						this.revocationDNFCounter = 0;
					}
					else {
						if (this.logMINOR) {
							Logger.minor(this, "Revocation count " + this.revocationDNFCounter);
						}
					}
					if (this.logMINOR) {
						Logger.minor(this, "fetcher=" + this.revocationGetter);
					}
					if (this.revocationGetter != null && this.logMINOR) {
						Logger.minor(this, "revocation fetcher: cancelled=" + this.revocationGetter.isCancelled()
								+ ", finished=" + this.revocationGetter.isFinished());
					}
					// Client startup may not have completed yet.
					if (!this.manager.node.clientCore.getPersistentTempDir().mkdirs()) {
						Logger.error(this, "Unable to make persistent temp directory");
					}
					cg = new ClientGetter(this, this.manager.getRevocationURI(), this.ctxRevocation,
							aggressive ? PriorityClasses.MAXIMUM_PRIORITY_CLASS
									: PriorityClasses.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
							null, new BinaryBlobWriter(new ArrayBucket()), null);
					this.revocationGetter = cg;
					if (this.logMINOR) {
						Logger.minor(this,
								"Queued another revocation fetcher (count=" + this.revocationDNFCounter + ")");
					}
				}
			}
			if (toCancel != null) {
				toCancel.cancel(this.core.clientContext);
			}
			if (cg != null) {
				this.core.clientContext.start(cg);
				if (this.logMINOR) {
					Logger.minor(this, "Started revocation fetcher");
				}
			}
			return wasRunning;
		}
		catch (FetchException ex) {
			if (ex.mode == FetchExceptionMode.RECENTLY_FAILED) {
				Logger.error(this, "Cannot start revocation fetcher because recently failed");
			}
			else {
				Logger.error(this, "Cannot start fetch for the auto-update revocation key: " + ex, ex);
				this.manager.blow("Cannot start fetch for the auto-update revocation key: " + ex, true);
			}
			synchronized (this) {
				if (this.revocationGetter == cg) {
					this.revocationGetter = null;
				}
			}
			return false;
		}
		catch (PersistenceDisabledException ex) {
			// Impossible
			return false;
		}
	}

	long lastSucceeded() {
		return this.lastSucceeded;
	}

	long lastSucceededDelta() {
		if (this.lastSucceeded <= 0) {
			return -1;
		}
		return System.currentTimeMillis() - this.lastSucceeded;
	}

	/** Called when the revocation URI changes. */
	public void onChangeRevocationURI() {
		this.kill();
		this.start(this.wasAggressive);
	}

	@Override
	public void onSuccess(FetchResult result, ClientGetter state) {
		this.onSuccess(result, state, state.getBlobBucket());
	}

	void onSuccess(FetchResult result, ClientGetter state, Bucket blob) {
		// The key has been blown !
		// FIXME: maybe we need a bigger warning message.
		this.blown = true;
		this.moveBlob(blob);
		String msg;
		try {
			byte[] buf = result.asByteArray();
			msg = new String(buf, MediaType.getCharsetRobustOrUTF(result.getMimeType()));
		}
		catch (Throwable ex) {
			try {
				msg = "Failed to extract result when key blown: " + ex;
				Logger.error(this, msg, ex);
				System.err.println(msg);
				ex.printStackTrace();
			}
			catch (Throwable t1) {
				msg = "Internal error after retreiving revocation key";
			}
		}
		this.manager.blow(msg, false); // Real one, even if we can't extract the message.
	}

	public boolean hasBlown() {
		return this.blown;
	}

	private void moveBlob(Bucket tmpBlob) {
		if (tmpBlob == null) {
			Logger.error(this,
					"No temporary binary blob file moving it: may not be able to propagate revocation, bug???");
			return;
		}
		if (tmpBlob instanceof ArrayBucket) {
			synchronized (this) {
				if (tmpBlob == this.blobBucket) {
					return;
				}
				this.blobBucket = (ArrayBucket) tmpBlob;
			}
		}
		else {
			try {
				ArrayBucket buf = new ArrayBucket(BucketTools.toByteArray(tmpBlob));
				synchronized (this) {
					this.blobBucket = buf;
				}
			}
			catch (IOException ex) {
				System.err.println("Unable to copy data from revocation bucket!");
				System.err.println(
						"This should not happen and indicates there may be a problem with the auto-update checker.");
				// Don't blow(), as that's already happened.
				return;
			}
			if (tmpBlob instanceof FileBucket) {
				File f = ((FileBucket) tmpBlob).getFile();
				synchronized (this) {
					if (f == this.blobFile) {
						return;
					}
					if (f.equals(this.blobFile)) {
						return;
					}
					if (FileUtil.getCanonicalFile(f).equals(FileUtil.getCanonicalFile(this.blobFile))) {
						return;
					}
				}
			}
			System.out.println("Unexpected blob file in revocation checker: " + tmpBlob);
		}
		FileBucket fb = new FileBucket(this.blobFile, false, false, false, false);
		try {
			BucketTools.copy(tmpBlob, fb);
		}
		catch (IOException ex) {
			System.err.println("Got revocation but cannot write it to disk: " + ex);
			System.err.println("This means the auto-update system is blown but we can't tell other nodes about it!");
			ex.printStackTrace();
		}
	}

	@Override
	public void onFailure(FetchException e, ClientGetter state) {
		this.onFailure(e, state, state.getBlobBucket());
	}

	void onFailure(FetchException e, ClientGetter state, Bucket blob) {
		this.logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
		if (this.logMINOR) {
			Logger.minor(this, "Revocation fetch failed: " + e);
		}
		FetchExceptionMode errorCode = e.getMode();
		boolean completed = false;
		long now = System.currentTimeMillis();
		if (errorCode == FetchExceptionMode.CANCELLED) {
			return; // cancelled by us above, or killed; either way irrelevant and doesn't
					// need to be restarted
		}
		if (e.isFatal()) {
			if (!e.isDefinitelyFatal()) {
				// INTERNAL_ERROR could be related to the key but isn't necessarily.
				// FIXME somebody should look at these two strings and de-uglify them!
				// They should never be seen but they should be idiot-proof if they ever
				// are.
				// FIXME split into two parts? Fetch manually should be a second part?
				String message = this.l10n("revocationFetchFailedMaybeInternalError", new String[] { "detail", "key" },
						new String[] { e.toUserFriendlyString(), this.manager.getRevocationURI().toASCIIString() });
				System.err.println(message);
				e.printStackTrace();
				this.manager.blow(message, true);
				return;
			}
			// Really fatal, i.e. something was inserted but can't be decoded.
			// FIXME somebody should look at these two strings and de-uglify them!
			// They should never be seen but they should be idiot-proof if they ever are.
			String message = this.l10n("revocationFetchFailedFatally", new String[] { "detail", "key" },
					new String[] { e.toUserFriendlyString(), this.manager.getRevocationURI().toASCIIString() });
			this.manager.blow(message, false);
			this.moveBlob(blob);
			return;
		}
		if (e.newURI != null) {
			this.manager.blow("Revocation URI redirecting to " + e.newURI
					+ " - maybe you set the revocation URI to the update URI?", false);
		}
		synchronized (this) {
			if (errorCode == FetchExceptionMode.DATA_NOT_FOUND) {
				this.revocationDNFCounter++;
				if (this.logMINOR) {
					Logger.minor(this, "Incremented DNF counter to " + this.revocationDNFCounter);
				}
			}
			if (this.revocationDNFCounter >= 3) {
				this.lastSucceeded = now;
				completed = true;
				this.revocationDNFCounter = 0;
			}
			this.revocationGetter = null;
		}
		if (completed) {
			this.manager.noRevocationFound();
		}
		else {
			if (errorCode == FetchExceptionMode.RECENTLY_FAILED) {
				// Try again in 1 second.
				// This ensures we don't constantly start them, fail them, and start them
				// again.
				this.manager.node.ticker.queueTimedJob(
						() -> RevocationChecker.this.start(RevocationChecker.this.wasAggressive, false),
						TimeUnit.SECONDS.toMillis(1));
			}
			else {
				this.start(this.wasAggressive, false);
			}
		}
	}

	private String l10n(String key, String[] pattern, String[] value) {
		return NodeL10n.getBase().getString("RevocationChecker." + key, pattern, value);
	}

	public void kill() {
		if (this.revocationGetter != null) {
			this.revocationGetter.cancel(this.core.clientContext);
		}
	}

	public long getBlobSize() {
		return this.blobFile.length();
	}

	public RandomAccessBucket getBlobBucket() {
		if (!this.manager.isBlown()) {
			return null;
		}
		synchronized (this) {
			if (this.blobBucket != null) {
				return this.blobBucket;
			}
		}
		File f = this.getBlobFile();
		if (f == null) {
			return null;
		}
		return new FileBucket(f, true, false, false, false);
	}

	public RandomAccessBuffer getBlobBuffer() {
		if (!this.manager.isBlown()) {
			return null;
		}
		synchronized (this) {
			if (this.blobBucket != null) {
				try {
					ByteArrayRandomAccessBuffer t = new ByteArrayRandomAccessBuffer(this.blobBucket.toByteArray());
					t.setReadOnly();
					return t;
				}
				catch (IOException ex) {
					Logger.error(this, "Impossible: " + ex, ex);
					return null;
				}
			}
		}
		File f = this.getBlobFile();
		if (f == null) {
			return null;
		}
		try {
			return new FileRandomAccessBuffer(f, true);
		}
		catch (FileNotFoundException ex) {
			Logger.error(this,
					"We do not have the blob file for the revocation even though we have successfully downloaded it!",
					ex);
			return null;
		}
		catch (IOException ex) {
			Logger.error(this, "Error reading downloaded revocation blob file: " + ex, ex);
			return null;
		}
	}

	/** Get the binary blob, if we have fetched it. */
	private File getBlobFile() {
		if (this.blobFile.exists()) {
			return this.blobFile;
		}
		return null;
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

	@Override
	public RequestClient getRequestClient() {
		return this;
	}

}
