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

package freenet.client.async;

import java.io.Serial;
import java.io.Serializable;

import freenet.client.FetchContext;
import freenet.clientlogger.Logger;
import freenet.keys.USK;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger.LogLevel;
import freenet.support.io.NativeThread;

/**
 * Not the actual fetcher. Just a tag associating a USK with the client that should be
 * called when the fetch has been done. Can be included in persistent requests. On
 * startup, all USK fetches are restarted, but this remains the same: the actual
 * USKFetcher's are always transient.
 *
 * WARNING: Changing non-transient members on classes that are Serializable can result in
 * restarting downloads or losing uploads.
 *
 * @author toad
 */
public final class USKFetcherTag implements ClientGetState, USKFetcherCallback, Serializable {

	@Serial
	private static final long serialVersionUID = 1L;

	/** The callback */
	public final USKFetcherCallback callback;

	/** The original USK */
	public final USK origUSK;

	/** The edition number found so far */
	private long edition;

	/** Persistent?? */
	public final boolean persistent;

	/** Context */
	public final FetchContext ctx;

	public final boolean keepLastData;

	/** Priority */
	private final short priority;

	private final long token;

	private transient USKFetcher fetcher;

	private final short pollingPriorityNormal;

	private final short pollingPriorityProgress;

	private boolean finished;

	private final boolean ownFetchContext;

	private final boolean checkStoreOnly;

	private final int hashCode;

	private final boolean realTimeFlag;

	private USKFetcherTag(USK origUSK, USKFetcherCallback callback, boolean persistent, boolean realTime,
			FetchContext ctx, boolean keepLastData, long token, boolean hasOwnFetchContext, boolean checkStoreOnly) {
		this.callback = callback;
		this.origUSK = origUSK;
		this.edition = origUSK.suggestedEdition;
		this.persistent = persistent;
		this.ctx = ctx;
		this.keepLastData = keepLastData;
		this.token = token;
		this.ownFetchContext = hasOwnFetchContext;
		this.realTimeFlag = realTime;
		this.pollingPriorityNormal = callback.getPollingPriorityNormal();
		this.pollingPriorityProgress = callback.getPollingPriorityProgress();
		this.priority = this.pollingPriorityNormal;
		this.checkStoreOnly = checkStoreOnly;
		this.hashCode = super.hashCode();
		if (logMINOR) {
			Logger.minor(this, "Created tag for " + origUSK + " and " + callback + " : " + this);
		}
	}

	@Override
	public int hashCode() {
		return this.hashCode;
	}

	/**
	 * For a persistent request, the caller must call removeFromDatabase() when finished.
	 * Note that the caller is responsible for deleting the USKFetcherCallback and the
	 * FetchContext.
	 */
	public static USKFetcherTag create(USK usk, USKFetcherCallback callback, boolean persistent, boolean realTime,
			FetchContext ctx, boolean keepLast, int token, boolean hasOwnFetchContext, boolean checkStoreOnly) {
		return new USKFetcherTag(usk, callback, persistent, realTime, ctx, keepLast, token, hasOwnFetchContext,
				checkStoreOnly);
	}

	synchronized void updatedEdition(long ed) {
		if (this.edition < ed) {
			this.edition = ed;
		}
	}

	public void start(USKManager manager, ClientContext context) {
		USK usk = this.origUSK;
		if (usk.suggestedEdition < this.edition) {
			usk = usk.copy(this.edition);
		}
		else if (this.persistent) {
			// Copy it to avoid deactivation issues
			usk = usk.copy();
		}
		this.fetcher = manager.getFetcher(usk, this.ctx,
				new USKFetcherWrapper(usk, this.priority, this.realTimeFlag ? USKManager.rcRT : USKManager.rcBulk),
				this.keepLastData, this.checkStoreOnly);
		this.fetcher.addCallback(this);
		this.fetcher.schedule(context); // non-persistent
		if (logMINOR) {
			Logger.minor(this, "Starting " + this.fetcher + " for " + this);
		}
	}

	@Override
	public void cancel(ClientContext context) {
		USKFetcher f = this.fetcher;
		if (f != null) {
			this.fetcher.cancel(context);
		}
		synchronized (this) {
			if (this.finished) {
				if (logMINOR) {
					Logger.minor(this, "Already cancelled " + this);
				}
				return;
			}
			this.finished = true;
		}
		if (f != null) {
			Logger.error(this, "cancel() for " + this.fetcher + " did not set finished on " + this + " ???");
		}
	}

	@Override
	public long getToken() {
		return this.token;
	}

	@Override
	public void schedule(ClientContext context) {
		this.start(context.uskManager, context);
	}

	@Override
	public void onCancelled(ClientContext context) {
		if (logMINOR) {
			Logger.minor(this, "Cancelled on " + this);
		}
		synchronized (this) {
			this.finished = true;
		}
		if (this.persistent) {
			// This can be called from USKFetcher, in which case we want to run on the
			// PersistentJobRunner.
			try {
				context.jobRunner.queue((context1) -> {
					if (USKFetcherTag.this.callback instanceof USKFetcherTagCallback) {
						((USKFetcherTagCallback) USKFetcherTag.this.callback).setTag(USKFetcherTag.this, context1);
					}
					USKFetcherTag.this.callback.onCancelled(context1);
					return false;
				}, NativeThread.HIGH_PRIORITY);
			}
			catch (PersistenceDisabledException ignored) {
				// Impossible.
			}
		}
		else {
			if (this.callback instanceof USKFetcherTagCallback) {
				((USKFetcherTagCallback) this.callback).setTag(USKFetcherTag.this, context);
			}
			this.callback.onCancelled(context);
		}
	}

	@Override
	public void onFailure(ClientContext context) {
		if (logMINOR) {
			Logger.minor(this, "Failed on " + this);
		}
		synchronized (this) {
			if (this.finished) {
				Logger.error(this, "onFailure called after finish on " + this, new Exception("error"));
				return;
			}
			this.finished = true;
		}
		if (this.persistent) {
			try {
				context.jobRunner.queue((context1) -> {
					if (USKFetcherTag.this.callback instanceof USKFetcherTagCallback) {
						((USKFetcherTagCallback) USKFetcherTag.this.callback).setTag(USKFetcherTag.this, context1);
					}
					USKFetcherTag.this.callback.onFailure(context1);
					return true;
				}, NativeThread.HIGH_PRIORITY);
			}
			catch (PersistenceDisabledException ignored) {
				// Impossible.
			}
		}
		else {
			if (this.callback instanceof USKFetcherTagCallback) {
				((USKFetcherTagCallback) this.callback).setTag(USKFetcherTag.this, context);
			}
			this.callback.onFailure(context);
		}
	}

	@Override
	public short getPollingPriorityNormal() {
		return this.pollingPriorityNormal;
	}

	@Override
	public short getPollingPriorityProgress() {
		return this.pollingPriorityProgress;
	}

	@Override
	public void onFoundEdition(final long l, final USK key, ClientContext context, final boolean metadata,
			final short codec, final byte[] data, final boolean newKnownGood, final boolean newSlotToo) {
		if (logMINOR) {
			Logger.minor(this, "Found edition " + l + " on " + this);
		}
		synchronized (this) {
			if (this.fetcher == null) {
				Logger.error(this,
						"onFoundEdition but fetcher is null - isn't onFoundEdition() terminal for USKFetcherCallback's??",
						new Exception("debug"));
			}
			if (this.finished) {
				Logger.error(this, "onFoundEdition called after finish on " + this, new Exception("error"));
				return;
			}
			this.finished = true;
			this.fetcher = null;
		}
		if (this.persistent) {
			try {
				context.jobRunner.queue((context1) -> {
					if (USKFetcherTag.this.callback instanceof USKFetcherTagCallback) {
						((USKFetcherTagCallback) USKFetcherTag.this.callback).setTag(USKFetcherTag.this, context1);
					}
					USKFetcherTag.this.callback.onFoundEdition(l, key, context1, metadata, codec, data, newKnownGood,
							newSlotToo);
					return false;
				}, NativeThread.HIGH_PRIORITY);
			}
			catch (PersistenceDisabledException ignored) {
				// Impossible.
			}
		}
		else {
			if (this.callback instanceof USKFetcherTagCallback) {
				((USKFetcherTagCallback) this.callback).setTag(USKFetcherTag.this, context);
			}
			this.callback.onFoundEdition(l, key, context, metadata, codec, data, newKnownGood, newSlotToo);
		}
	}

	public boolean isFinished() {
		return this.finished;
	}

	private static volatile boolean logMINOR;

	// private static volatile boolean logDEBUG;

	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback() {

			@Override
			public void shouldUpdate() {
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
				// logDEBUG = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}

	@Override
	public void onResume(ClientContext context) {
		if (this.finished) {
			return;
		}
		this.start(context.uskManager, context);
	}

	@Override
	public void onShutdown(ClientContext context) {
		// Ignore.
	}

}
