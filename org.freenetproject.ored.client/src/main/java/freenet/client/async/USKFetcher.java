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

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.lang.ref.WeakReference;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;

import freenet.bucket.Bucket;
import freenet.bucket.BucketCloser;
import freenet.bucket.BucketTools;
import freenet.client.ClientMetadata;
import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.FetchException.FetchExceptionMode;
import freenet.client.InsertContext.CompatibilityMode;
import freenet.client.request.KeysFetchingLocally;
import freenet.client.request.LowLevelException;
import freenet.client.request.PriorityClasses;
import freenet.client.request.RequestClient;
import freenet.client.request.SendableGet;
import freenet.client.request.SendableRequestItem;
import freenet.clientlogger.Logger;
import freenet.compress.Compressor;
import freenet.compress.DecompressorThreadManager;
import freenet.crypt.HashResult;
import freenet.keys.ClientKey;
import freenet.keys.ClientSSK;
import freenet.keys.ClientSSKBlock;
import freenet.keys.FreenetURI;
import freenet.keys.Key;
import freenet.keys.KeyBlock;
import freenet.keys.KeyDecodeException;
import freenet.keys.NodeSSK;
import freenet.keys.SSKBlock;
import freenet.keys.SSKVerifyException;
import freenet.keys.USK;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger.LogLevel;
import freenet.support.RemoveRangeArrayList;

/**
 *
 * On 0.7, this shouldn't however take more than 10 seconds or so; these are SSKs we are
 * talking about. If this is fast enough then people will use the "-" form.
 *
 * FProxy should cause USKs with negative edition numbers to be redirected to USKs with
 * positive edition numbers.
 *
 * If the number specified is up to date, we just do the fetch. If a more recent USK can
 * be found, then we fail with an exception with the new version. The client is expected
 * to redirect to this. The point here is that FProxy will then have the correct number in
 * the location bar, so that if the user copies the URL, it will keep the edition number
 * hint.
 *
 * A positive number fetch triggers a background fetch.
 *
 * This class does both background fetches and negative number fetches.
 *
 * It does them in the same way.
 *
 * There is one USKFetcher for a given USK, at most. They are registered on the
 * USKManager. They have a list of ClientGetState-implementing callbacks; these are all
 * triggered on completion.
 *
 * When a new suggestedEdition is added, if that is later than the currently searched-for
 * version, the USKFetcher will try to fetch that as well as its current pointer.
 *
 * Current algorithm: - Fetch the next 5 editions all at once. - If we have four
 * consecutive editions with DNF, and no later pending fetches, then we finish with the
 * last known good version. (There are details relating to other error codes handled below
 * in the relevant method). - We immediately update the USKManager if we successfully
 * fetch an edition. - If a new, higher suggestion comes in, that is also fetched.
 *
 * Future extensions: - Binary search. - Hierarchical DBRs. - TUKs (when we have TUKs). -
 * Passive requests (when we have passive requests).
 *
 * PERSISTENCE: This class is not persistent. USKFetcherTag is used to mark persistent USK
 * fetches, which will be restarted on startup.
 */
public class USKFetcher implements ClientGetState, USKCallback, HasKeyListener, KeyListener {

	private static volatile boolean logMINOR;

	private static volatile boolean logDEBUG;

	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback() {

			@Override
			public void shouldUpdate() {
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
				logDEBUG = Logger.shouldLog(LogLevel.DEBUG, this);
			}
		});
	}

	/** USK manager */
	private final USKManager uskManager;

	/** The USK to fetch */
	private final USK origUSK;

	/** Callbacks */
	private final List<USKFetcherCallback> callbacks;

	/** Fetcher context */
	final FetchContext ctx;

	/** Fetcher context ignoring store */
	final FetchContext ctxNoStore;

	/** Fetcher context for DBR hint fetches */
	final FetchContext ctxDBR;

	/** Finished? */
	private boolean completed;

	/** Cancelled? */
	private boolean cancelled;

	private final boolean checkStoreOnly;

	final ClientRequester parent;

	// We keep the data from the last (highest number) request.
	private Bucket lastRequestData;

	private short lastCompressionCodec;

	private boolean lastWasMetadata;

	/** Structure tracking which keys we want. */
	private final USKWatchingKeys watchingKeys;

	private final ArrayList<USKAttempt> attemptsToStart;

	private static final int WATCH_KEYS = 50;

	/**
	 * Callbacks are told when the USKFetcher finishes, and unless background poll is
	 * enabled, they are only sent onFoundEdition *once*, on completion.
	 *
	 * However they do help to determine the fetcher's priority.
	 *
	 * FIXME: Don't allow callbacks if backgroundPoll is enabled??
	 */
	public boolean addCallback(USKFetcherCallback cb) {
		synchronized (this) {
			if (this.completed) {
				return false;
			}
			this.callbacks.add(cb);
		}
		this.updatePriorities();
		return true;
	}

	private final HashSet<DBRAttempt> dbrAttempts = new HashSet<>();

	private final TreeMap<Long, USKAttempt> runningAttempts = new TreeMap<>();

	private final TreeMap<Long, USKAttempt> pollingAttempts = new TreeMap<>();

	private long lastFetchedEdition;

	final long origMinFailures;

	boolean firstLoop;

	static final long origSleepTime = TimeUnit.MINUTES.toMillis(30);
	static final long maxSleepTime = TimeUnit.HOURS.toMillis(24);

	long sleepTime = origSleepTime;

	private long valueAtSchedule;

	/** Keep going forever? */
	private final boolean backgroundPoll;

	/** Keep the last fetched data? */
	final boolean keepLastData;

	private boolean started;

	private final boolean realTimeFlag;

	private static final short DEFAULT_NORMAL_POLL_PRIORITY = PriorityClasses.PREFETCH_PRIORITY_CLASS;

	private short normalPollPriority = DEFAULT_NORMAL_POLL_PRIORITY;

	private static final short DEFAULT_PROGRESS_POLL_PRIORITY = PriorityClasses.UPDATE_PRIORITY_CLASS;

	private short progressPollPriority = DEFAULT_PROGRESS_POLL_PRIORITY;

	private boolean scheduledDBRs;

	private boolean scheduleAfterDBRsDone;

	// FIXME use this!
	USKFetcher(USK origUSK, USKManager manager, FetchContext ctx, ClientRequester requester, int minFailures,
			boolean pollForever, boolean keepLastData, boolean checkStoreOnly) {
		this.parent = requester;
		this.origUSK = origUSK;
		this.uskManager = manager;
		this.origMinFailures = minFailures;
		if (this.origMinFailures > WATCH_KEYS) {
			throw new IllegalArgumentException();
		}
		this.firstLoop = true;
		this.callbacks = new ArrayList<>();
		this.subscribers = new HashSet<>();
		this.lastFetchedEdition = -1;
		this.realTimeFlag = this.parent.realTimeFlag();
		this.ctxDBR = ctx.clone();
		if (ctx.followRedirects) {
			this.ctx = ctx.clone();
			this.ctx.followRedirects = false;
		}
		else {
			this.ctx = ctx;
		}
		this.ctxDBR.maxOutputLength = 1024;
		this.ctxDBR.maxTempLength = 32768;
		this.ctxDBR.filterData = false;
		this.ctxDBR.maxArchiveLevels = 0;
		this.ctxDBR.maxArchiveRestarts = 0;
		if (checkStoreOnly) {
			this.ctxDBR.localRequestOnly = true;
		}
		if (ctx.ignoreStore) {
			this.ctxNoStore = this.ctx;
		}
		else {
			this.ctxNoStore = this.ctx.clone();
			this.ctxNoStore.ignoreStore = true;
		}
		this.backgroundPoll = pollForever;
		this.keepLastData = keepLastData;
		this.checkStoreOnly = checkStoreOnly;
		if (checkStoreOnly && logMINOR) {
			Logger.minor(this, "Just checking store on " + this);
		}
		// origUSK is a hint. We *do* want to check the edition given.
		// Whereas latestSlot we've definitely fetched, we don't want to re-check.
		this.watchingKeys = new USKWatchingKeys(origUSK, Math.max(0, this.uskManager.lookupLatestSlot(origUSK) + 1));
		this.attemptsToStart = new ArrayList<>();
	}

	public void onDBRsFinished(ClientContext context) {
		boolean needSchedule = false;
		synchronized (this) {
			if (this.scheduleAfterDBRsDone) {
				needSchedule = true; // FIXME other conditions???
			}
		}
		if (needSchedule) {
			this.schedule(context);
		}
		this.checkFinishedForNow(context);
	}

	private int dbrHintsFound = 0;

	private int dbrHintsStarted = 0;

	public void processDBRHint(long hint, ClientContext context, DBRAttempt dbrAttempt) {
		// FIXME this is an inefficient first attempt!
		// We should have a separate registry of latest DBR hint versions,
		// like those for latest known good and latest slot.
		// We should dump anything before it within USKFetcher, and fetch from
		// the given slot onwards, inclusive (unlike elsewhere where we fetch
		// from the last known exclusive).
		try {
			this.updatePriorities();
			short prio;
			List<DBRAttempt> toCancel = null;
			synchronized (this) {
				if (this.cancelled || this.completed) {
					return;
				}
				this.dbrHintsFound++;
				prio = this.progressPollPriority;
				for (Iterator<DBRAttempt> i = this.dbrAttempts.iterator(); i.hasNext();) {
					DBRAttempt a = i.next();
					if (dbrAttempt.type.alwaysMorePreciseThan(a.type)) {
						if (toCancel == null) {
							toCancel = new ArrayList<>();
						}
						toCancel.add(a);
						i.remove();
					}
				}
			}
			this.uskManager.hintUpdate(this.origUSK.copy(hint).getURI(), context, prio);
			if (toCancel != null) {
				for (DBRAttempt a : toCancel) {
					a.cancel(context);
				}
			}
		}
		catch (MalformedURLException ex) {
			// Impossible
		}
	}

	public void onCheckEnteredFiniteCooldown(ClientContext context) {
		this.checkFinishedForNow(context);
	}

	private void checkFinishedForNow(ClientContext context) {
		USKAttempt[] attempts;
		synchronized (this) {
			if (this.cancelled || this.completed) {
				return;
			}
			if (this.runningStoreChecker != null) {
				if (logMINOR) {
					Logger.minor(this, "Not finished because still running store checker on " + this);
				}
				return; // Still checking the store
			}
			if (!this.runningAttempts.isEmpty()) {
				if (logMINOR) {
					Logger.minor(this, "Not finished because running attempts (random probes) on " + this);
				}
				return; // Still running
			}
			if (this.pollingAttempts.isEmpty()) {
				if (logMINOR) {
					Logger.minor(this, "Not finished because no polling attempts (not started???) on " + this);
				}
				return; // Not started yet
			}
			if (!this.dbrAttempts.isEmpty()) {
				if (logMINOR) {
					Logger.minor(this, "Not finished because still waiting for DBR attempts on " + this + " : "
							+ this.dbrAttempts);
				}
				return; // DBRs
			}
			attempts = this.pollingAttempts.values().toArray(new USKAttempt[0]);
		}
		for (USKAttempt a : attempts) {
			// All the polling attempts currently running must have entered cooldown once.
			// I.e. they must have done all their fetches at least once.
			// If we check whether they are *currently* in cooldown, then under heavy USK
			// load (the common case!), we can see them overlapping and never notify
			// finished.
			if (!a.everInCooldown()) {
				if (logMINOR) {
					Logger.minor(this,
							"Not finished because polling attempt " + a + " never entered cooldown on " + this);
				}
				return;
			}
		}
		this.notifyFinishedForNow(context);
	}

	private void notifyFinishedForNow(ClientContext context) {
		if (logMINOR) {
			Logger.minor(this, "Notifying finished for now on " + this + " for " + this.origUSK
					+ (this.realTimeFlag ? " (realtime)" : " (bulk)"));
		}
		USKCallback[] toCheck;
		synchronized (this) {
			if (this.cancelled || this.completed) {
				return;
			}
			toCheck = this.subscribers.toArray(new USKCallback[0]);
		}
		for (USKCallback cb : toCheck) {
			if (cb instanceof USKProgressCallback) {
				((USKProgressCallback) cb).onRoundFinished(context);
			}
		}
	}

	private void notifySendingToNetwork(ClientContext context) {
		USKCallback[] toCheck;
		synchronized (this) {
			if (this.cancelled || this.completed) {
				return;
			}
			toCheck = this.subscribers.toArray(new USKCallback[0]);
		}
		for (USKCallback cb : toCheck) {
			if (cb instanceof USKProgressCallback) {
				((USKProgressCallback) cb).onSendingToNetwork(context);
			}
		}
	}

	void onDNF(USKAttempt att, ClientContext context) {
		if (logMINOR) {
			Logger.minor(this, "DNF: " + att);
		}
		boolean finished = false;
		long curLatest = this.uskManager.lookupLatestSlot(this.origUSK);
		synchronized (this) {
			if (this.completed || this.cancelled) {
				return;
			}
			this.lastFetchedEdition = Math.max(this.lastFetchedEdition, att.number);
			this.runningAttempts.remove(att.number);
			if (this.runningAttempts.isEmpty()) {
				if (logMINOR) {
					Logger.minor(this, "latest: " + curLatest + ", last fetched: " + this.lastFetchedEdition
							+ ", curLatest+MIN_FAILURES: " + (curLatest + this.origMinFailures));
				}
				if (this.started) {
					finished = true;
				}
			}
			else if (logMINOR) {
				Logger.minor(this, "Remaining: " + this.runningAttempts());
			}
		}
		if (finished) {
			this.finishSuccess(context);
		}
	}

	private synchronized String runningAttempts() {
		StringBuilder sb = new StringBuilder();
		boolean first = true;
		for (USKAttempt a : this.runningAttempts.values()) {
			if (!first) {
				sb.append(", ");
			}
			sb.append(a.number);
			if (a.cancelled) {
				sb.append("(cancelled)");
			}
			if (a.succeeded) {
				sb.append("(succeeded)");
			}
		}
		return sb.toString();
	}

	private void finishSuccess(ClientContext context) {
		if (logMINOR) {
			Logger.minor(this, "finishSuccess() on " + this);
		}
		if (this.backgroundPoll) {
			long valAtEnd = this.uskManager.lookupLatestSlot(this.origUSK);
			long end;
			long now = System.currentTimeMillis();
			synchronized (this) {
				this.started = false; // don't finish before have rescheduled

				// Find out when we should check next ('end'), in an increasing delay
				// (unless we make progress).
				long newSleepTime = this.sleepTime * 2;
				if (newSleepTime > maxSleepTime) {
					newSleepTime = maxSleepTime;
				}
				this.sleepTime = newSleepTime;
				end = now + context.random.nextInt((int) this.sleepTime);

				if (valAtEnd > this.valueAtSchedule && valAtEnd > this.origUSK.suggestedEdition) {
					// We have advanced; keep trying as if we just started.
					// Only if we actually DO advance, not if we just confirm our
					// suspicion (valueAtSchedule always starts at 0).
					this.sleepTime = origSleepTime;
					this.firstLoop = false;
					end = now;
					if (logMINOR) {
						Logger.minor(this,
								"We have advanced: at start, " + this.valueAtSchedule + " at end, " + valAtEnd);
					}
				}
				if (logMINOR) {
					Logger.minor(this,
							"Sleep time is " + this.sleepTime + " this sleep is " + (end - now) + " for " + this);
				}
			}
			this.schedule(end - now, context);
			this.checkFinishedForNow(context);
		}
		else {
			USKFetcherCallback[] cb;
			synchronized (this) {
				this.completed = true;
				cb = this.callbacks.toArray(new USKFetcherCallback[0]);
			}
			this.uskManager.unsubscribe(this.origUSK, this);
			this.uskManager.onFinished(this);
			context.getSskFetchScheduler(this.realTimeFlag).schedTransient.removePendingKeys((KeyListener) this);
			long ed = this.uskManager.lookupLatestSlot(this.origUSK);
			byte[] data;
			synchronized (this) {
				if (this.lastRequestData == null) {
					data = null;
				}
				else {
					try {
						data = BucketTools.toByteArray(this.lastRequestData);
					}
					catch (IOException ex) {
						Logger.error(this, "Unable to turn lastRequestData into byte[]: caught I/O exception: " + ex,
								ex);
						data = null;
					}
					this.lastRequestData.free();
				}
			}
			for (USKFetcherCallback c : cb) {
				try {
					if (ed == -1) {
						c.onFailure(context);
					}
					else {
						c.onFoundEdition(ed, this.origUSK.copy(ed), context, this.lastWasMetadata,
								this.lastCompressionCodec, data, false, false);
					}
				}
				catch (Exception ex) {
					Logger.error(this, "An exception occured while dealing with a callback:" + c.toString() + "\n"
							+ ex.getMessage(), ex);
				}
			}
		}
	}

	void onSuccess(USKAttempt att, boolean dontUpdate, ClientSSKBlock block, final ClientContext context) {
		this.onSuccess(att, att.number, dontUpdate, block, context);
	}

	void onSuccess(USKAttempt att, long curLatest, boolean dontUpdate, ClientSSKBlock block,
			final ClientContext context) {
		final long lastEd = this.uskManager.lookupLatestSlot(this.origUSK);
		if (logMINOR) {
			Logger.minor(this,
					"Found edition " + curLatest + " for " + this.origUSK + " official is " + lastEd + " on " + this);
		}
		boolean decode;
		List<USKAttempt> killAttempts = null;
		boolean registerNow;
		// FIXME call uskManager.updateSlot BEFORE getEditionsToFetch, avoids a possible
		// conflict, but creates another (with onFoundEdition) - we'd probably have to
		// handle this there???
		synchronized (this) {
			if (att != null) {
				this.runningAttempts.remove(att.number);
			}
			if (this.completed || this.cancelled) {
				if (logMINOR) {
					Logger.minor(this,
							"Finished already: completed=" + this.completed + " cancelled=" + this.cancelled);
				}
				return;
			}
			decode = curLatest >= lastEd && !(dontUpdate && block == null);
			curLatest = Math.max(lastEd, curLatest);
			if (logMINOR) {
				Logger.minor(this, "Latest: " + curLatest + " in onSuccess");
			}
			if (!this.checkStoreOnly) {
				killAttempts = this.cancelBefore(curLatest, context);
				USKWatchingKeys.ToFetch list = this.watchingKeys.getEditionsToFetch(curLatest, context.random,
						this.getRunningFetchEditions(), this.shouldAddRandomEditions(context.random));
				Lookup[] toPoll = list.toPoll;
				Lookup[] toFetch = list.toFetch;
				for (Lookup i : toPoll) {
					if (logDEBUG) {
						Logger.debug(this, "Polling " + i + " for " + this);
					}
					this.attemptsToStart.add(this.add(i, true));
				}
				for (Lookup i : toFetch) {
					if (logMINOR) {
						Logger.minor(this, "Adding checker for edition " + i + " for " + this.origUSK);
					}
					this.attemptsToStart.add(this.add(i, false));
				}
			}
			if ((!this.scheduleAfterDBRsDone) || this.dbrAttempts.isEmpty()) {
				registerNow = !this.fillKeysWatching(curLatest, context);
			}
			else {
				registerNow = false;
			}
		}
		this.finishCancelBefore(killAttempts, context);
		Bucket data = null;
		if (decode && block != null) {
			try {
				data = block.decode(context.getBucketFactory(this.parent.persistent()),
						1025 /* it's an SSK */, true);
			}
			catch (KeyDecodeException ignored) {
			}
			catch (IOException ex) {
				Logger.error(this, "An IOE occured while decoding: " + ex.getMessage(), ex);
			}
		}
		synchronized (this) {
			if (decode) {
				if (block != null) {
					this.lastCompressionCodec = block.getCompressionCodec();
					this.lastWasMetadata = block.isMetadata();
					if (this.keepLastData) {
						if (this.lastRequestData != null) {
							this.lastRequestData.free();
						}
						this.lastRequestData = data;
					}
					else {
						assert data != null;
						data.free();
					}
				}
				else {
					this.lastCompressionCodec = -1;
					this.lastWasMetadata = false;
					this.lastRequestData = null;
				}
			}
		}
		if (!dontUpdate) {
			this.uskManager.updateSlot(this.origUSK, curLatest, context);
		}
		if (registerNow) {
			this.registerAttempts(context);
		}
	}

	private boolean shouldAddRandomEditions(Random random) {
		if (this.firstLoop) {
			return false;
		}
		return random.nextInt(this.dbrHintsStarted + 1) >= this.dbrHintsFound;
	}

	void onCancelled(USKAttempt att, ClientContext context) {
		synchronized (this) {
			this.runningAttempts.remove(att.number);
			if (!this.runningAttempts.isEmpty()) {
				return;
			}

			if (this.cancelled) {
				this.finishCancelled(context);
			}
		}
	}

	private void finishCancelled(ClientContext context) {
		USKFetcherCallback[] cb;
		synchronized (this) {
			this.completed = true;
			cb = this.callbacks.toArray(new USKFetcherCallback[0]);
		}
		for (USKFetcherCallback c : cb) {
			c.onCancelled(context);
		}
	}

	public void onFail(USKAttempt attempt, ClientContext context) {
		// FIXME what else can we do?
		// Certainly we don't want to continue fetching indefinitely...
		// ... e.g. RNFs don't indicate we should try a later slot, none of them
		// really do.
		this.onDNF(attempt, context);
	}

	private List<USKAttempt> cancelBefore(long curLatest, ClientContext context) {
		List<USKAttempt> v = null;
		int count = 0;
		synchronized (this) {
			for (Iterator<USKAttempt> i = this.runningAttempts.values().iterator(); i.hasNext();) {
				USKAttempt att = i.next();
				if (att.number < curLatest) {
					if (v == null) {
						v = new ArrayList<>(this.runningAttempts.size() - count);
					}
					v.add(att);
					i.remove();
				}
				count++;
			}
			for (Iterator<Map.Entry<Long, USKAttempt>> i = this.pollingAttempts.entrySet().iterator(); i.hasNext();) {
				Map.Entry<Long, USKAttempt> entry = i.next();
				if (entry.getKey() < curLatest) {
					if (v == null) {
						v = new ArrayList<>(Math.max(1, this.pollingAttempts.size() - count));
					}
					v.add(entry.getValue());
					i.remove();
				}
				else {
					break; // TreeMap is ordered.
				}
			}
		}
		return v;
	}

	private void finishCancelBefore(List<USKAttempt> v, ClientContext context) {
		if (v != null) {
			for (USKAttempt att : v) {
				att.cancel(context);
			}
		}
	}

	/**
	 * Add a USKAttempt for another edition number. Caller is responsible for calling
	 * .schedule().
	 */
	private synchronized USKAttempt add(Lookup l, boolean forever) {
		long i = l.val;
		if (l.val < 0) {
			throw new IllegalArgumentException("Can't check <0 for " + l.val + " on " + this + " for " + this.origUSK);
		}
		if (this.cancelled) {
			return null;
		}
		if (this.checkStoreOnly) {
			return null;
		}
		if (logMINOR) {
			Logger.minor(this, "Adding USKAttempt for " + i + " for " + this.origUSK.getURI());
		}
		if (forever) {
			if (this.pollingAttempts.containsKey(i)) {
				if (logMINOR) {
					Logger.minor(this, "Already polling edition: " + i + " for " + this);
				}
				return null;
			}
		}
		else {
			if (this.runningAttempts.containsKey(i)) {
				if (logMINOR) {
					Logger.minor(this, "Returning because already running for " + this.origUSK.getURI());
				}
				return null;
			}
		}
		USKAttempt a = new USKAttempt(l, forever);
		if (forever) {
			this.pollingAttempts.put(i, a);
		}
		else {
			this.runningAttempts.put(i, a);
		}
		if (logMINOR) {
			Logger.minor(this, "Added " + a + " for " + this.origUSK);
		}
		return a;
	}

	public FreenetURI getURI() {
		return this.origUSK.getURI();
	}

	public boolean isFinished() {
		synchronized (this) {
			return this.completed || this.cancelled;
		}
	}

	public USK getOriginalUSK() {
		return this.origUSK;
	}

	public void schedule(long delay, final ClientContext context) {
		if (delay <= 0) {
			this.schedule(context);
		}
		else {
			context.ticker.queueTimedJob(() -> USKFetcher.this.schedule(context), delay);
		}
	}

	@Override
	public void schedule(ClientContext context) {
		if (logMINOR) {
			Logger.minor(this, "Scheduling " + this);
		}
		DBRAttempt[] atts = null;
		synchronized (this) {
			if (this.cancelled) {
				return;
			}
			if (this.completed) {
				return;
			}
			if (!this.scheduledDBRs && !this.ctx.ignoreUSKDatehints) {
				atts = this.addDBRs(context);
			}
			this.scheduledDBRs = true;
		}
		context.getSskFetchScheduler(this.realTimeFlag).schedTransient.addPendingKeys(this);
		this.updatePriorities();
		this.uskManager.subscribe(this.origUSK, this, false, this.parent.getClient());
		if (atts != null) {
			this.startDBRs(atts, context);
		}
		long lookedUp = this.uskManager.lookupLatestSlot(this.origUSK);
		boolean registerNow = false;
		boolean bye;
		boolean completeCheckingStore = false;
		synchronized (this) {
			this.valueAtSchedule = Math.max(lookedUp + 1, this.valueAtSchedule);
			bye = this.cancelled || this.completed;
			if (!bye) {

				// subscribe() above may have called onFoundEdition and thus added a load
				// of stuff. If so, we don't need to do so here.
				if ((!this.checkStoreOnly) && this.attemptsToStart.isEmpty() && this.runningAttempts.isEmpty()
						&& this.pollingAttempts.isEmpty()) {
					USKWatchingKeys.ToFetch list = this.watchingKeys.getEditionsToFetch(lookedUp, context.random,
							this.getRunningFetchEditions(), this.shouldAddRandomEditions(context.random));
					Lookup[] toPoll = list.toPoll;
					Lookup[] toFetch = list.toFetch;
					for (Lookup i : toPoll) {
						if (logDEBUG) {
							Logger.debug(this, "Polling " + i + " for " + this);
						}
						this.attemptsToStart.add(this.add(i, true));
					}
					for (Lookup i : toFetch) {
						if (logMINOR) {
							Logger.minor(this, "Adding checker for edition " + i + " for " + this.origUSK);
						}
						this.attemptsToStart.add(this.add(i, false));
					}
				}

				this.started = true;
				if (lookedUp <= 0 && atts != null) {
					// If we don't know anything, do the DBRs first.
					this.scheduleAfterDBRsDone = true;
				}
				else if ((!this.scheduleAfterDBRsDone) || this.dbrAttempts.isEmpty()) {
					registerNow = !this.fillKeysWatching(lookedUp, context);
				}
				completeCheckingStore = this.checkStoreOnly && this.scheduleAfterDBRsDone
						&& this.runningStoreChecker == null;
			}
		}
		if (registerNow) {
			this.registerAttempts(context);
		}
		else if (completeCheckingStore) {
			this.finishSuccess(context);
			return;
		}
		if (!bye) {
			return;
		}
		// We have been cancelled.
		this.uskManager.unsubscribe(this.origUSK, this);
		context.getSskFetchScheduler(this.realTimeFlag).schedTransient.removePendingKeys((KeyListener) this);
		this.uskManager.onFinished(this, true);
	}

	/** Call synchronized, then call startDBRs() */
	private DBRAttempt[] addDBRs(ClientContext context) {
		USKDateHint date = USKDateHint.now();
		ClientSSK[] ssks = date.getRequestURIs(this.origUSK);
		DBRAttempt[] atts = new DBRAttempt[ssks.length];
		int x = 0;
		for (int i = 0; i < ssks.length; i++) {
			ClientKey key = ssks[i];
			DBRAttempt att = new DBRAttempt(key, context, USKDateHint.Type.values()[i]);
			this.dbrAttempts.add(att);
			atts[x++] = att;
		}
		this.dbrHintsStarted = atts.length;
		return atts;
	}

	private void startDBRs(DBRAttempt[] toStart, ClientContext context) {
		for (DBRAttempt att : toStart) {
			att.start(context);
		}
	}

	@Override
	public void cancel(ClientContext context) {
		if (logMINOR) {
			Logger.minor(this, "Cancelling " + this);
		}
		this.uskManager.unsubscribe(this.origUSK, this);
		context.getSskFetchScheduler(this.realTimeFlag).schedTransient.removePendingKeys((KeyListener) this);
		USKAttempt[] attempts;
		USKAttempt[] polling;
		DBRAttempt[] atts;
		this.uskManager.onFinished(this);
		SendableGet storeChecker;
		Bucket data;
		synchronized (this) {
			if (this.cancelled) {
				Logger.error(this, "Already cancelled " + this);
			}
			if (this.completed) {
				Logger.error(this, "Already completed " + this);
			}
			this.cancelled = true;
			attempts = this.runningAttempts.values().toArray(new USKAttempt[0]);
			polling = this.pollingAttempts.values().toArray(new USKAttempt[0]);
			atts = this.dbrAttempts.toArray(new DBRAttempt[0]);
			this.attemptsToStart.clear();
			this.runningAttempts.clear();
			this.pollingAttempts.clear();
			this.dbrAttempts.clear();
			storeChecker = this.runningStoreChecker;
			this.runningStoreChecker = null;
			data = this.lastRequestData;
			this.lastRequestData = null;
		}
		for (USKAttempt attempt : attempts) {
			attempt.cancel(context);
		}
		for (USKAttempt p : polling) {
			p.cancel(context);
		}
		for (DBRAttempt a : atts) {
			a.cancel(context);
		}
		if (storeChecker != null) {
			// Remove from the store checker queue.
			storeChecker.unregister(context, storeChecker.getPriorityClass());
		}
		if (data != null) {
			data.free();
		}
	}

	/**
	 * Set of interested USKCallbacks. Note that we don't actually send them any
	 * information - they are essentially placeholders, an alternative to a refcount. This
	 * could be replaced with a Bloom filter or whatever, we only need .exists and .count.
	 */
	final HashSet<USKCallback> subscribers;

	/** Map from subscribers to hint editions. */
	final HashMap<USKCallback, Long> subscriberHints = new HashMap<>();

	/**
	 * Add a subscriber. Subscribers are not directly sent onFoundEdition()'s by the
	 * USKFetcher, we just use them to determine the priority of our requests and whether
	 * we should continue to request.
	 */
	public void addSubscriber(USKCallback cb, long hint) {
		Long[] hints;
		synchronized (this) {
			this.subscribers.add(cb);
			this.subscriberHints.put(cb, hint);
			hints = this.subscriberHints.values().toArray(new Long[0]);
		}
		this.updatePriorities();
		this.watchingKeys.updateSubscriberHints(hints, this.uskManager.lookupLatestSlot(this.origUSK));
	}

	private void updatePriorities() {
		// FIXME should this be synchronized? IMHO it doesn't matter that much if we get
		// the priority
		// wrong for a few requests... also, we avoid any possible deadlock this way if
		// the callbacks
		// take locks...
		short normalPrio = PriorityClasses.PAUSED_PRIORITY_CLASS;
		short progressPrio = PriorityClasses.PAUSED_PRIORITY_CLASS;
		USKCallback[] localCallbacks;
		USKFetcherCallback[] fetcherCallbacks;
		synchronized (this) {
			localCallbacks = this.subscribers.toArray(new USKCallback[0]);
			// Callbacks also determine the fetcher's priority.
			// Otherwise USKFetcherTag would have no way to tell us the priority we should
			// run at.
			fetcherCallbacks = this.callbacks.toArray(new USKFetcherCallback[0]);
		}
		if (localCallbacks.length == 0 && fetcherCallbacks.length == 0) {
			this.normalPollPriority = DEFAULT_NORMAL_POLL_PRIORITY;
			this.progressPollPriority = DEFAULT_PROGRESS_POLL_PRIORITY;
			if (logMINOR) {
				Logger.minor(this, "Updating priorities: normal = " + this.normalPollPriority + " progress = "
						+ this.progressPollPriority + " for " + this + " for " + this.origUSK);
			}
			return;
		}

		for (USKCallback cb : localCallbacks) {
			short prio = cb.getPollingPriorityNormal();
			if (logDEBUG) {
				Logger.debug(this, "Normal priority for " + cb + " : " + prio);
			}
			if (prio < normalPrio) {
				normalPrio = prio;
			}
			if (logDEBUG) {
				Logger.debug(this, "Progress priority for " + cb + " : " + prio);
			}
			prio = cb.getPollingPriorityProgress();
			if (prio < progressPrio) {
				progressPrio = prio;
			}
		}
		for (USKFetcherCallback cb : fetcherCallbacks) {
			short prio = cb.getPollingPriorityNormal();
			if (logDEBUG) {
				Logger.debug(this, "Normal priority for " + cb + " : " + prio);
			}
			if (prio < normalPrio) {
				normalPrio = prio;
			}
			if (logDEBUG) {
				Logger.debug(this, "Progress priority for " + cb + " : " + prio);
			}
			prio = cb.getPollingPriorityProgress();
			if (prio < progressPrio) {
				progressPrio = prio;
			}
		}
		if (logMINOR) {
			Logger.minor(this, "Updating priorities: normal=" + normalPrio + " progress=" + progressPrio + " for "
					+ this + " for " + this.origUSK);
		}
		synchronized (this) {
			this.normalPollPriority = normalPrio;
			this.progressPollPriority = progressPrio;
		}
	}

	public synchronized boolean hasSubscribers() {
		return !this.subscribers.isEmpty();
	}

	public synchronized boolean hasCallbacks() {
		return !this.callbacks.isEmpty();
	}

	public void removeSubscriber(USKCallback cb, ClientContext context) {
		Long[] hints;
		synchronized (this) {
			this.subscribers.remove(cb);
			this.subscriberHints.remove(cb);
			hints = this.subscriberHints.values().toArray(new Long[0]);
		}
		this.updatePriorities();
		this.watchingKeys.updateSubscriberHints(hints, this.uskManager.lookupLatestSlot(this.origUSK));
	}

	public void removeCallback(USKCallback cb) {
		Long[] hints;
		synchronized (this) {
			this.subscribers.remove(cb);
			this.subscriberHints.remove(cb);
			hints = this.subscriberHints.values().toArray(new Long[0]);
		}
		this.watchingKeys.updateSubscriberHints(hints, this.uskManager.lookupLatestSlot(this.origUSK));
	}

	@Override
	public long getToken() {
		return -1;
	}

	@Override
	public short getPollingPriorityNormal() {
		throw new UnsupportedOperationException();
	}

	@Override
	public short getPollingPriorityProgress() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void onFoundEdition(long ed, USK key, final ClientContext context, boolean metadata, short codec,
			byte[] data, boolean newKnownGood, boolean newSlotToo) {
		if (newKnownGood && !newSlotToo) {
			return; // Only interested in slots
		}
		// Because this is frequently run off-thread, it is actually possible that the
		// looked up edition is not the same as the edition we are being notified of.
		final long lastEd = this.uskManager.lookupLatestSlot(this.origUSK);
		boolean decode;
		List<USKAttempt> killAttempts = null;
		boolean registerNow;
		synchronized (this) {
			if (this.completed || this.cancelled) {
				return;
			}
			decode = lastEd == ed && data != null;
			ed = Math.max(lastEd, ed);
			if (logMINOR) {
				Logger.minor(this, "Latest: " + ed + " in onFoundEdition");
			}

			if (!this.checkStoreOnly) {
				killAttempts = this.cancelBefore(ed, context);
				USKWatchingKeys.ToFetch list = this.watchingKeys.getEditionsToFetch(ed, context.random,
						this.getRunningFetchEditions(), this.shouldAddRandomEditions(context.random));
				Lookup[] toPoll = list.toPoll;
				Lookup[] toFetch = list.toFetch;
				for (Lookup i : toPoll) {
					if (logMINOR) {
						Logger.minor(this, "Polling " + i + " for " + this + " in onFoundEdition");
					}
					this.attemptsToStart.add(this.add(i, true));
				}
				for (Lookup i : toFetch) {
					if (logMINOR) {
						Logger.minor(this,
								"Adding checker for edition " + i + " for " + this.origUSK + " in onFoundEdition");
					}
					this.attemptsToStart.add(this.add(i, false));
				}
			}
			if ((!this.scheduleAfterDBRsDone) || this.dbrAttempts.isEmpty()) {
				registerNow = !this.fillKeysWatching(ed, context);
			}
			else {
				registerNow = false;
			}

		}
		this.finishCancelBefore(killAttempts, context);
		if (registerNow) {
			this.registerAttempts(context);
		}
		synchronized (this) {
			if (decode) {
				this.lastCompressionCodec = codec;
				this.lastWasMetadata = metadata;
				if (this.keepLastData) {
					// FIXME inefficient to convert from bucket to byte[] to bucket
					if (this.lastRequestData != null) {
						this.lastRequestData.free();
					}
					try {
						this.lastRequestData = BucketTools.makeImmutableBucket(context.tempBucketFactory, data);
					}
					catch (IOException ex) {
						Logger.error(this, "Caught " + ex, ex);
					}
				}
			}
		}
	}

	private synchronized List<Lookup> getRunningFetchEditions() {
		List<Lookup> ret = new ArrayList<>();
		for (USKAttempt a : this.runningAttempts.values()) {
			if (!ret.contains(a.lookup)) {
				ret.add(a.lookup);
			}
		}
		for (USKAttempt a : this.pollingAttempts.values()) {
			if (!ret.contains(a.lookup)) {
				ret.add(a.lookup);
			}
		}
		return ret;
	}

	private void registerAttempts(ClientContext context) {
		USKAttempt[] attempts;
		synchronized (USKFetcher.this) {
			if (this.cancelled || this.completed) {
				return;
			}
			attempts = this.attemptsToStart.toArray(new USKAttempt[0]);
			this.attemptsToStart.clear();
		}

		if (attempts.length > 0) {
			this.parent.toNetwork(context);
		}
		if (logMINOR) {
			Logger.minor(this, "Registering " + attempts.length + " USKChecker's for " + this + " running="
					+ this.runningAttempts.size() + " polling=" + this.pollingAttempts.size());
		}
		for (USKAttempt attempt : attempts) {
			// Look up on each iteration since scheduling can cause new editions to be
			// found sometimes.
			long lastEd = this.uskManager.lookupLatestSlot(this.origUSK);
			synchronized (USKFetcher.this) {
				// FIXME not sure this condition works, test it!
				if (this.keepLastData && this.lastRequestData == null && lastEd == this.origUSK.suggestedEdition) {
					lastEd--; // If we want the data, then get it for the known edition,
				}
				// so we always get the data, so USKInserter can compare
				// it and return the old edition if it is identical.
			}
			if (attempt == null) {
				continue;
			}
			if (attempt.number > lastEd) {
				attempt.schedule(context);
			}
			else {
				synchronized (USKFetcher.this) {
					this.runningAttempts.remove(attempt.number);
				}
			}
		}
	}

	private StoreCheckerGetter runningStoreChecker = null;

	private boolean fillKeysWatching(long ed, ClientContext context) {
		synchronized (this) {
			// Do not run a new one until this one has finished.
			// StoreCheckerGetter itself will automatically call back to fillKeysWatching
			// so there is no chance of losing it.
			if (this.runningStoreChecker != null) {
				return true;
			}
			final USKStoreChecker checker = this.watchingKeys.getDatastoreChecker(ed);
			if (checker == null) {
				if (logMINOR) {
					Logger.minor(this, "No datastore checker");
				}
				return false;
			}

			this.runningStoreChecker = new StoreCheckerGetter(this.parent, checker);
		}
		try {
			context.getSskFetchScheduler(this.realTimeFlag).register(null,
					new SendableGet[] { this.runningStoreChecker }, false, null, false);
		}
		catch (Throwable ex) {
			synchronized (this) {
				this.runningStoreChecker = null;
			}
			Logger.error(this, "Unable to start: " + ex, ex);
			try {
				this.runningStoreChecker.unregister(context, this.progressPollPriority);
			}
			catch (Throwable ignored) {
				// Ignore, hopefully it's already unregistered
			}
		}
		if (logMINOR) {
			Logger.minor(this, "Registered " + this.runningStoreChecker + " for " + this);
		}
		return true;
	}

	@Override
	public synchronized boolean isCancelled() {
		return this.completed || this.cancelled;
	}

	@Override
	public KeyListener makeKeyListener(ClientContext context, boolean onStartup) {
		return this;
	}

	@Override
	public synchronized long countKeys() {
		return this.watchingKeys.size();
	}

	@Override
	public short definitelyWantKey(Key key, byte[] saltedKey, ClientContext context) {
		if (!(key instanceof NodeSSK k)) {
			return -1;
		}
		if (!this.origUSK.samePubKeyHash(k)) {
			return -1;
		}
		long lastSlot = this.uskManager.lookupLatestSlot(this.origUSK) + 1;
		synchronized (this) {
			if (this.watchingKeys.match(k, lastSlot) != -1) {
				return this.progressPollPriority;
			}
		}
		return -1;
	}

	@Override
	public HasKeyListener getHasKeyListener() {
		return this;
	}

	@Override
	public short getPriorityClass() {
		return this.progressPollPriority;
	}

	@Override
	public SendableGet[] getRequestsForKey(Key key, byte[] saltedKey, ClientContext context) {
		return new SendableGet[0];
	}

	@Override
	public boolean handleBlock(Key key, byte[] saltedKey, KeyBlock found, ClientContext context) {
		if (!(found instanceof SSKBlock)) {
			return false;
		}
		long lastSlot = this.uskManager.lookupLatestSlot(this.origUSK) + 1;
		long edition = this.watchingKeys.match((NodeSSK) key, lastSlot);
		if (edition == -1) {
			return false;
		}
		if (logMINOR) {
			Logger.minor(this, "Matched edition " + edition + " for " + this.origUSK);
		}

		ClientSSKBlock data;
		try {
			data = this.watchingKeys.decode((SSKBlock) found, edition);
		}
		catch (SSKVerifyException ex) {
			data = null;
		}
		this.onSuccess(null, edition, false, data, context);
		return true;
	}

	@Override
	public synchronized boolean isEmpty() {
		return this.cancelled || this.completed;
	}

	@Override
	public boolean isSSK() {
		return true;
	}

	@Override
	public void onRemove() {
		// Ignore
	}

	@Override
	public boolean persistent() {
		return false;
	}

	@Override
	public boolean probablyWantKey(Key key, byte[] saltedKey) {
		if (!(key instanceof NodeSSK k)) {
			return false;
		}
		if (!this.origUSK.samePubKeyHash(k)) {
			return false;
		}
		long lastSlot = this.uskManager.lookupLatestSlot(this.origUSK) + 1;
		synchronized (this) {
			return this.watchingKeys.match(k, lastSlot) != -1;
		}
	}

	/**
	 * FIXME this is a special case hack For a generic solution see <a href=
	 * "https://bugs.freenetproject.org/view.php?id=4984">https://bugs.freenetproject.org/view.php?id=4984</a>
	 */
	public void changeUSKPollParameters(long time, int tries, ClientContext context) {
		this.ctx.setCooldownRetries(tries);
		this.ctxNoStore.setCooldownRetries(tries);
		this.ctx.setCooldownTime(time);
		this.ctxNoStore.setCooldownTime(time);
		USKAttempt[] pollers;
		synchronized (this) {
			pollers = this.pollingAttempts.values().toArray(new USKAttempt[0]);
		}
		for (USKAttempt a : pollers) {
			a.reloadPollParameters(context);
		}
	}

	public void addHintEdition(long suggestedEdition) {
		this.watchingKeys.addHintEdition(suggestedEdition, this.uskManager.lookupLatestSlot(this.origUSK));
	}

	@Override
	public void onResume(ClientContext context) {
		throw new UnsupportedOperationException("Not persistent");
	}

	@Override
	public void onShutdown(ClientContext context) {
		throw new UnsupportedOperationException("Not persistent");
	}

	class DBRFetcher extends SimpleSingleFileFetcher {

		DBRFetcher(ClientKey key, int maxRetries, FetchContext ctx, ClientRequester parent, GetCompletionCallback rcb,
				boolean isEssential, boolean dontAdd, long l, ClientContext context, boolean deleteFetchContext,
				boolean realTimeFlag) {
			super(key, maxRetries, ctx, parent, rcb, isEssential, dontAdd, l, context, deleteFetchContext,
					realTimeFlag);
		}

		@Override
		public short getPriorityClass() {
			return USKFetcher.this.progressPollPriority;
		}

		@Override
		public String toString() {
			return super.objectToString() + " for " + USKFetcher.this + " for " + USKFetcher.this.origUSK;
		}

	}

	public class DBRAttempt implements GetCompletionCallback {

		final SimpleSingleFileFetcher fetcher;

		final USKDateHint.Type type;

		DBRAttempt(ClientKey key, ClientContext context, USKDateHint.Type type) {
			this.fetcher = new DBRFetcher(key, USKFetcher.this.ctxDBR.maxUSKRetries, USKFetcher.this.ctxDBR,
					USKFetcher.this.parent, this, false, true, 0, context, false, USKFetcher.this.realTimeFlag);
			this.type = type;
			if (logMINOR) {
				Logger.minor(this, "Created " + this + " with " + this.fetcher);
			}
		}

		@Override
		public void onSuccess(StreamGenerator streamGenerator, ClientMetadata clientMetadata,
				List<? extends Compressor> decompressors, ClientGetState state, ClientContext context) {
			OutputStream output = null;
			PipedInputStream pipeIn = new PipedInputStream();
			PipedOutputStream pipeOut = new PipedOutputStream();
			Bucket data = null;
			long maxLen = Math.max(USKFetcher.this.ctx.maxTempLength, USKFetcher.this.ctx.maxOutputLength);
			try {
				data = context.getBucketFactory(false).makeBucket(maxLen);
				output = data.getOutputStream();
				if (decompressors != null) {
					if (logMINOR) {
						Logger.minor(this, "decompressing...");
					}
					pipeOut.connect(pipeIn);
					DecompressorThreadManager decompressorManager = new DecompressorThreadManager(pipeIn, decompressors,
							maxLen);
					pipeIn = decompressorManager.execute();
					ClientGetWorkerThread worker = new ClientGetWorkerThread(new BufferedInputStream(pipeIn), output,
							null, null, USKFetcher.this.ctx.getSchemeHostAndPort(), null, false, null, null, null,
							context.linkFilterExceptionProvider);
					worker.start();
					streamGenerator.writeTo(pipeOut, context);
					decompressorManager.waitFinished();
					worker.waitFinished();
				}
				else {
					streamGenerator.writeTo(output, context);
				}

				output.close();
				pipeOut.close();
				pipeIn.close();
				output = null;
				pipeOut = null;
				pipeIn = null;

				// Run directly - we are running on some thread somewhere, don't worry
				// about it.
				this.innerSuccess(data, context);
			}
			catch (Throwable ex) {
				Logger.error(this, "Caught " + ex, ex);
				this.onFailure(new FetchException(FetchExceptionMode.INTERNAL_ERROR, ex), state, context);
			}
			finally {
				boolean dbrsFinished;
				synchronized (USKFetcher.this) {
					USKFetcher.this.dbrAttempts.remove(this);
					if (logMINOR) {
						Logger.minor(this, "Remaining DBR attempts: " + USKFetcher.this.dbrAttempts);
					}
					dbrsFinished = USKFetcher.this.dbrAttempts.isEmpty();
				}
				BucketCloser.close(pipeOut);
				BucketCloser.close(pipeIn);
				BucketCloser.close(output);
				if (dbrsFinished) {
					USKFetcher.this.onDBRsFinished(context);
				}
				BucketCloser.close(data);
			}
		}

		private void innerSuccess(Bucket bucket, ClientContext context) {
			byte[] data;
			try {
				data = BucketTools.toByteArray(bucket);
			}
			catch (IOException ex) {
				Logger.error(this, "Unable to read hint data because of I/O error, maybe bad decompression?: " + ex,
						ex);
				return;
			}
			String line;
			try {
				line = new String(data, StandardCharsets.UTF_8);
			}
			catch (Throwable ex) {
				// Something very bad happened, most likely bogus encoding.
				// Ignore it.
				Logger.error(this, "Impossible throwable - maybe bogus encoding?: " + ex, ex);
				return;
			}
			String[] split = line.split("\n");
			if (split.length < 3) {
				Logger.error(this, "Unable to parse hint (not enough lines): \"" + line + "\"");
				return;
			}
			if (!split[0].startsWith("HINT")) {
				Logger.error(this, "Unable to parse hint (first line doesn't start with HINT): \"" + line + "\"");
				return;
			}
			String value = split[1];
			long hint;
			try {
				hint = Long.parseLong(value);
			}
			catch (NumberFormatException ex) {
				Logger.error(this, "Unable to parse hint \"" + value + "\"", ex);
				return;
			}
			if (logMINOR) {
				Logger.minor(this, "Found DBR hint edition " + hint + " for " + this.fetcher.getKey(null).getURI()
						+ " for " + USKFetcher.this);
			}
			USKFetcher.this.processDBRHint(hint, context, this);
		}

		@Override
		public void onFailure(FetchException e, ClientGetState state, ClientContext context) {
			// Okay.
			if (logMINOR) {
				Logger.minor(this, "Failed to fetch hint " + this.fetcher.getKey(null) + " for " + this + " for "
						+ USKFetcher.this);
			}
			boolean dbrsFinished;
			synchronized (USKFetcher.this) {
				USKFetcher.this.dbrAttempts.remove(this);
				if (logMINOR) {
					Logger.minor(this, "Remaining DBR attempts: " + USKFetcher.this.dbrAttempts);
				}
				dbrsFinished = USKFetcher.this.dbrAttempts.isEmpty();
			}
			if (dbrsFinished) {
				USKFetcher.this.onDBRsFinished(context);
			}
		}

		@Override
		public void onBlockSetFinished(ClientGetState state, ClientContext context) {
			// Ignore
		}

		@Override
		public void onTransition(ClientGetState oldState, ClientGetState newState, ClientContext context) {
			// Ignore
		}

		@Override
		public void onExpectedSize(long size, ClientContext context) {
			// Ignore
		}

		@Override
		public void onExpectedMIME(ClientMetadata meta, ClientContext context) {
			// Ignore
		}

		@Override
		public void onFinalizedMetadata() {
			// Ignore
		}

		@Override
		public void onExpectedTopSize(long size, long compressed, int blocksReq, int blocksTotal,
				ClientContext context) {
			// Ignore
		}

		@Override
		public void onSplitfileCompatibilityMode(CompatibilityMode min, CompatibilityMode max,
				byte[] customSplitfileKey, boolean compressed, boolean bottomLayer, boolean definitiveAnyway,
				ClientContext context) {
			// Ignore
		}

		@Override
		public void onHashes(HashResult[] hashes, ClientContext context) {
			// Ignore
		}

		public void start(ClientContext context) {
			this.fetcher.schedule(context);
		}

		public void cancel(ClientContext context) {
			this.fetcher.cancel(context);
		}

	}

	public class USKAttempt implements USKCheckerCallback {

		/** Edition number */
		long number;

		/** Attempt to fetch that edition number (or null if the fetch has finished) */
		USKChecker checker;

		/** Successful fetch? */
		boolean succeeded;

		/** DNF? */
		boolean dnf;

		boolean cancelled;

		final Lookup lookup;

		final boolean forever;

		private boolean everInCooldown;

		public USKAttempt(Lookup l, boolean forever) {
			this.lookup = l;
			this.number = l.val;
			this.succeeded = false;
			this.dnf = false;
			this.forever = forever;
			this.checker = new USKChecker(this, l.key, forever ? -1 : USKFetcher.this.ctx.maxUSKRetries,
					l.ignoreStore ? USKFetcher.this.ctxNoStore : USKFetcher.this.ctx, USKFetcher.this.parent,
					USKFetcher.this.realTimeFlag);
		}

		@Override
		public void onDNF(ClientContext context) {
			synchronized (this) {
				this.checker = null;
				this.dnf = true;
			}
			USKFetcher.this.onDNF(this, context);
		}

		@Override
		public void onSuccess(ClientSSKBlock block, ClientContext context) {
			synchronized (this) {
				this.checker = null;
				this.succeeded = true;
			}
			USKFetcher.this.onSuccess(this, false, block, context);
		}

		@Override
		public void onFatalAuthorError(ClientContext context) {
			synchronized (this) {
				this.checker = null;
			}
			// Counts as success except it doesn't update
			USKFetcher.this.onSuccess(this, true, null, context);
		}

		@Override
		public void onNetworkError(ClientContext context) {
			synchronized (this) {
				this.checker = null;
			}
			// Not a DNF
			USKFetcher.this.onFail(this, context);
		}

		@Override
		public void onCancelled(ClientContext context) {
			synchronized (this) {
				this.checker = null;
			}
			USKFetcher.this.onCancelled(this, context);
		}

		public void cancel(ClientContext context) {
			this.cancelled = true;
			USKChecker c;
			synchronized (this) {
				c = this.checker;
			}
			if (c != null) {
				c.cancel(context);
			}
			this.onCancelled(context);
		}

		public void schedule(ClientContext context) {
			USKChecker c;
			synchronized (this) {
				c = this.checker;
			}
			if (c == null) {
				if (logMINOR) {
					Logger.minor(this, "Checker == null in schedule() for " + this, new Exception("debug"));
				}
			}
			else {
				assert (!c.persistent());
				c.schedule(context);
			}
		}

		@Override
		public String toString() {
			return "USKAttempt for " + this.number + " for " + USKFetcher.this.origUSK.getURI() + " for "
					+ USKFetcher.this + (this.forever ? " (forever)" : "");
		}

		@Override
		public short getPriority() {
			if (USKFetcher.this.backgroundPoll) {
				synchronized (this) {
					if (this.forever) {
						if (!this.everInCooldown) {
							// Boost the priority initially, so that finding the first
							// edition takes precedence over ongoing polling after we're
							// fairly sure we're not going to find anything.
							// The ongoing polling keeps the ULPRs up to date so that we
							// will get told quickly, but if we are overloaded we won't be
							// able to keep up regardless.
							return USKFetcher.this.progressPollPriority;
						}
						else {
							return USKFetcher.this.normalPollPriority;
						}
					}
					else {
						// If !forever, this is a random-probe.
						// It's not that important.
						return USKFetcher.this.normalPollPriority;
					}
				}
			}
			return USKFetcher.this.parent.getPriorityClass();
		}

		@Override
		public void onEnterFiniteCooldown(ClientContext context) {
			synchronized (this) {
				this.everInCooldown = true;
			}
			USKFetcher.this.onCheckEnteredFiniteCooldown(context);
		}

		public synchronized boolean everInCooldown() {
			return this.everInCooldown;
		}

		public void reloadPollParameters(ClientContext context) {
			USKChecker c;
			synchronized (this) {
				c = this.checker;
			}
			if (c == null) {
				return;
			}
			c.onChangedFetchContext(context);
		}

	}

	class USKStoreChecker {

		final USKWatchingKeys.KeyList.StoreSubChecker[] checkers;

		USKStoreChecker(List<USKWatchingKeys.KeyList.StoreSubChecker> c) {
			this.checkers = c.toArray(new USKWatchingKeys.KeyList.StoreSubChecker[0]);
		}

		USKStoreChecker(USKWatchingKeys.KeyList.StoreSubChecker[] checkers2) {
			this.checkers = checkers2;
		}

		Key[] getKeys() {
			if (this.checkers.length == 0) {
				return new Key[0];
			}
			else if (this.checkers.length == 1) {
				return this.checkers[0].keysToCheck;
			}
			else {
				int x = 0;
				for (USKWatchingKeys.KeyList.StoreSubChecker checker : this.checkers) {
					x += checker.keysToCheck.length;
				}
				Key[] keys = new Key[x];
				int ptr = 0;
				// FIXME more intelligent (cheaper) merging algorithm, e.g. considering
				// the ranges in each.
				HashSet<Key> check = new HashSet<>();
				for (USKWatchingKeys.KeyList.StoreSubChecker checker : this.checkers) {
					for (Key k : checker.keysToCheck) {
						if (!check.add(k)) {
							continue;
						}
						keys[ptr++] = k;
					}
				}
				if (keys.length != ptr) {
					keys = Arrays.copyOf(keys, ptr);
				}
				return keys;
			}
		}

		void checked() {
			for (USKWatchingKeys.KeyList.StoreSubChecker checker : this.checkers) {
				checker.checked();
			}
		}

	}

	class StoreCheckerGetter extends SendableGet {

		StoreCheckerGetter(ClientRequester parent, USKStoreChecker c) {
			super(parent, USKFetcher.this.realTimeFlag);
			this.checker = c;
		}

		public final USKStoreChecker checker;

		boolean done = false;

		@Override
		public FetchContext getContext() {
			return USKFetcher.this.ctx;
		}

		@Override
		public long getCooldownWakeup(SendableRequestItem token, ClientContext context) {
			return -1;
		}

		@Override
		public ClientKey getKey(SendableRequestItem token) {
			return null;
		}

		@Override
		public Key[] listKeys() {
			return this.checker.getKeys();
		}

		@Override
		public void onFailure(LowLevelException e, SendableRequestItem token, ClientContext context) {
			// Ignore
		}

		@Override
		public boolean preRegister(ClientContext context, boolean toNetwork) {
			this.unregister(context, this.getPriorityClass());
			USKAttempt[] attempts;
			synchronized (USKFetcher.this) {
				USKFetcher.this.runningStoreChecker = null;
				// FIXME should we only start the USKAttempt's if the datastore check
				// hasn't made progress?
				attempts = USKFetcher.this.attemptsToStart.toArray(new USKAttempt[0]);
				USKFetcher.this.attemptsToStart.clear();
				this.done = true;
				if (USKFetcher.this.cancelled) {
					return true;
				}
			}
			this.checker.checked();

			if (logMINOR) {
				Logger.minor(this, "Checked datastore, finishing registration for " + attempts.length + " checkers for "
						+ USKFetcher.this + " for " + USKFetcher.this.origUSK);
			}
			if (attempts.length > 0) {
				this.parent.toNetwork(context);
				USKFetcher.this.notifySendingToNetwork(context);
			}
			for (USKAttempt attempt : attempts) {
				long lastEd = USKFetcher.this.uskManager.lookupLatestSlot(USKFetcher.this.origUSK);
				synchronized (USKFetcher.this) {
					// FIXME not sure this condition works, test it!
					if (USKFetcher.this.keepLastData && USKFetcher.this.lastRequestData == null
							&& lastEd == USKFetcher.this.origUSK.suggestedEdition) {
						lastEd--; // If we want the data, then get it for the known
					}
					// edition, so we always get the data, so USKInserter
					// can compare it and return the old edition if it is
					// identical.
				}
				if (attempt == null) {
					continue;
				}
				if (attempt.number > lastEd) {
					attempt.schedule(context);
				}
				else {
					synchronized (USKFetcher.this) {
						USKFetcher.this.runningAttempts.remove(attempt.number);
						USKFetcher.this.pollingAttempts.remove(attempt.number);
					}
				}
			}
			long lastEd = USKFetcher.this.uskManager.lookupLatestSlot(USKFetcher.this.origUSK);
			// Do not check beyond WATCH_KEYS after the current slot.
			if (!USKFetcher.this.fillKeysWatching(lastEd, context)) {
				if (USKFetcher.this.checkStoreOnly) {
					if (logMINOR) {
						Logger.minor(this, "Just checking store, terminating " + USKFetcher.this + " ...");
					}
					synchronized (this) {
						if (!USKFetcher.this.dbrAttempts.isEmpty()) {
							USKFetcher.this.scheduleAfterDBRsDone = true;
							return true;
						}
					}
					USKFetcher.this.finishSuccess(context);
				}
				// No need to call registerAttempts as we have already registered them.
			}
			return true;
		}

		@Override
		public SendableRequestItem chooseKey(KeysFetchingLocally keys, ClientContext context) {
			return null;
		}

		@Override
		public long countAllKeys(ClientContext context) {
			return USKFetcher.this.watchingKeys.size();
		}

		@Override
		public long countSendableKeys(ClientContext context) {
			return 0;
		}

		@Override
		public RequestClient getClient() {
			return this.realTimeFlag ? USKManager.rcRT : USKManager.rcBulk;
		}

		@Override
		public ClientRequester getClientRequest() {
			return this.parent;
		}

		@Override
		public short getPriorityClass() {
			return USKFetcher.this.progressPollPriority; // FIXME
		}

		@Override
		public boolean isCancelled() {
			return this.done || USKFetcher.this.cancelled || USKFetcher.this.completed;
		}

		@Override
		public boolean isSSK() {
			return true;
		}

		@Override
		public long getWakeupTime(ClientContext context, long now) {
			return 0;
		}

		@Override
		protected ClientGetState getClientGetState() {
			return USKFetcher.this;
		}

	}

	/**
	 * Tracks the list of editions that we want to fetch, from various sources -
	 * subscribers, origUSK, last known slot from USKManager, etc.
	 *
	 * LOCKING: Take the lock on this class last and always pass in lookup values. Do not
	 * lookup values in USKManager inside this class's lock.
	 *
	 * @author Matthew Toseland &lt;toad@amphibian.dyndns.org&gt; (0xE43DA450)
	 */
	private class USKWatchingKeys {

		// Common for whole USK
		final byte[] pubKeyHash;

		final byte cryptoAlgorithm;

		// List of slots since the USKManager's current last known good edition.
		private final KeyList fromLastKnownSlot;

		private final TreeMap<Long, KeyList> fromSubscribers;

		private final TreeSet<Long> persistentHints = new TreeSet<>();

		// private ArrayList<KeyList> fromCallbacks;

		// FIXME add more WeakReference<KeyList>'s: one for the origUSK, one for each
		// subscriber who gave an edition number. All of which should disappear on the
		// subscriber going or on the last known superceding.

		USKWatchingKeys(USK origUSK, long lookedUp) {
			this.pubKeyHash = origUSK.getPubKeyHash();
			this.cryptoAlgorithm = origUSK.cryptoAlgorithm;
			if (logMINOR) {
				Logger.minor(this, "Creating KeyList from last known good: " + lookedUp);
			}
			this.fromLastKnownSlot = new KeyList(lookedUp);
			this.fromSubscribers = new TreeMap<>();
			if (origUSK.suggestedEdition > lookedUp) {
				this.fromSubscribers.put(origUSK.suggestedEdition, new KeyList(origUSK.suggestedEdition));
			}
		}

		/**
		 * Get a bunch of editions to probe for.
		 * @param lookedUp The current best known slot, from USKManager.
		 * @param random The random number generator.
		 * @param alreadyRunning This will be modified: We will remove anything that
		 * should still be running from it.
		 * @return Editions to fetch and editions to poll for.
		 */
		synchronized ToFetch getEditionsToFetch(long lookedUp, Random random, List<Lookup> alreadyRunning,
				boolean doRandom) {

			if (logMINOR) {
				Logger.minor(this,
						"Get editions to fetch, latest slot is " + lookedUp + " running is " + alreadyRunning);
			}

			List<Lookup> toFetch = new ArrayList<>();
			List<Lookup> toPoll = new ArrayList<>();

			boolean probeFromLastKnownGood = lookedUp > -1
					|| (USKFetcher.this.backgroundPoll && !USKFetcher.this.firstLoop) || this.fromSubscribers.isEmpty();

			if (probeFromLastKnownGood) {
				this.fromLastKnownSlot.getNextEditions(toFetch, toPoll, lookedUp, alreadyRunning, random);
			}

			// If we have moved past the origUSK, then clear the KeyList for it.
			for (Iterator<Entry<Long, KeyList>> it = this.fromSubscribers.entrySet().iterator(); it.hasNext();) {
				Entry<Long, KeyList> entry = it.next();
				long l = entry.getKey() - 1;
				if (l <= lookedUp) {
					it.remove();
				}
				entry.getValue().getNextEditions(toFetch, toPoll, l - 1, alreadyRunning, random);
			}

			if (doRandom) {
				// Now getRandomEditions
				// But how many???
				int runningRandom = 0;
				for (Lookup l : alreadyRunning) {
					if (toFetch.contains(l) || toPoll.contains(l)) {
						continue;
					}
					runningRandom++;
				}

				int allowedRandom = 1 + this.fromSubscribers.size();
				if (logMINOR) {
					Logger.minor(this, "Running random requests: " + runningRandom + " total allowed: " + allowedRandom
							+ " looked up is " + lookedUp + " for " + USKFetcher.this);
				}

				allowedRandom -= runningRandom;

				if (allowedRandom > 0 && probeFromLastKnownGood) {
					this.fromLastKnownSlot.getRandomEditions(toFetch, lookedUp, alreadyRunning, random, 1);
					allowedRandom -= 1;
				}

				for (Iterator<KeyList> it = this.fromSubscribers.values().iterator(); allowedRandom >= 2
						&& it.hasNext();) {
					KeyList k = it.next();
					k.getRandomEditions(toFetch, lookedUp, alreadyRunning, random, 1);
					allowedRandom -= 1;
				}
			}

			return new ToFetch(toFetch, toPoll);
		}

		synchronized void updateSubscriberHints(Long[] hints, long lookedUp) {
			List<Long> surviving = new ArrayList<>();
			Arrays.sort(hints);
			long prev = -1;
			for (Long hint : hints) {
				if (hint == prev) {
					continue;
				}
				prev = hint;
				if (hint <= lookedUp) {
					continue;
				}
				surviving.add(hint);
			}
			for (Iterator<Long> i = this.persistentHints.iterator(); i.hasNext();) {
				Long hint = i.next();
				if (hint <= lookedUp) {
					i.remove();
				}
				if (surviving.contains(hint)) {
					continue;
				}
				surviving.add(hint);
			}
			if (USKFetcher.this.origUSK.suggestedEdition > lookedUp
					&& !surviving.contains(USKFetcher.this.origUSK.suggestedEdition)) {
				surviving.add(USKFetcher.this.origUSK.suggestedEdition);
			}
			for (Iterator<Long> it = this.fromSubscribers.keySet().iterator(); it.hasNext();) {
				Long l = it.next();
				if (surviving.contains(l)) {
					continue;
				}
				it.remove();
			}
			for (Long l : surviving) {
				if (this.fromSubscribers.containsKey(l)) {
					continue;
				}
				this.fromSubscribers.put(l, new KeyList(l));
			}
		}

		synchronized void addHintEdition(long suggestedEdition, long lookedUp) {
			if (suggestedEdition <= lookedUp) {
				return;
			}
			if (!this.persistentHints.add(suggestedEdition)) {
				return;
			}
			if (this.fromSubscribers.containsKey(suggestedEdition)) {
				return;
			}
			this.fromSubscribers.put(suggestedEdition, new KeyList(suggestedEdition));
		}

		synchronized long size() {
			// FIXME take overlap into account
			return WATCH_KEYS + (long) this.fromSubscribers.size() * WATCH_KEYS;
		}

		synchronized USKStoreChecker getDatastoreChecker(long lastSlot) {
			// Check WATCH_KEYS from last known good slot.
			// FIXME: Take into account origUSK, subscribers, etc.
			if (logMINOR) {
				Logger.minor(this, "Getting datastore checker from " + lastSlot + " for " + USKFetcher.this.origUSK
						+ " on " + USKFetcher.this, new Exception("debug"));
			}
			List<KeyList.StoreSubChecker> checkers = new ArrayList<>();
			KeyList.StoreSubChecker c = this.fromLastKnownSlot.checkStore(lastSlot + 1);
			if (c != null) {
				checkers.add(c);
			}
			// If we have moved past the origUSK, then clear the KeyList for it.
			for (Iterator<Entry<Long, KeyList>> it = this.fromSubscribers.entrySet().iterator(); it.hasNext();) {
				Entry<Long, KeyList> entry = it.next();
				long l = entry.getKey();
				if (l <= lastSlot) {
					it.remove();
				}
				c = entry.getValue().checkStore(l);
				if (c != null) {
					checkers.add(c);
				}
			}
			if (checkers.size() > 0) {
				return new USKStoreChecker(checkers);
			}
			else {
				return null;
			}
		}

		ClientSSKBlock decode(SSKBlock block, long edition) throws SSKVerifyException {
			ClientSSK csk = USKFetcher.this.origUSK.getSSK(edition);
			assert (Arrays.equals(csk.ehDocname, block.getKey().getKeyBytes()));
			return ClientSSKBlock.construct(block, csk);
		}

		synchronized long match(NodeSSK key, long lastSlot) {
			if (logMINOR) {
				Logger.minor(this,
						"Trying to match " + key + " from slot " + lastSlot + " for " + USKFetcher.this.origUSK);
			}
			long ret = this.fromLastKnownSlot.match(key, lastSlot);
			if (ret != -1) {
				return ret;
			}

			for (Iterator<Entry<Long, KeyList>> it = this.fromSubscribers.entrySet().iterator(); it.hasNext();) {
				Entry<Long, KeyList> entry = it.next();
				long l = entry.getKey();
				if (l <= lastSlot) {
					it.remove();
				}
				ret = entry.getValue().match(key, l);
				if (ret != -1) {
					return ret;
				}
			}
			return -1;
		}

		class ToFetch {

			ToFetch(List<Lookup> toFetch2, List<Lookup> toPoll2) {
				this.toFetch = toFetch2.toArray(new Lookup[0]);
				this.toPoll = toPoll2.toArray(new Lookup[0]);
			}

			public final Lookup[] toFetch;

			public final Lookup[] toPoll;

		}

		/**
		 * A precomputed list of E(H(docname))'s for each slot we might match. This is
		 * from an edition number which might be out of date.
		 */
		class KeyList {

			/** The USK edition number of the first slot */
			long firstSlot;

			/** The precomputed E(H(docname)) for each such slot. */
			private WeakReference<RemoveRangeArrayList<byte[]>> cache;

			/** We have checked the datastore from this point. */
			private long checkedDatastoreFrom = -1;

			/** We have checked the datastore up to this point. */
			private long checkedDatastoreTo = -1;

			KeyList(long slot) {
				if (logMINOR) {
					Logger.minor(this, "Creating KeyList from " + slot + " on " + USKFetcher.this + " " + this,
							new Exception("debug"));
				}
				this.firstSlot = slot;
				RemoveRangeArrayList<byte[]> ehDocnames = new RemoveRangeArrayList<>(WATCH_KEYS);
				this.cache = new WeakReference<>(ehDocnames);
				this.generate(this.firstSlot, WATCH_KEYS, ehDocnames);
			}

			/**
			 * Add the next bunch of editions to fetch to toFetch and toPoll. If they are
			 * already running, REMOVE THEM from the alreadyRunning array.
			 */
			synchronized void getNextEditions(List<Lookup> toFetch, List<Lookup> toPoll, long lookedUp,
					List<Lookup> alreadyRunning, Random random) {
				if (logMINOR) {
					Logger.minor(this, "Getting next editions from " + lookedUp);
				}
				if (lookedUp < 0) {
					lookedUp = 0;
				}
				for (int i = 1; i <= USKFetcher.this.origMinFailures; i++) {
					long ed = i + lookedUp;
					Lookup l = new Lookup();
					l.val = ed;
					boolean poll = USKFetcher.this.backgroundPoll;
					if (((!poll) && toFetch.contains(l)) || (poll && toPoll.contains(l))) {
						if (logDEBUG) {
							Logger.debug(this, "Ignoring " + l);
						}
						continue;
					}
					if (alreadyRunning.remove(l)) {
						if (logDEBUG) {
							Logger.debug(this, "Ignoring (2): " + l);
						}
						continue;
					}
					ClientSSK key;
					// FIXME reuse ehDocnames somehow
					// The problem is we need a ClientSSK for the high level stuff.
					key = USKFetcher.this.origUSK.getSSK(ed);
					l.key = key;
					l.ignoreStore = true;
					if (poll) {
						if (!toPoll.contains(l)) {
							toPoll.add(l);
						}
						else {
							if (logDEBUG) {
								Logger.debug(this, "Ignoring poll (3): " + l);
							}
						}
					}
					else {
						if (!toFetch.contains(l)) {
							toFetch.add(l);
						}
						else {
							if (logDEBUG) {
								Logger.debug(this, "Ignoring fetch (3): " + l);
							}
						}
					}
				}
			}

			synchronized void getRandomEditions(List<Lookup> toFetch, long lookedUp, List<Lookup> alreadyRunning,
					Random random, int allowed) {
				// Then add a couple of random editions for catch-up.
				long baseEdition = lookedUp + USKFetcher.this.origMinFailures;
				for (int i = 0; i < allowed; i++) {
					while (true) {
						// Geometric distribution.
						// 20% chance of mean 100, 80% chance of mean 10. Thanks evanbd.
						int mean = (random.nextInt(5) != 0) ? 10 : 100;
						long fetch = baseEdition
								+ (long) Math.floor(Math.log(random.nextFloat()) / Math.log(1.0 - 1.0 / mean));
						if (fetch < baseEdition) {
							continue;
						}
						Lookup l = new Lookup();
						l.val = fetch;
						if (toFetch.contains(l)) {
							continue;
						}
						if (alreadyRunning.contains(l)) {
							continue;
						}
						l.key = USKFetcher.this.origUSK.getSSK(fetch);
						l.ignoreStore = !(fetch - lookedUp >= WATCH_KEYS);
						toFetch.add(l);
						if (logMINOR) {
							Logger.minor(this, "Trying random future edition " + fetch + " for "
									+ USKFetcher.this.origUSK + " current edition " + lookedUp);
						}
						break;
					}
				}
			}

			/**
			 * Check for WATCH_KEYS from lastSlot, but do not check any slots earlier than
			 * checkedDatastoreUpTo. Re-use the cache if possible, and extend it if
			 * necessary; all we need to construct a NodeSSK is the base data and the
			 * E(H(docname)), and we have that.
			 */
			synchronized StoreSubChecker checkStore(long lastSlot) {
				if (logDEBUG) {
					Logger.minor(this, "check store from " + lastSlot + " current first slot " + this.firstSlot);
				}
				long checkFrom = lastSlot;
				long checkTo = lastSlot + WATCH_KEYS;
				if (this.checkedDatastoreTo >= checkFrom) {
					checkFrom = this.checkedDatastoreTo;
				}
				if (checkFrom >= checkTo) {
					return null; // Nothing to check.
				}
				// Update the cache.
				RemoveRangeArrayList<byte[]> ehDocnames = this.updateCache(lastSlot);
				// Now create NodeSSK[] from the part of the cache that
				// ehDocnames[0] is firstSlot
				// ehDocnames[checkFrom-firstSlot] is checkFrom
				int offset = (int) (checkFrom - this.firstSlot);
				NodeSSK[] keysToCheck = new NodeSSK[WATCH_KEYS - offset];
				for (int x = 0, i = offset; i < WATCH_KEYS; i++, x++) {
					keysToCheck[x] = new NodeSSK(USKWatchingKeys.this.pubKeyHash, ehDocnames.get(i),
							USKWatchingKeys.this.cryptoAlgorithm);
				}
				return new StoreSubChecker(keysToCheck, checkFrom, checkTo);
			}

			synchronized RemoveRangeArrayList<byte[]> updateCache(long curBaseEdition) {
				if (logMINOR) {
					Logger.minor(this, "update cache from " + curBaseEdition + " current first slot " + this.firstSlot);
				}
				RemoveRangeArrayList<byte[]> ehDocnames = this.cache.get();
				if (this.cache == null || ehDocnames == null) {
					ehDocnames = new RemoveRangeArrayList<>(WATCH_KEYS);
					this.cache = new WeakReference<>(ehDocnames);
					this.firstSlot = curBaseEdition;
					if (logMINOR) {
						Logger.minor(this, "Regenerating because lost cached keys");
					}
					this.generate(this.firstSlot, WATCH_KEYS, ehDocnames);
					return ehDocnames;
				}
				this.match(null, curBaseEdition, ehDocnames);
				return ehDocnames;
			}

			/**
			 * Update the key list if necessary based on the new base edition. Then try to
			 * match the given key. If it matches return the edition number.
			 * @param key The key we are trying to match. If null, just update the cache,
			 * do not do any matching (used by checkStore(); it is only necessary to
			 * update the cache if you are actually going to use it).
			 * @param curBaseEdition The new base edition.
			 * @return The edition number for the key, or -1 if the key is not a match.
			 */
			synchronized long match(NodeSSK key, long curBaseEdition) {
				if (logDEBUG) {
					Logger.minor(this, "match from " + curBaseEdition + " current first slot " + this.firstSlot);
				}
				RemoveRangeArrayList<byte[]> ehDocnames = this.cache.get();
				if (this.cache == null || ehDocnames == null) {
					ehDocnames = new RemoveRangeArrayList<>(WATCH_KEYS);
					this.cache = new WeakReference<>(ehDocnames);
					this.firstSlot = curBaseEdition;
					this.generate(this.firstSlot, WATCH_KEYS, ehDocnames);
					return (key != null) ? this.innerMatch(key, ehDocnames, 0, ehDocnames.size(), this.firstSlot) : -1;
				}
				// Might as well check first.
				long x = this.innerMatch(key, ehDocnames, 0, ehDocnames.size(), this.firstSlot);
				if (x != -1) {
					return x;
				}
				return this.match(key, curBaseEdition, ehDocnames);
			}

			/**
			 * Update ehDocnames as needed according to the new curBaseEdition, then
			 * innerMatch against *only the changed parts*. The caller must already have
			 * done innerMatch over the passed in ehDocnames.
			 * @param curBaseEdition The edition to check from. If this is different to
			 * firstSlot, we will update ehDocnames.
			 */
			private long match(NodeSSK key, long curBaseEdition, RemoveRangeArrayList<byte[]> ehDocnames) {
				if (logMINOR) {
					Logger.minor(this, "Matching " + key + " cur base edition " + curBaseEdition + " first slot was "
							+ this.firstSlot + " for " + USKFetcher.this.origUSK + " on " + this);
				}
				if (this.firstSlot < curBaseEdition) {
					if (this.firstSlot + ehDocnames.size() <= curBaseEdition) {
						// No overlap. Clear it and start again.
						ehDocnames.clear();
						this.firstSlot = curBaseEdition;
						this.generate(curBaseEdition, WATCH_KEYS, ehDocnames);
						return (key != null) ? this.innerMatch(key, ehDocnames, 0, ehDocnames.size(), this.firstSlot)
								: -1;
					}
					else {
						// There is some overlap. Delete the first part of the array then
						// add stuff at the end.
						// ehDocnames[i] is slot firstSlot + i
						// We want to get rid of anything before curBaseEdition
						// So the first slot that is useful is the slot at i =
						// curBaseEdition - firstSlot
						// Which is the new [0], whose edition is curBaseEdition
						ehDocnames.removeRange(0, (int) (curBaseEdition - this.firstSlot));
						int size = ehDocnames.size();
						this.firstSlot = curBaseEdition;
						this.generate(curBaseEdition + size, WATCH_KEYS - size, ehDocnames);
						return (key != null) ? this.innerMatch(key, ehDocnames, WATCH_KEYS - size, size, this.firstSlot)
								: -1;
					}
				}
				else if (this.firstSlot > curBaseEdition) {
					// Normal due to race conditions. We don't always report the new
					// edition to the USKManager immediately.
					// So ignore it.
					if (logMINOR) {
						Logger.minor(this,
								"Ignoring regression in match() from " + curBaseEdition + " to " + this.firstSlot);
					}
					return (key != null) ? this.innerMatch(key, ehDocnames, 0, ehDocnames.size(), this.firstSlot) : -1;
				}
				return -1;
			}

			/**
			 * Do the actual match, using the current firstSlot, and a specified offset
			 * and length within the array.
			 */
			private long innerMatch(NodeSSK key, RemoveRangeArrayList<byte[]> ehDocnames, int offset, int size,
					long firstSlot) {
				byte[] data = key.getKeyBytes();
				for (int i = offset; i < (offset + size); i++) {
					if (Arrays.equals(data, ehDocnames.get(i))) {
						if (logMINOR) {
							Logger.minor(this, "Found edition " + (firstSlot + i) + " for " + USKFetcher.this.origUSK);
						}
						return firstSlot + i;
					}
				}
				return -1;
			}

			/**
			 * Append a series of E(H(docname))'s to the array.
			 * @param baseEdition The edition to start from.
			 * @param keys The number of keys to add.
			 */
			private void generate(long baseEdition, int keys, RemoveRangeArrayList<byte[]> ehDocnames) {
				if (logMINOR) {
					Logger.minor(this, "generate() from " + baseEdition + " for " + USKFetcher.this.origUSK);
				}
				assert (baseEdition >= 0);
				for (int i = 0; i < keys; i++) {
					long ed = baseEdition + i;
					ehDocnames.add(USKFetcher.this.origUSK.getSSK(ed).ehDocname);
				}
			}

			public final class StoreSubChecker {

				/** Keys to check */
				final NodeSSK[] keysToCheck;

				/**
				 * The edition from which we will have checked after we have executed
				 * this.
				 */
				private final long checkedFrom;

				/**
				 * The edition up to which we have checked after we have executed this.
				 */
				private final long checkedTo;

				private StoreSubChecker(NodeSSK[] keysToCheck, long checkFrom, long checkTo) {
					this.keysToCheck = keysToCheck;
					this.checkedFrom = checkFrom;
					this.checkedTo = checkTo;
					if (logMINOR) {
						Logger.minor(this, "Checking datastore from " + checkFrom + " to " + checkTo + " for "
								+ USKFetcher.this + " on " + this);
					}
				}

				/** The keys have been checked. */
				void checked() {
					synchronized (KeyList.this) {
						if (KeyList.this.checkedDatastoreTo >= this.checkedFrom
								&& KeyList.this.checkedDatastoreFrom <= this.checkedFrom) {
							// checkedFrom is unchanged
							KeyList.this.checkedDatastoreTo = this.checkedTo;
						}
						else {
							KeyList.this.checkedDatastoreFrom = this.checkedFrom;
							KeyList.this.checkedDatastoreTo = this.checkedTo;
						}
						if (logMINOR) {
							Logger.minor(this,
									"Checked from " + this.checkedFrom + " to " + this.checkedTo + " (now overall is "
											+ KeyList.this.checkedDatastoreFrom + " to "
											+ KeyList.this.checkedDatastoreTo + ") for " + USKFetcher.this + " for "
											+ USKFetcher.this.origUSK);
						}
					}

				}

			}

		}

	}

	public class Lookup {

		long val;

		ClientSSK key;

		boolean ignoreStore;

		@Override
		public boolean equals(Object o) {
			if (o instanceof Lookup) {
				return ((Lookup) o).val == this.val;
			}
			else {
				return false;
			}
		}

		@Override
		public int hashCode() {
			return (int) (this.val ^ (this.val >>> 32));
		}

		@Override
		public String toString() {
			return USKFetcher.this.origUSK + ":" + this.val;
		}

	}

}
