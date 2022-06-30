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

import java.util.Random;

import freenet.bucket.BucketFactory;
import freenet.bucket.BucketFilenameGenerator;
import freenet.bucket.PersistentTempBucketFactory;
import freenet.bucket.TempBucketFactory;
import freenet.client.ArchiveManager;
import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.InsertContext;
import freenet.client.InsertException;
import freenet.client.events.SimpleEventProducer;
import freenet.client.filter.LinkFilterExceptionProvider;
import freenet.client.request.RequestScheduler;
import freenet.compress.RealCompressor;
import freenet.config.Config;
import freenet.crypt.MasterSecret;
import freenet.crypt.RandomSource;
import freenet.lockablebuffer.FileRandomAccessBufferFactory;
import freenet.lockablebuffer.LockableRandomAccessBufferFactory;
import freenet.support.Executor;
import freenet.support.MemoryLimitedJobRunner;
import freenet.support.Ticker;
import freenet.support.io.NativeThread;
import freenet.support.io.PersistentFileTracker;
import freenet.support.node.UserAlert;

/**
 * Object passed in to client-layer operations, containing references to essential but
 * mostly transient objects such as the schedulers and the FEC queue.
 *
 * @author toad
 */
public class ClientContext {

	private transient ClientRequestScheduler sskFetchSchedulerBulk;

	private transient ClientRequestScheduler chkFetchSchedulerBulk;

	private transient ClientRequestScheduler sskInsertSchedulerBulk;

	private transient ClientRequestScheduler chkInsertSchedulerBulk;

	private transient ClientRequestScheduler sskFetchSchedulerRT;

	private transient ClientRequestScheduler chkFetchSchedulerRT;

	private transient ClientRequestScheduler sskInsertSchedulerRT;

	private transient ClientRequestScheduler chkInsertSchedulerRT;

	private transient UserAlertRegister alertRegister;

	/** The main Executor for the node. Jobs for transient requests run here. */
	public final transient Executor mainExecutor;

	/**
	 * We need to be able to suspend execution of jobs changing persistent state in order
	 * to write it to disk consistently. Also, some jobs may want to request immediate
	 * serialization.
	 */
	public final transient PersistentJobRunner jobRunner;

	public final transient RandomSource random;

	public final transient ArchiveManager archiveManager;

	public final transient PersistentTempBucketFactory persistentBucketFactory;

	public transient PersistentFileTracker persistentFileTracker;

	public final transient TempBucketFactory tempBucketFactory;

	public final transient LockableRandomAccessBufferFactory tempRAFFactory;

	public final transient LockableRandomAccessBufferFactory persistentRAFFactory;

	public final transient HealingQueue healingQueue;

	public final transient USKManager uskManager;

	public final transient Random fastWeakRandom;

	public final transient long bootID;

	public final transient Ticker ticker;

	public final transient BucketFilenameGenerator fg;

	public final transient BucketFilenameGenerator persistentFG;

	public final transient RealCompressor rc;

	public final transient DatastoreChecker checker;

	public transient DownloadCache downloadCache;

	/**
	 * Used for memory intensive jobs such as in-RAM FEC decodes. Some of these jobs may
	 * do disk I/O and we don't guarantee to serialise them. The new splitfile code does
	 * FEC decodes entirely in memory, which saves a lot of seeks and improves robustness.
	 */
	public final transient MemoryLimitedJobRunner memoryLimitedJobRunner;

	public final transient PersistentRequestChecker persistentRequestChecker;

	private final transient FetchContext defaultPersistentFetchContext;

	private final transient InsertContext defaultPersistentInsertContext;

	public final transient MasterSecret cryptoSecretTransient;

	private transient MasterSecret cryptoSecretPersistent;

	private final transient FileRandomAccessBufferFactory fileRAFTransient;

	private final transient FileRandomAccessBufferFactory fileRAFPersistent;

	/** Provider for link filter exceptions. */
	public final transient LinkFilterExceptionProvider linkFilterExceptionProvider;

	/**
	 * Transient version of the PersistentJobRunner, just starts stuff immediately.
	 * Helpful for avoiding having two different API's, e.g. in SplitFileFetcherStorage.
	 */
	public PersistentJobRunner dummyJobRunner;

	private final transient Config config;

	public final transient int maxBackgroundUSKFetchers;

	public ClientContext(long bootID, ClientLayerPersister jobRunner, Executor mainExecutor,
			ArchiveManager archiveManager, PersistentTempBucketFactory ptbf, TempBucketFactory tbf,
			PersistentFileTracker tracker, HealingQueue hq, USKManager uskManager, RandomSource strongRandom,
			Random fastWeakRandom, Ticker ticker, MemoryLimitedJobRunner memoryLimitedJobRunner,
			BucketFilenameGenerator fg, BucketFilenameGenerator persistentFG,
			LockableRandomAccessBufferFactory rafFactory, LockableRandomAccessBufferFactory persistentRAFFactory,
			FileRandomAccessBufferFactory fileRAFTransient, FileRandomAccessBufferFactory fileRAFPersistent,
			RealCompressor rc, DatastoreChecker checker, PersistentRequestChecker persistentRequestChecker,
			MasterSecret cryptoSecretTransient, LinkFilterExceptionProvider linkFilterExceptionProvider,
			FetchContext defaultPersistentFetchContext, InsertContext defaultPersistentInsertContext, Config config,
			int maxBackgroundUSKFetchers) {
		this.bootID = bootID;
		this.jobRunner = jobRunner;
		this.mainExecutor = mainExecutor;
		this.random = strongRandom;
		this.archiveManager = archiveManager;
		this.persistentBucketFactory = ptbf;
		this.persistentFileTracker = ptbf;
		this.tempBucketFactory = tbf;
		this.healingQueue = hq;
		this.uskManager = uskManager;
		this.fastWeakRandom = fastWeakRandom;
		this.ticker = ticker;
		this.fg = fg;
		this.persistentFG = persistentFG;
		this.persistentRAFFactory = persistentRAFFactory;
		this.fileRAFPersistent = fileRAFPersistent;
		this.fileRAFTransient = fileRAFTransient;
		this.rc = rc;
		this.checker = checker;
		this.linkFilterExceptionProvider = linkFilterExceptionProvider;
		this.memoryLimitedJobRunner = memoryLimitedJobRunner;
		this.tempRAFFactory = rafFactory;
		this.persistentRequestChecker = persistentRequestChecker;
		this.dummyJobRunner = new DummyJobRunner(mainExecutor, this);
		this.defaultPersistentFetchContext = defaultPersistentFetchContext;
		this.defaultPersistentInsertContext = defaultPersistentInsertContext;
		this.cryptoSecretTransient = cryptoSecretTransient;
		this.config = config;
		this.maxBackgroundUSKFetchers = maxBackgroundUSKFetchers;
	}

	public void init(RequestStarterSchedulerGroup starters, UserAlertRegister alertRegister) {
		this.sskFetchSchedulerBulk = starters.getSskFetchSchedulerBulk();
		this.chkFetchSchedulerBulk = starters.getChkFetchSchedulerBulk();
		this.sskInsertSchedulerBulk = starters.getSskPutSchedulerBulk();
		this.chkInsertSchedulerBulk = starters.getChkPutSchedulerBulk();
		this.sskFetchSchedulerRT = starters.getSskFetchSchedulerRT();
		this.chkFetchSchedulerRT = starters.getChkFetchSchedulerRT();
		this.sskInsertSchedulerRT = starters.getSskPutSchedulerRT();
		this.chkInsertSchedulerRT = starters.getChkPutSchedulerRT();
		this.alertRegister = alertRegister;
	}

	public synchronized void setPersistentMasterSecret(MasterSecret secret) {
		this.cryptoSecretPersistent = secret;
	}

	public synchronized MasterSecret getPersistentMasterSecret() {
		return this.cryptoSecretPersistent;
	}

	public ClientRequestScheduler getSskFetchScheduler(boolean realTime) {
		return realTime ? this.sskFetchSchedulerRT : this.sskFetchSchedulerBulk;
	}

	public ClientRequestScheduler getChkFetchScheduler(boolean realTime) {
		return realTime ? this.chkFetchSchedulerRT : this.chkFetchSchedulerBulk;
	}

	public ClientRequestScheduler getSskInsertScheduler(boolean realTime) {
		return realTime ? this.sskInsertSchedulerRT : this.sskInsertSchedulerBulk;
	}

	public ClientRequestScheduler getChkInsertScheduler(boolean realTime) {
		return realTime ? this.chkInsertSchedulerRT : this.chkInsertSchedulerBulk;
	}

	/**
	 * Start an insert. Queue a database job if it is a persistent insert, otherwise start
	 * it right now.
	 * @param inserter The insert to start.
	 * @throws InsertException If the insert is transient and it fails to start.
	 * @throws PersistenceDisabledException If the insert is persistent and the database
	 * is disabled (e.g. because it is encrypted and the user hasn't entered the password
	 * yet).
	 */
	public void start(final ClientPutter inserter) throws InsertException, PersistenceDisabledException {
		if (inserter.persistent()) {
			this.jobRunner.queue((context) -> {
				try {
					inserter.start(false, context);
				}
				catch (InsertException ex) {
					inserter.client.onFailure(ex, inserter);
				}
				return true;
			}, NativeThread.NORM_PRIORITY);
		}
		else {
			inserter.start(false, this);
		}
	}

	/**
	 * Start a request. Schedule a job on the database thread if it is persistent,
	 * otherwise start it immediately.
	 * @param getter The request to start.
	 * @throws FetchException If the request is transient and failed to start.
	 * @throws PersistenceDisabledException If the request is persistent and the database
	 * is disabled.
	 */
	public void start(final ClientGetter getter) throws FetchException, PersistenceDisabledException {
		if (getter.persistent()) {
			this.jobRunner.queue((context) -> {
				try {
					getter.start(context);
				}
				catch (FetchException ex) {
					assert getter.clientCallback != null;
					getter.clientCallback.onFailure(ex, getter);
				}
				return true;
			}, NativeThread.NORM_PRIORITY);
		}
		else {
			getter.start(this);
		}
	}

	/**
	 * Start a new-style site insert. Schedule a job on the database thread if it is
	 * persistent, otherwise start it immediately.
	 * @param inserter The request to start.
	 * @throws InsertException If the insert is transient and failed to start.
	 * @throws PersistenceDisabledException If the insert is persistent and the database
	 * is disabled.
	 */
	public void start(final BaseManifestPutter inserter) throws InsertException, PersistenceDisabledException {
		if (inserter.persistent()) {
			this.jobRunner.queue((context) -> {
				try {
					inserter.start(context);
				}
				catch (InsertException ex) {
					inserter.cb.onFailure(ex, inserter);
				}
				return true;
			}, NativeThread.NORM_PRIORITY);
		}
		else {
			inserter.start(this);
		}
	}

	/**
	 * Get the temporary bucket factory appropriate for a request.
	 * @param persistent If true, get the persistent temporary bucket factory. This
	 * creates buckets which persist across restarts of the node. If false, get the
	 * temporary bucket factory, which creates buckets which will be deleted once the node
	 * is restarted.
	 */
	public BucketFactory getBucketFactory(boolean persistent) {
		if (persistent) {
			return this.persistentBucketFactory;
		}
		else {
			return this.tempBucketFactory;
		}
	}

	/**
	 * Get the RequestScheduler responsible for the given key type. This is used to queue
	 * low level requests.
	 * @param ssk If true, get the SSK request scheduler. If false, get the CHK request
	 * scheduler.
	 */
	public RequestScheduler getFetchScheduler(boolean ssk, boolean realTime) {
		if (ssk) {
			return realTime ? this.sskFetchSchedulerRT : this.sskFetchSchedulerBulk;
		}
		return realTime ? this.chkFetchSchedulerRT : this.chkFetchSchedulerBulk;
	}

	public void postUserAlert(final UserAlert alert) {
		if (this.alertRegister == null) {
			// Wait until after startup
			this.ticker.queueTimedJob(() -> ClientContext.this.alertRegister.register(alert), "Post alert", 0L, false,
					false);
		}
		else {
			this.alertRegister.register(alert);
		}
	}

	public void setDownloadCache(DownloadCache cache) {
		this.downloadCache = cache;
	}

	public FetchContext getDefaultPersistentFetchContext() {
		return new FetchContext(this.defaultPersistentFetchContext, FetchContext.IDENTICAL_MASK);
	}

	public InsertContext getDefaultPersistentInsertContext() {
		return new InsertContext(this.defaultPersistentInsertContext, new SimpleEventProducer());
	}

	public PersistentJobRunner getJobRunner(boolean persistent) {
		return persistent ? this.jobRunner : this.dummyJobRunner;
	}

	public FileRandomAccessBufferFactory getFileRandomAccessBufferFactory(boolean persistent) {
		return persistent ? this.fileRAFPersistent : this.fileRAFTransient;

	}

	public LockableRandomAccessBufferFactory getRandomAccessBufferFactory(boolean persistent) {
		return persistent ? this.persistentRAFFactory : this.tempBucketFactory;
	}

	public Config getConfig() {
		return this.config;
	}

}
