/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
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
 * Object passed in to client-layer operations, containing references to essential but mostly transient 
 * objects such as the schedulers and the FEC queue.
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
	public transient final Executor mainExecutor;
	/** We need to be able to suspend execution of jobs changing persistent state in order to write
	 * it to disk consistently. Also, some jobs may want to request immediate serialization. */
	public transient final PersistentJobRunner jobRunner;
	public transient final RandomSource random;
	public transient final ArchiveManager archiveManager;
	public transient final PersistentTempBucketFactory persistentBucketFactory;
	public transient PersistentFileTracker persistentFileTracker;
	public transient final TempBucketFactory tempBucketFactory;
	public transient final LockableRandomAccessBufferFactory tempRAFFactory;
	public transient final LockableRandomAccessBufferFactory persistentRAFFactory;
	public transient final HealingQueue healingQueue;
	public transient final USKManager uskManager;
	public transient final Random fastWeakRandom;
	public transient final long bootID;
	public transient final Ticker ticker;
	public transient final BucketFilenameGenerator fg;
	public transient final BucketFilenameGenerator persistentFG;
	public transient final RealCompressor rc;
	public transient final DatastoreChecker checker;
	public transient DownloadCache downloadCache;
	/** Used for memory intensive jobs such as in-RAM FEC decodes. Some of these jobs may do disk 
	 * I/O and we don't guarantee to serialise them. The new splitfile code does FEC decodes 
	 * entirely in memory, which saves a lot of seeks and improves robustness. */
	public transient final MemoryLimitedJobRunner memoryLimitedJobRunner;
	public transient final PersistentRequestChecker persistentRequestChecker;
	private transient FetchContext defaultPersistentFetchContext;
	private transient InsertContext defaultPersistentInsertContext;
	public transient final MasterSecret cryptoSecretTransient;
	private transient MasterSecret cryptoSecretPersistent;
	private transient FileRandomAccessBufferFactory fileRAFTransient;
	private transient FileRandomAccessBufferFactory fileRAFPersistent;

	/** Provider for link filter exceptions. */
	public transient final LinkFilterExceptionProvider linkFilterExceptionProvider;
	/** Transient version of the PersistentJobRunner, just starts stuff immediately. Helpful for
	 * avoiding having two different API's, e.g. in SplitFileFetcherStorage. */
    public PersistentJobRunner dummyJobRunner;

	private transient final Config config;
	public transient final int maxBackgroundUSKFetchers;

	public ClientContext(long bootID, ClientLayerPersister jobRunner, Executor mainExecutor,
						 ArchiveManager archiveManager, PersistentTempBucketFactory ptbf, TempBucketFactory tbf, PersistentFileTracker tracker,
						 HealingQueue hq, USKManager uskManager, RandomSource strongRandom, Random fastWeakRandom,
						 Ticker ticker, MemoryLimitedJobRunner memoryLimitedJobRunner, BucketFilenameGenerator fg, BucketFilenameGenerator persistentFG,
						 LockableRandomAccessBufferFactory rafFactory, LockableRandomAccessBufferFactory persistentRAFFactory,
						 FileRandomAccessBufferFactory fileRAFTransient, FileRandomAccessBufferFactory fileRAFPersistent,
						 RealCompressor rc, DatastoreChecker checker, PersistentRequestChecker persistentRequestChecker, MasterSecret cryptoSecretTransient,
						 LinkFilterExceptionProvider linkFilterExceptionProvider, FetchContext defaultPersistentFetchContext,
						 InsertContext defaultPersistentInsertContext, Config config, int maxBackgroundUSKFetchers) {
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
	    return cryptoSecretPersistent;
	}

	public ClientRequestScheduler getSskFetchScheduler(boolean realTime) {
		return realTime ? sskFetchSchedulerRT : sskFetchSchedulerBulk;
	}
	
	public ClientRequestScheduler getChkFetchScheduler(boolean realTime) {
		return realTime ? chkFetchSchedulerRT : chkFetchSchedulerBulk;
	}
	
	public ClientRequestScheduler getSskInsertScheduler(boolean realTime) {
		return realTime ? sskInsertSchedulerRT : sskInsertSchedulerBulk;
	}
	
	public ClientRequestScheduler getChkInsertScheduler(boolean realTime) {
		return realTime ? chkInsertSchedulerRT : chkInsertSchedulerBulk;
	}
	
	/** 
	 * Start an insert. Queue a database job if it is a persistent insert, otherwise start it right now.
	 * @param inserter The insert to start.
	 * @throws InsertException If the insert is transient and it fails to start.
	 * @throws PersistenceDisabledException If the insert is persistent and the database is disabled (e.g.
	 * because it is encrypted and the user hasn't entered the password yet).
	 */
	public void start(final ClientPutter inserter) throws InsertException, PersistenceDisabledException {
		if(inserter.persistent()) {
			jobRunner.queue(new PersistentJob() {
				
				@Override
				public boolean run(ClientContext context) {
					try {
						inserter.start(false, context);
					} catch (InsertException e) {
						inserter.client.onFailure(e, inserter);
					}
					return true;
				}
				
			}, NativeThread.NORM_PRIORITY);
		} else {
			inserter.start(false, this);
		}
	}

	/**
	 * Start a request. Schedule a job on the database thread if it is persistent, otherwise start it 
	 * immediately.
	 * @param getter The request to start.
	 * @throws FetchException If the request is transient and failed to start.
	 * @throws PersistenceDisabledException If the request is persistent and the database is disabled.
	 */
	public void start(final ClientGetter getter) throws FetchException, PersistenceDisabledException {
		if(getter.persistent()) {
			jobRunner.queue(new PersistentJob() {
				
				@Override
				public boolean run(ClientContext context) {
					try {
						getter.start(context);
					} catch (FetchException e) {
						getter.clientCallback.onFailure(e, getter);
					}
					return true;
				}
				
			}, NativeThread.NORM_PRIORITY);
		} else {
			getter.start(this);
		}
	}

	/**
	 * Start a new-style site insert. Schedule a job on the database thread if it is persistent, 
	 * otherwise start it immediately.
	 * @param inserter The request to start.
	 * @throws InsertException If the insert is transient and failed to start.
	 * @throws PersistenceDisabledException If the insert is persistent and the database is disabled.
	 */
	public void start(final BaseManifestPutter inserter) throws InsertException, PersistenceDisabledException {
		if(inserter.persistent()) {
			jobRunner.queue(new PersistentJob() {
				
				@Override
				public boolean run(ClientContext context) {
					try {
						inserter.start(context);
					} catch (InsertException e) {
						inserter.cb.onFailure(e, inserter);
					}
					return true;
				}
				
			}, NativeThread.NORM_PRIORITY);
		} else {
			inserter.start(this);
		}
	}

	/**
	 * Get the temporary bucket factory appropriate for a request.
	 * @param persistent If true, get the persistent temporary bucket factory. This creates buckets which 
	 * persist across restarts of the node. If false, get the temporary bucket factory, which creates buckets
	 * which will be deleted once the node is restarted.
	 */
	public BucketFactory getBucketFactory(boolean persistent) {
		if(persistent)
			return persistentBucketFactory;
		else
			return tempBucketFactory;
	}

	/**
	 * Get the RequestScheduler responsible for the given key type. This is used to queue low level requests.
	 * @param ssk If true, get the SSK request scheduler. If false, get the CHK request scheduler.
	 */
	public RequestScheduler getFetchScheduler(boolean ssk, boolean realTime) {
		if(ssk) return realTime ? sskFetchSchedulerRT : sskFetchSchedulerBulk;
		return realTime ? chkFetchSchedulerRT : chkFetchSchedulerBulk;
	}
	
	public void postUserAlert(final UserAlert alert) {
		if(alertRegister == null) {
			// Wait until after startup
			ticker.queueTimedJob(new Runnable() {

				@Override
				public void run() {
					alertRegister.register(alert);
				}
				
			}, "Post alert", 0L, false, false);
		} else {
			alertRegister.register(alert);
		}
	}

	public void setDownloadCache(DownloadCache cache) {
		this.downloadCache = cache;
	}

    public FetchContext getDefaultPersistentFetchContext() {
        return new FetchContext(defaultPersistentFetchContext, FetchContext.IDENTICAL_MASK);
    }
    
    public InsertContext getDefaultPersistentInsertContext() {
        return new InsertContext(defaultPersistentInsertContext, new SimpleEventProducer());
    }
    
    public PersistentJobRunner getJobRunner(boolean persistent) {
        return persistent ? jobRunner : dummyJobRunner;
    }

    public FileRandomAccessBufferFactory getFileRandomAccessBufferFactory(boolean persistent) {
        return persistent ? fileRAFPersistent : fileRAFTransient;
                 
    }

    public LockableRandomAccessBufferFactory getRandomAccessBufferFactory(boolean persistent) {
        return persistent ? persistentRAFFactory : tempBucketFactory;
    }

	public Config getConfig() {
		return config;
	}
}
