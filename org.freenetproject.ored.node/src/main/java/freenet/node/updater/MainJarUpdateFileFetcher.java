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
import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Properties;

import freenet.bucket.FileBucket;
import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.FetchException.FetchExceptionMode;
import freenet.client.FetchResult;
import freenet.client.async.ClientContext;
import freenet.client.async.ClientGetCallback;
import freenet.client.async.ClientGetter;
import freenet.client.events.ClientEvent;
import freenet.client.events.ClientEventListener;
import freenet.client.events.SplitfileProgressEvent;
import freenet.client.request.PriorityClasses;
import freenet.client.request.RequestClient;
import freenet.clients.fcp.ClientPut.COMPRESS_STATE;
import freenet.clients.fcp.FCPMessage;
import freenet.clients.fcp.FCPUserAlert;
import freenet.clients.http.QueueToadlet;
import freenet.keys.FreenetURI;
import freenet.l10n.NodeL10n;
import freenet.node.Version;
import freenet.node.updater.UpdateOverMandatoryManager.UOMDependencyFetcher;
import freenet.nodelogger.Logger;
import freenet.support.HTMLNode;
import freenet.support.io.Closer;
import freenet.support.io.FileUtil;
import freenet.support.io.InsufficientDiskSpaceException;

public class MainJarUpdateFileFetcher extends AbstractJarUpdateFileFetcher
		implements MainJarDependenciesChecker.Deployer {

	private static volatile boolean logMINOR;

	static {
		Logger.registerClass(MainJarUpdateFileFetcher.class);
	}

	public static final long MAX_MAIN_JAR_LENGTH = 48 * 1024 * 1024; // 48MiB

	private final FetchContext dependencyCtx;

	private final ClientContext clientContext;

	private MainJarDependenciesChecker.MainJarDependencies latestMainJarDependencies;

	MainJarUpdateFileFetcher(NodeUpdateManager manager, FreenetURI URI, int current, int min, int max,
			String blobFilenamePrefix) {
		super(manager, URI, current, min, max, blobFilenamePrefix);
		this.dependencyCtx = this.core.makeClient((short) 0, true, false).getFetchContext();
		this.dependencyCtx.allowSplitfiles = true;
		this.dependencyCtx.dontEnterImplicitArchives = false;
		this.dependencyCtx.maxNonSplitfileRetries = -1;
		this.dependencyCtx.maxSplitfileBlockRetries = -1;
		this.clientContext = this.core.clientContext;
		this.dependencies = new MainJarDependenciesChecker(this, manager.node.executor);
	}

	private final MainJarDependenciesChecker dependencies;

	@Override
	public String fileName() {
		return "freenet.jar";
	}

	public void start() {
		// this.maybeProcessOldBlob();
		super.start();
	}

	@Override
	protected void maybeParseManifest(FetchResult result, int build) {
		// Do nothing.
	}

	@Override
	protected void processSuccess(int fetched, FetchResult result, File blob) {
		super.processSuccess(fetched, result, blob);

		// this.manager.onDownloadedNewJar(result.asBucket(), fetched, blob);
		// NodeUpdateManager expects us to dependencies *AFTER* we tell it about the new
		// jar.
		this.parseDependencies(result, fetched);
	}

	@Override
	protected void onStartFetching() {
		// this.manager.onStartFetching();
	}

	// Dependency handling.

	private final HashSet<DependencyJarFetcher> fetchers = new HashSet<>();

	private final HashSet<DependencyJarFetcher> essentialFetchers = new HashSet<>();

	protected void parseDependencies(Properties props, int build) {
		synchronized (this.fetchers) {
			this.fetchers.clear();
		}
		MainJarDependenciesChecker.MainJarDependencies deps = this.dependencies.handle(props, build);
		if (deps != null) {
			// this.manager.onDependenciesReady(deps);
		}
	}

	@Override
	public void deploy(MainJarDependenciesChecker.MainJarDependencies deps) {
		// this.manager.onDependenciesReady(deps);
	}

	@Override
	public MainJarDependenciesChecker.JarFetcher fetch(FreenetURI uri, File downloadTo, long expectedLength,
			byte[] expectedHash, MainJarDependenciesChecker.JarFetcherCallback cb, int build, boolean essential,
			boolean executable) throws FetchException {
		if (essential) {
			System.out.println("Fetching " + downloadTo + " needed for new Freenet update " + build);
		}
		else if (build != 0) {
			// build 0 means it's a preload or a multi-file update.
			System.out.println("Preloading " + downloadTo + " needed for new Freenet update " + build);
		}
		if (logMINOR) {
			Logger.minor(this, "Fetching " + uri + " to " + downloadTo + " for next update");
		}
		DependencyJarFetcher fetcher = new DependencyJarFetcher(downloadTo, uri, expectedLength, expectedHash, cb,
				essential, executable);
		synchronized (this.fetchers) {
			this.fetchers.add(fetcher);
			if (essential) {
				this.essentialFetchers.add(fetcher);
			}
		}
		fetcher.start();
		if (this.manager.uom.fetchingUOM()) {
			if (essential) {
				fetcher.fetchFromUOM();
			}
		}
		return fetcher;
	}

	public void onStartFetchingUOM() {
		DependencyJarFetcher[] f;
		synchronized (this.fetchers) {
			f = this.fetchers.toArray(new DependencyJarFetcher[0]);
		}
		for (DependencyJarFetcher fetcher : f) {
			fetcher.fetchFromUOM();
		}
	}

	public void renderProperties(HTMLNode alertNode) {
		synchronized (this.fetchers) {
			if (!this.fetchers.isEmpty()) {
				alertNode.addChild("p", this.l10n("fetchingDependencies") + ":");
				HTMLNode table = alertNode.addChild("table");
				for (DependencyJarFetcher f : this.fetchers) {
					table.addChild(f.renderRow());
				}
			}
		}
	}

	private String l10n(String key) {
		return NodeL10n.getBase().getString("MainJarUpdater." + key);
	}

	public boolean brokenDependencies() {
		return this.dependencies.isBroken();
	}

	public void cleanup() {
		InputStream is = this.getClass().getResourceAsStream("/" + DEPENDENCIES_FILE);
		if (is == null) {
			System.err.println(
					"Can't find dependencies file. Other nodes will not be able to use Update Over Mandatory through this one.");
			return;
		}
		Properties props = new Properties();
		try {
			props.load(is);
		}
		catch (IOException ex) {
			System.err.println(
					"Can't read dependencies file. Other nodes will not be able to use Update Over Mandatory through this one.");
			return;
		}
		finally {
			Closer.close(is);
		}
		this.dependencies.cleanup(props, this, Version.buildNumber());
	}

	@Override
	public void addDependency(byte[] expectedHash, File filename) {
		this.manager.uom.addDependency(expectedHash, filename);
	}

	@Override
	public void reannounce() {
		this.manager.broadcastUOMAnnounceManifest();
	}

	@Override
	public void multiFileReplaceReadyToDeploy(final MainJarDependenciesChecker.AtomicDeployer atomicDeployer) {
		if (this.manager.isAutoUpdateAllowed()) {
			atomicDeployer.deployMultiFileUpdateOffThread();
		}
		else {
			final long now = System.currentTimeMillis();
			System.err.println("Not deploying multi-file update for " + atomicDeployer.name
					+ " because auto-update is not enabled.");
			this.node.clientCore.alerts.register(new FCPUserAlert() {

				private String l10n(String key) {
					return NodeL10n.getBase().getString("MainJarUpdater.ConfirmMultiFileUpdater." + key);
				}

				@Override
				public boolean userCanDismiss() {
					return true;
				}

				@Override
				public String getTitle() {
					return this.l10n("title." + atomicDeployer.name);
				}

				@Override
				public String getText() {
					return this.l10n("text." + atomicDeployer.name);
				}

				@Override
				public HTMLNode getHTMLText() {
					return new HTMLNode("p", this.getText());
					// FIXME separate button, then the alert could be dismissable? Only
					// useful if it's permanently dismissable though, which means a config
					// setting as well...
				}

				@Override
				public String getShortText() {
					return this.getTitle();
				}

				@Override
				public short getPriorityClass() {
					return FCPUserAlert.ERROR;
				}

				@Override
				public boolean isValid() {
					return true;
				}

				@Override
				public void isValid(boolean validity) {
					// Ignore
				}

				@Override
				public String dismissButtonText() {
					return NodeL10n.getBase().getDefaultString("UpdatedVersionAvailableUserAlert.updateNowButton");
				}

				@Override
				public boolean shouldUnregisterOnDismiss() {
					return true;
				}

				@Override
				public void onDismiss() {
					atomicDeployer.deployMultiFileUpdateOffThread();
				}

				@Override
				public String anchor() {
					return "multi-file-update-confirm-" + atomicDeployer.name;
				}

				@Override
				public boolean isEventNotification() {
					return false;
				}

				@Override
				public FCPMessage getFCPMessage() {
					return null;
				}

				@Override
				public long getUpdatedTime() {
					return now;
				}

			});
		}
	}

	/** Glue code. */
	private class DependencyJarFetcher
			implements MainJarDependenciesChecker.JarFetcher, ClientGetCallback, RequestClient, ClientEventListener {

		private final File filename;

		private final ClientGetter getter;

		private SplitfileProgressEvent lastProgress;

		private final MainJarDependenciesChecker.JarFetcherCallback cb;

		private boolean fetched;

		private final byte[] expectedHash;

		private final long expectedLength;

		private final boolean essential;

		private final File tempFile;

		private UOMDependencyFetcher uomFetcher;

		private final boolean executable;

		DependencyJarFetcher(File filename, FreenetURI chk, long expectedLength, byte[] expectedHash,
				MainJarDependenciesChecker.JarFetcherCallback cb, boolean essential, boolean executable)
				throws FetchException {
			FetchContext myCtx = new FetchContext(MainJarUpdateFileFetcher.this.dependencyCtx,
					FetchContext.IDENTICAL_MASK);
			File parent = filename.getParentFile();
			if (parent == null) {
				parent = new File(".");
			}
			try {
				this.tempFile = File.createTempFile(filename.getName(), NodeUpdateManager.TEMP_FILE_SUFFIX, parent);
			}
			catch (InsufficientDiskSpaceException ex) {
				throw new FetchException(FetchExceptionMode.NOT_ENOUGH_DISK_SPACE);
			}
			catch (IOException ex) {
				throw new FetchException(FetchExceptionMode.BUCKET_ERROR, "Cannot create temp file for " + filename
						+ " in " + parent + " - disk full? permissions problem?");
			}
			this.getter = new ClientGetter(this, chk, myCtx, PriorityClasses.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
					new FileBucket(this.tempFile, false, false, false, false), null, null);
			myCtx.eventProducer.addEventListener(this);
			this.cb = cb;
			this.filename = filename;
			this.expectedHash = expectedHash;
			this.expectedLength = expectedLength;
			this.essential = essential;
			this.executable = executable;
		}

		@Override
		public void cancel() {
			final UOMDependencyFetcher f;
			synchronized (this) {
				this.fetched = true;
				f = this.uomFetcher;
			}
			MainJarUpdateFileFetcher.this.node.executor.execute(() -> {
				DependencyJarFetcher.this.getter.cancel(MainJarUpdateFileFetcher.this.clientContext);
				if (f != null) {
					f.cancel();
				}
			});
		}

		@Override
		public boolean persistent() {
			return false;
		}

		@Override
		public boolean realTimeFlag() {
			return false;
		}

		@SuppressWarnings("ResultOfMethodCallIgnored")
		@Override
		public void onSuccess(FetchResult result, ClientGetter state) {
			synchronized (this) {
				if (this.fetched) {
					this.tempFile.delete();
					return;
				}
				this.fetched = true;
			}
			if (!MainJarDependenciesChecker.validFile(this.tempFile, this.expectedHash, this.expectedLength,
					this.executable)) {
				Logger.error(this,
						"Unable to download dependency " + this.filename + " : not the expected size or hash!");
				System.err.println("Download of " + this.filename
						+ " for update failed because temp file appears to be corrupted!");
				if (this.cb != null) {
					this.cb.onFailure(new FetchException(FetchExceptionMode.BUCKET_ERROR,
							"Downloaded jar from Freenet but failed consistency check: " + this.tempFile + " length "
									+ this.tempFile.length() + " "));
				}
				this.tempFile.delete();
				return;
			}
			if (!FileUtil.renameTo(this.tempFile, this.filename)) {
				Logger.error(this, "Unable to rename temp file " + this.tempFile + " to " + this.filename);
				System.err.println("Download of " + this.filename + " for update failed because cannot rename from "
						+ this.tempFile);
				if (this.cb != null) {
					this.cb.onFailure(new FetchException(FetchExceptionMode.BUCKET_ERROR,
							"Unable to rename temp file " + this.tempFile + " to " + this.filename));
				}
				this.tempFile.delete();
				return;
			}
			if (this.cb != null) {
				this.cb.onSuccess();
			}
		}

		@Override
		public void onFailure(FetchException e, ClientGetter state) {
			// noinspection ResultOfMethodCallIgnored
			this.tempFile.delete();
			synchronized (this) {
				if (this.fetched) {
					return;
				}
			}
			if (this.cb != null) {
				this.cb.onFailure(e);
			}
		}

		@Override
		public synchronized void receive(ClientEvent ce, ClientContext context) {
			if (ce instanceof SplitfileProgressEvent) {
				this.lastProgress = (SplitfileProgressEvent) ce;
			}
		}

		private void start() throws FetchException {
			this.getter.start(MainJarUpdateFileFetcher.this.clientContext);
		}

		synchronized HTMLNode renderRow() {
			HTMLNode row = new HTMLNode("tr");
			row.addChild("td").addChild("p", this.filename.toString());

			if (this.uomFetcher != null) {
				row.addChild("td").addChild("#", MainJarUpdateFileFetcher.this.l10n("fetchingFromUOM"));
			}
			else if (this.lastProgress == null) {
				row.addChild(QueueToadlet.createProgressCell(false, true, COMPRESS_STATE.WORKING, 0, 0, 0, 0, 0, false,
						false));
			}
			else {
				row.addChild(QueueToadlet.createProgressCell(false, true, COMPRESS_STATE.WORKING,
						this.lastProgress.succeedBlocks, this.lastProgress.failedBlocks,
						this.lastProgress.fatallyFailedBlocks, this.lastProgress.minSuccessfulBlocks,
						this.lastProgress.totalBlocks, this.lastProgress.finalizedTotal, false));
			}
			return row;
		}

		void fetchFromUOM() {
			synchronized (this) {
				if (this.fetched) {
					return;
				}
				if (!this.essential) {
					return;
				}
			}
			UOMDependencyFetcher f = MainJarUpdateFileFetcher.this.manager.uom.fetchDependency(this.expectedHash,
					this.expectedLength, this.filename, this.executable, () -> {
						synchronized (DependencyJarFetcher.this) {
							if (DependencyJarFetcher.this.fetched) {
								return;
							}
							DependencyJarFetcher.this.fetched = true;
						}
						if (DependencyJarFetcher.this.cb != null) {
							DependencyJarFetcher.this.cb.onSuccess();
						}
					});
			synchronized (this) {
				if (this.uomFetcher != null) {
					Logger.error(this, "Started UOMFetcher twice for " + this.filename, new Exception("error"));
					return;
				}
				this.uomFetcher = f;
			}
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

}
