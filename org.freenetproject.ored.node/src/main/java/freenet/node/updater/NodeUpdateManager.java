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
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import freenet.bucket.Bucket;
import freenet.bucket.BucketCloser;
import freenet.bucket.BucketFileUtil;
import freenet.bucket.BucketTools;
import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.FetchResult;
import freenet.client.HighLevelSimpleClient;
import freenet.client.async.ClientContext;
import freenet.client.async.ClientGetCallback;
import freenet.client.async.ClientGetter;
import freenet.client.async.PersistenceDisabledException;
import freenet.client.request.PriorityClasses;
import freenet.client.request.RequestClient;
import freenet.clients.fcp.FCPUserAlert;
import freenet.config.BooleanCallback;
import freenet.config.Config;
import freenet.config.InvalidConfigValueException;
import freenet.config.NodeNeedRestartException;
import freenet.config.StringCallback;
import freenet.config.SubConfig;
import freenet.io.comm.ByteCounter;
import freenet.io.comm.DMT;
import freenet.io.comm.Message;
import freenet.io.comm.NotConnectedException;
import freenet.keys.FreenetURI;
import freenet.l10n.NodeL10n;
import freenet.node.Node;
import freenet.node.NodeFile;
import freenet.node.NodeStarter;
import freenet.node.OpennetManager;
import freenet.node.PeerNode;
import freenet.node.ProgramDirectory;
import freenet.node.Version;
import freenet.node.useralerts.RevocationKeyFoundUserAlert;
import freenet.node.useralerts.SimpleUserAlert;
import freenet.node.useralerts.UpdatedVersionAvailableUserAlert;
import freenet.nodelogger.Logger;
import freenet.pluginmanager.OfficialPlugins.OfficialPluginDescription;
import freenet.pluginmanager.PluginInfoWrapper;
import freenet.support.HTMLNode;
import freenet.support.JVMVersion;
import freenet.support.io.Closer;
import freenet.support.io.FileUtil;
import freenet.support.node.NodeInitException;

/**
 * <p>
 * Supervises NodeUpdater's. Enables us to easily update multiple files, change the URI's
 * on the fly, eliminates some messy code in the callbacks etc.
 * </p>
 *
 * <p>
 * Procedure for updating the update key: Create a new key. Create a new build X, the
 * "transition version". This must be UOM-compatible with the previous transition version.
 * UOM-compatible means UOM should work from the older builds. This in turn means that it
 * should support an overlapping set of connection setup negTypes (@link
 * FNPPacketMangler.supportedNegTypes()). Similarly there may be issues with changes to
 * the UOM messages, or to messages in general. Build X is inserted to both the old key
 * and the new key. Build X's SSK URI (on the old auto-update key) will be hard-coded as
 * the new transition version. Then the next build, X+1, can get rid of some of the back
 * compatibility cruft (especially old connection setup types), and will be inserted only
 * to the new key. Secure backups of the new key are required and are documented
 * elsewhere.
 * </p>
 *
 * FIXME: See bug #6009 for some current UOM compatibility issues.
 */
public class NodeUpdateManager {

	/**
	 * The last build on the previous key with Java 7 support. Older nodes can update to
	 * this point via old UOM.
	 */
	public static final int TRANSITION_VERSION = 1481;

	/** The URI for post-TRANSITION_VERSION builds' freenet.jar on modern JVMs. */
	public static final String UPDATE_URI = "USK@vCKGjQtKuticcaZ-dwOgmkYPVLj~N1dm9mb3j3Smg4Y,-wz5IYtd7PlhI2Kx4cAwpUu13fW~XBglPyOn8wABn60,AQACAAE/jar/"
			+ Version.buildNumber();

	/** The URI for post-TRANSITION_VERSION builds' freenet.jar on EoL JVMs. */
	public static final String LEGACY_UPDATE_URI = "SSK@ugWS2VICgMcQ5ptmEE1mAvHgUn2OSCOogJIUAvbL090,ZKO1pZRI9oaBuBQuWFL4bK3K0blvmEdqYgiIJF5GcjQ,AQACAAE/jar-"
			+ TRANSITION_VERSION;

	/**
	 * The URI for freenet.jar before the updater was rekeyed. Unless both the EoL and
	 * modern keys rekey this is LEGACY_UPDATE_URI.
	 */
	public static final String PREVIOUS_UPDATE_URI = "SSK@O~UmMwTeDcyDIW-NsobFBoEicdQcogw7yrLO2H-sJ5Y,JVU4L7m9mNppkd21UNOCzRHKuiTucd6Ldw8vylBOe5o,AQACAAE/jar-"
			+ TRANSITION_VERSION;

	public static final String REVOCATION_URI = "SSK@tHlY8BK2KFB7JiO2bgeAw~e4sWU43YdJ6kmn73gjrIw,DnQzl0BYed15V8WQn~eRJxxIA-yADuI8XW7mnzEbut8,AQACAAE/revoked";

	// These are necessary to prevent DoS.
	public static final long MAX_REVOCATION_KEY_LENGTH = 32 * 1024;

	public static final long MAX_REVOCATION_KEY_TEMP_LENGTH = 64 * 1024;

	public static final long MAX_REVOCATION_KEY_BLOB_LENGTH = 128 * 1024;

	public static final long MAX_MAIN_JAR_LENGTH = 48 * 1024 * 1024; // 48MiB

	public static final long MAX_JAVA_INSTALLER_LENGTH = 300 * 1024 * 1024;

	public static final long MAX_WINDOWS_INSTALLER_LENGTH = 300 * 1024 * 1024;

	public static final long MAX_IP_TO_COUNTRY_LENGTH = 24 * 1024 * 1024;

	public static final long MAX_SEEDNODES_LENGTH = 3 * 1024 * 1024;

	static final FreenetURI legacyMainJarSSK;
	static final FreenetURI legacyMainJarUSK;

	static final FreenetURI previousMainJarSSK;
	static final FreenetURI previousMainJarUSK;

	public static final String transitionMainJarFilename = "legacy-freenet-jar-" + TRANSITION_VERSION + ".fblob";

	public final File transitionMainJarFile;

	static {
		try {
			legacyMainJarSSK = new FreenetURI(LEGACY_UPDATE_URI);
			legacyMainJarUSK = legacyMainJarSSK.uskForSSK();
			previousMainJarSSK = new FreenetURI(PREVIOUS_UPDATE_URI);
			previousMainJarUSK = previousMainJarSSK.uskForSSK();
		}
		catch (MalformedURLException ex) {
			throw new Error(ex);
		}
	}

	private FreenetURI updateURI;

	private FreenetURI revocationURI;

	private final LegacyJarFetcher transitionMainJarFetcher;

	private MainJarUpdater mainUpdater;

	private Map<String, PluginJarUpdater> pluginUpdaters;

	private boolean autoDeployPluginsOnRestart;

	private final boolean wasEnabledOnStartup;

	/** Is auto-update enabled? */
	private volatile boolean isAutoUpdateAllowed;

	/** Has the user given the go-ahead? */
	private volatile boolean armed;

	/**
	 * Currently deploying an update? Set when we start to deploy an update. Which means
	 * it should not be un-set, except in the case of a severe error causing a valid
	 * update to fail. However, it is un-set in this case, so that we can try again with
	 * another build.
	 */
	private boolean isDeployingUpdate;

	private final Object broadcastUOMAnnouncesSync = new Object();

	private boolean broadcastUOMAnnouncesOld = false;

	private boolean broadcastUOMAnnouncesNew = false;

	public final Node node;

	final RevocationChecker revocationChecker;

	private String revocationMessage;

	private volatile boolean hasBeenBlown;

	private volatile boolean peersSayBlown;

	private boolean updateSeednodes;

	private boolean updateInstallers;

	// FIXME make configurable
	private final boolean updateIPToCountry = true;

	/** Is there a new main jar ready to deploy? */
	private volatile boolean hasNewMainJar;

	/** If another main jar is being fetched, when did the fetch start? */
	private long startedFetchingNextMainJar;

	/** Time when we got the jar */
	private long gotJarTime;

	// Revocation alert
	private RevocationKeyFoundUserAlert revocationAlert;

	// Update alert
	private final UpdatedVersionAvailableUserAlert alert;

	public final UpdateOverMandatoryManager uom;

	private static volatile boolean logMINOR;

	private boolean disabledThisSession;

	private MainJarDependenciesChecker.MainJarDependencies latestMainJarDependencies;

	private int dependenciesValidForBuild;

	/** The version we have fetched and will deploy. */
	private int fetchedMainJarVersion;

	/** The jar of the version we have fetched and will deploy. */
	private Bucket fetchedMainJarData;

	/** The blob file for the current version, for UOM */
	private File currentVersionBlobFile;

	/**
	 * The version we have fetched and aren't using because we are already deploying.
	 */
	private int maybeNextMainJarVersion;

	/**
	 * The version we have fetched and aren't using because we are already deploying.
	 */
	private Bucket maybeNextMainJarData;

	private static final Object deployLock = new Object();

	static final String TEMP_BLOB_SUFFIX = ".updater.fblob.tmp";
	static final String TEMP_FILE_SUFFIX = ".updater.tmp";

	static {
		Logger.registerClass(NodeUpdateManager.class);
	}

	public NodeUpdateManager(Node node, Config config) throws InvalidConfigValueException {
		this.node = node;
		this.hasBeenBlown = false;
		this.alert = new UpdatedVersionAvailableUserAlert(this);
		this.alert.isValid(false);

		SubConfig updaterConfig = config.createSubConfig("node.updater");

		updaterConfig.register("enabled", true, 1, false, false, "NodeUpdateManager.enabled",
				"NodeUpdateManager.enabledLong", new UpdaterEnabledCallback());

		this.wasEnabledOnStartup = updaterConfig.getBoolean("enabled");

		// is the auto-update allowed ?
		updaterConfig.register("autoupdate", false, 2, false, true, "NodeUpdateManager.installNewVersions",
				"NodeUpdateManager.installNewVersionsLong", new AutoUpdateAllowedCallback());
		this.isAutoUpdateAllowed = updaterConfig.getBoolean("autoupdate");

		// Set default update URI for new nodes depending on JVM version.
		updaterConfig.register("URI", JVMVersion.needsLegacyUpdater() ? legacyMainJarUSK.toString() : UPDATE_URI, 3,
				true, true, "NodeUpdateManager.updateURI", "NodeUpdateManager.updateURILong", new UpdateURICallback());

		try {
			this.updateURI = new FreenetURI(updaterConfig.getString("URI"));
		}
		catch (MalformedURLException ex) {
			throw new InvalidConfigValueException(this.l10n("invalidUpdateURI", "error", ex.getLocalizedMessage()));
		}

		/*
		 * The update URI is always written, so override the existing key depending on JVM
		 * version. Only override official URIs to avoid interfering with unofficial
		 * update keys.
		 *
		 * An up-to-date JVM must update the legacy URI (in addition to the previous URI)
		 * in case a node was run with an EoL JVM that was subsequently upgraded.
		 */
		if (JVMVersion.needsLegacyUpdater()) {
			this.transitionKey(updaterConfig, previousMainJarSSK, legacyMainJarUSK.toString());
		}
		else {
			this.transitionKey(updaterConfig, previousMainJarSSK, UPDATE_URI);
			this.transitionKey(updaterConfig, legacyMainJarSSK, UPDATE_URI);
		}

		this.updateURI = this.updateURI.setSuggestedEdition(Version.buildNumber());
		if (this.updateURI.hasMetaStrings()) {
			throw new InvalidConfigValueException(this.l10n("updateURIMustHaveNoMetaStrings"));
		}
		if (!this.updateURI.isUSK()) {
			throw new InvalidConfigValueException(this.l10n("updateURIMustBeAUSK"));
		}

		updaterConfig.register("revocationURI", REVOCATION_URI, 4, true, false, "NodeUpdateManager.revocationURI",
				"NodeUpdateManager.revocationURILong", new UpdateRevocationURICallback());

		try {
			this.revocationURI = new FreenetURI(updaterConfig.getString("revocationURI"));
		}
		catch (MalformedURLException ex) {
			throw new InvalidConfigValueException(this.l10n("invalidRevocationURI", "error", ex.getLocalizedMessage()));
		}

		LegacyJarFetcher.LegacyFetchCallback legacyFetcherCallback = new LegacyJarFetcher.LegacyFetchCallback() {

			@Override
			public void onSuccess(LegacyJarFetcher fetcher) {
				if (NodeUpdateManager.this.transitionMainJarFetcher.fetched()) {
					System.out.println("Got legacy jar, announcing...");
					NodeUpdateManager.this.broadcastUOMAnnouncesOld();
				}
			}

			@Override
			public void onFailure(FetchException e, LegacyJarFetcher fetcher) {
				Logger.error(this,
						"Failed to fetch " + fetcher.saveTo
								+ " : UPDATE OVER MANDATORY WILL NOT WORK WITH OLDER NODES THAN " + TRANSITION_VERSION
								+ " : " + e,
						e);
				System.err.println("Failed to fetch " + fetcher.saveTo
						+ " : UPDATE OVER MANDATORY WILL NOT WORK WITH OLDER NODES THAN " + TRANSITION_VERSION + " : "
						+ e);
			}

		};

		this.transitionMainJarFile = new File(node.clientCore.getPersistentTempDir(), transitionMainJarFilename);
		this.transitionMainJarFetcher = new LegacyJarFetcher(previousMainJarSSK, this.transitionMainJarFile,
				node.clientCore, legacyFetcherCallback);

		updaterConfig.register("updateSeednodes", this.wasEnabledOnStartup, 6, true, true,
				"NodeUpdateManager.updateSeednodes", "NodeUpdateManager.updateSeednodesLong", new BooleanCallback() {

					@Override
					public Boolean get() {
						return NodeUpdateManager.this.updateSeednodes;
					}

					@Override
					public void set(Boolean val) throws NodeNeedRestartException {
						if (NodeUpdateManager.this.updateSeednodes == val) {
							return;
						}
						NodeUpdateManager.this.updateSeednodes = val;
						if (val) {
							throw new NodeNeedRestartException("Must restart to fetch the seednodes");
						}
						else {
							throw new NodeNeedRestartException(
									"Must restart to stop the seednodes fetch if it is still running");
						}
					}

				});

		this.updateSeednodes = updaterConfig.getBoolean("updateSeednodes");

		updaterConfig.register("updateInstallers", this.wasEnabledOnStartup, 6, true, true,
				"NodeUpdateManager.updateInstallers", "NodeUpdateManager.updateInstallersLong", new BooleanCallback() {

					@Override
					public Boolean get() {
						return NodeUpdateManager.this.updateInstallers;
					}

					@Override
					public void set(Boolean val) throws NodeNeedRestartException {
						if (NodeUpdateManager.this.updateInstallers == val) {
							return;
						}
						NodeUpdateManager.this.updateInstallers = val;
						if (val) {
							throw new NodeNeedRestartException("Must restart to fetch the installers");
						}
						else {
							throw new NodeNeedRestartException(
									"Must restart to stop the installers fetches if they are still running");
						}
					}

				});

		this.updateInstallers = updaterConfig.getBoolean("updateInstallers");

		updaterConfig.finishedInitialization();

		this.revocationChecker = new RevocationChecker(this,
				new File(node.clientCore.getPersistentTempDir(), "revocation-key.fblob"));

		this.uom = new UpdateOverMandatoryManager(this);
		this.uom.removeOldTempFiles();
	}

	private void transitionKey(SubConfig updaterConfig, FreenetURI from, String to) throws InvalidConfigValueException {

		if (this.updateURI.equalsKeypair(from)) {
			try {
				updaterConfig.set("URI", to);
			}
			catch (NodeNeedRestartException ex) {
				// UpdateURICallback.set() does not throw NodeNeedRestartException.
				Logger.warning(this, "Unexpected failure setting update URI", ex);
			}
		}
	}

	public File getInstallerWindows() {
		File f = NodeFile.InstallerWindows.getFile(this.node);
		if (!(f.exists() && f.canRead() && f.length() > 0)) {
			return null;
		}
		else {
			return f;
		}
	}

	public File getInstallerNonWindows() {
		File f = NodeFile.InstallerNonWindows.getFile(this.node);
		if (!(f.exists() && f.canRead() && f.length() > 0)) {
			return null;
		}
		else {
			return f;
		}
	}

	public FreenetURI getSeednodesURI() {
		return this.updateURI.sskForUSK().setDocName("seednodes-" + Version.buildNumber());
	}

	public FreenetURI getInstallerNonWindowsURI() {
		return this.updateURI.sskForUSK().setDocName("installer-" + Version.buildNumber());
	}

	public FreenetURI getInstallerWindowsURI() {
		return this.updateURI.sskForUSK().setDocName("wininstaller-" + Version.buildNumber());
	}

	public FreenetURI getIPv4ToCountryURI() {
		return this.updateURI.sskForUSK().setDocName("iptocountryv4-" + Version.buildNumber());
	}

	public void start() throws InvalidConfigValueException {

		this.node.clientCore.alerts.register(this.alert);

		this.enable(this.wasEnabledOnStartup);

		// Fetch seednodes to the nodeDir.
		if (this.updateSeednodes) {

			SimplePuller seedrefsGetter = new SimplePuller(this.getSeednodesURI(), NodeFile.Seednodes);
			seedrefsGetter.start(PriorityClasses.IMMEDIATE_SPLITFILE_PRIORITY_CLASS, MAX_SEEDNODES_LENGTH);
		}

		// Fetch installers and IP-to-country files to the runDir.
		if (this.updateInstallers) {
			SimplePuller installerGetter = new SimplePuller(this.getInstallerNonWindowsURI(),
					NodeFile.InstallerNonWindows);
			SimplePuller wininstallerGetter = new SimplePuller(this.getInstallerWindowsURI(),
					NodeFile.InstallerWindows);

			installerGetter.start(PriorityClasses.UPDATE_PRIORITY_CLASS, MAX_JAVA_INSTALLER_LENGTH);
			wininstallerGetter.start(PriorityClasses.UPDATE_PRIORITY_CLASS, MAX_WINDOWS_INSTALLER_LENGTH);

		}

		if (this.updateIPToCountry) {
			SimplePuller ip4Getter = new SimplePuller(this.getIPv4ToCountryURI(), NodeFile.IPv4ToCountry);
			ip4Getter.start(PriorityClasses.UPDATE_PRIORITY_CLASS, MAX_IP_TO_COUNTRY_LENGTH);
		}

	}

	void broadcastUOMAnnouncesOld() {
		boolean mainJarAvailable = this.transitionMainJarFetcher != null && this.transitionMainJarFetcher.fetched();
		Message msg;
		if (!mainJarAvailable) {
			return;
		}
		synchronized (this.broadcastUOMAnnouncesSync) {
			if (this.broadcastUOMAnnouncesOld && !this.hasBeenBlown) {
				return;
			}
			this.broadcastUOMAnnouncesOld = true;
			msg = this.getOldUOMAnnouncement();
		}
		this.node.peers.localBroadcast(msg, true, true, this.ctr, 0, TRANSITION_VERSION - 1);
	}

	void broadcastUOMAnnouncesNew() {
		if (logMINOR) {
			Logger.minor(this, "Broadcast UOM announcements (new)");
		}
		long size = this.canAnnounceUOMNew();
		Message msg;
		if (size <= 0 && !this.hasBeenBlown) {
			return;
		}
		synchronized (this.broadcastUOMAnnouncesSync) {
			if (this.broadcastUOMAnnouncesNew && !this.hasBeenBlown) {
				return;
			}
			this.broadcastUOMAnnouncesNew = true;
			msg = this.getNewUOMAnnouncement(size);
		}
		if (logMINOR) {
			Logger.minor(this, "Broadcasting UOM announcements (new)");
		}
		this.node.peers.localBroadcast(msg, true, true, this.ctr, TRANSITION_VERSION, Integer.MAX_VALUE);
	}

	/** Return the length of the data fetched for the current version, or -1. */
	private long canAnnounceUOMNew() {
		Bucket data;
		synchronized (this) {
			if (this.hasNewMainJar && this.armed) {
				if (logMINOR) {
					Logger.minor(this, "Will update soon, not offering UOM.");
				}
				return -1;
			}
			if (this.fetchedMainJarVersion <= 0) {
				if (logMINOR) {
					Logger.minor(this, "Not fetched yet");
				}
				return -1;
			}
			else if (this.fetchedMainJarVersion != Version.buildNumber()) {
				// Don't announce UOM unless we've successfully started the jar.
				if (logMINOR) {
					Logger.minor(this, "Downloaded a different version than the one we are running, not offering UOM.");
				}
				return -1;
			}
			data = this.fetchedMainJarData;
		}
		if (logMINOR) {
			Logger.minor(this, "Got data for UOM: " + data + " size " + data.size());
		}
		return data.size();
	}

	private Message getOldUOMAnnouncement() {
		boolean mainJarAvailable = this.transitionMainJarFetcher != null && this.transitionMainJarFetcher.fetched();
		return DMT.createUOMAnnouncement(previousMainJarUSK.toString(), this.revocationURI.toString(),
				this.revocationChecker.hasBlown(), mainJarAvailable ? TRANSITION_VERSION : -1,
				this.revocationChecker.lastSucceededDelta(), this.revocationChecker.getRevocationDNFCounter(),
				this.revocationChecker.getBlobSize(),
				mainJarAvailable ? this.transitionMainJarFetcher.getBlobSize() : -1,
				(int) this.node.nodeStats.getNodeAveragePingTime(), (int) this.node.nodeStats.getBwlimitDelayTime());
	}

	private Message getNewUOMAnnouncement(long blobSize) {
		int fetchedVersion = (blobSize <= 0) ? -1 : Version.buildNumber();
		return DMT.createUOMAnnouncement(this.updateURI.toString(), this.revocationURI.toString(),
				this.revocationChecker.hasBlown(), fetchedVersion, this.revocationChecker.lastSucceededDelta(),
				this.revocationChecker.getRevocationDNFCounter(), this.revocationChecker.getBlobSize(), blobSize,
				(int) this.node.nodeStats.getNodeAveragePingTime(), (int) this.node.nodeStats.getBwlimitDelayTime());
	}

	public void maybeSendUOMAnnounce(PeerNode peer) {
		boolean sendOld;
		boolean sendNew;
		synchronized (this.broadcastUOMAnnouncesSync) {
			if (!(this.broadcastUOMAnnouncesOld || this.broadcastUOMAnnouncesNew)) {
				if (logMINOR) {
					Logger.minor(this, "Not sending UOM (any) on connect: Nothing worth announcing yet");
				}
				return; // nothing worth announcing yet
			}
			sendOld = this.broadcastUOMAnnouncesOld;
			sendNew = this.broadcastUOMAnnouncesNew;
		}
		if (this.hasBeenBlown && !this.revocationChecker.hasBlown()) {
			if (logMINOR) {
				Logger.minor(this, "Not sending UOM (any) on connect: Local problem causing blown key");
			}
			// Local problem, don't broadcast.
			return;
		}
		long size = this.canAnnounceUOMNew();
		try {
			if (peer.getVersionNumber() < TRANSITION_VERSION) {
				if (sendOld || this.hasBeenBlown) {
					peer.sendAsync(this.getOldUOMAnnouncement(), null, this.ctr);
				}
			}
			else {
				if (sendNew || this.hasBeenBlown) {
					peer.sendAsync(this.getNewUOMAnnouncement(size), null, this.ctr);
				}
			}
		}
		catch (NotConnectedException ignored) {
			// Sad, but ignore it
		}
	}

	/**
	 * Is auto-update enabled?
	 */
	public synchronized boolean isEnabled() {
		return (this.mainUpdater != null);
	}

	/**
	 * Enable or disable auto-update.
	 * @param enable Whether auto-update should be enabled.
	 */
	void enable(boolean enable) {
		// FIXME 194eb7bb6f295e52d18378d805bd315c95030b24 is doubtful and incomplete.
		// if(!node.isUsingWrapper()){
		// Logger.normal(this,
		// "Don't try to start the updater as we are not running under the wrapper.");
		// return;
		// }
		NodeUpdater main = null;
		Map<String, PluginJarUpdater> oldPluginUpdaters = null;
		// We need to run the revocation checker even if auto-update is
		// disabled.
		// Two reasons:
		// 1. For the benefit of other nodes, and because even if auto-update is
		// off, it's something the user should probably know about.
		// 2. When the key is blown, we turn off auto-update!!!!
		this.revocationChecker.start(false);
		synchronized (this) {
			boolean enabled = (this.mainUpdater != null);
			if (enabled == enable) {
				return;
			}
			if (!enable) {
				// Kill it
				this.mainUpdater.preKill();
				main = this.mainUpdater;
				this.mainUpdater = null;
				oldPluginUpdaters = this.pluginUpdaters;
				this.pluginUpdaters = null;
				this.disabledNotBlown = false;
			}
			else {
				// if((!WrapperManager.isControlledByNativeWrapper()) ||
				// (NodeStarter.extBuildNumber == -1)) {
				// Logger.error(this,
				// "Cannot update because not running under wrapper");
				// throw new
				// InvalidConfigValueException(l10n("noUpdateWithoutWrapper"));
				// }
				// Start it
				this.mainUpdater = new MainJarUpdater(this, this.updateURI, Version.buildNumber(), -1,
						Integer.MAX_VALUE, "main-jar-");
				this.pluginUpdaters = new HashMap<>();
			}
		}
		if (!enable) {
			if (main != null) {
				main.kill();
			}
			this.stopPluginUpdaters(oldPluginUpdaters);
			this.transitionMainJarFetcher.stop();
		}
		else {
			// FIXME copy it, dodgy locking.
			try {
				// Must be run before starting everything else as it cleans up tempfiles
				// too.
				this.mainUpdater.cleanupDependencies();
			}
			catch (Throwable ex) {
				// Don't let it block startup, but be very loud!
				Logger.error(this, "Caught " + ex + " setting up Update Over Mandatory", ex);
				System.err.println("Updater error: " + ex);
				ex.printStackTrace();
			}
			this.mainUpdater.start();
			this.startPluginUpdaters();
			this.transitionMainJarFetcher.start();
		}
	}

	private void startPluginUpdaters() {
		for (OfficialPluginDescription plugin : this.node.getPluginManager().getOfficialPlugins()) {
			this.startPluginUpdater(plugin.name);
		}
	}

	/**
	 * @param plugName The filename for loading/config purposes for an official plugin.
	 * E.g. "Library" (no .jar)
	 */
	public void startPluginUpdater(String plugName) {
		if (logMINOR) {
			Logger.minor(this, "Starting plugin updater for " + plugName);
		}
		OfficialPluginDescription plugin = this.node.getPluginManager().getOfficialPlugin(plugName);
		if (plugin != null) {
			this.startPluginUpdater(plugin);
		}
		else
		// Most likely not an official plugin
		if (logMINOR) {
			Logger.minor(this, "No such plugin " + plugName + " in startPluginUpdater()");
		}
	}

	void startPluginUpdater(OfficialPluginDescription plugin) {
		String name = plugin.name;
		// @see https://emu.freenetproject.org/pipermail/devl/2015-November/038581.html
		long minVer = (plugin.essential ? plugin.minimumVersion : plugin.recommendedVersion);
		// But it might already be past that ...
		PluginInfoWrapper info = this.node.pluginManager.getPluginInfo(name);
		if (info == null) {
			if (!(this.node.pluginManager.isPluginLoadedOrLoadingOrWantLoad(name))) {
				if (logMINOR) {
					Logger.minor(this, "Plugin not loaded");
				}
				return;
			}
		}
		if (info != null) {
			minVer = Math.max(minVer, info.getPluginLongVersion());
		}
		FreenetURI uri = this.updateURI.setDocName(name).setSuggestedEdition(minVer);
		PluginJarUpdater updater = new PluginJarUpdater(this, uri, (int) minVer, -1,
				(plugin.essential ? (int) minVer : Integer.MAX_VALUE), name + "-", name, this.node.pluginManager,
				this.autoDeployPluginsOnRestart);
		synchronized (this) {
			if (this.pluginUpdaters == null) {
				if (logMINOR) {
					Logger.minor(this, "Updating not enabled");
				}
				return; // Not enabled
			}
			if (this.pluginUpdaters.containsKey(name)) {
				if (logMINOR) {
					Logger.minor(this, "Already in updaters list");
				}
				return; // Already started
			}
			this.pluginUpdaters.put(name, updater);
		}
		updater.start();
		System.out.println("Started plugin update fetcher for " + name);
	}

	public void stopPluginUpdater(String plugName) {
		OfficialPluginDescription plugin = this.node.getPluginManager().getOfficialPlugin(plugName);
		if (plugin == null) {
			return; // Not an official plugin
		}
		PluginJarUpdater updater;
		synchronized (this) {
			if (this.pluginUpdaters == null) {
				if (logMINOR) {
					Logger.minor(this, "Updating not enabled");
				}
				return; // Not enabled
			}
			updater = this.pluginUpdaters.remove(plugName);
		}
		if (updater != null) {
			updater.kill();
		}
	}

	private void stopPluginUpdaters(Map<String, PluginJarUpdater> oldPluginUpdaters) {
		for (PluginJarUpdater u : oldPluginUpdaters.values()) {
			u.kill();
		}
	}

	/**
	 * Create a NodeUpdateManager. Called by node constructor.
	 * @param node The node object.
	 * @param config The global config object. Options will be added to a subconfig called
	 * node.updater.
	 * @return A new NodeUpdateManager
	 * @throws InvalidConfigValueException If there is an error in the config.
	 */
	public static NodeUpdateManager maybeCreate(Node node, Config config) throws InvalidConfigValueException {
		return new NodeUpdateManager(node, config);
	}

	/**
	 * Get the URI for freenet.jar.
	 */
	public synchronized FreenetURI getURI() {
		return this.updateURI;
	}

	/**
	 * @return URI for the user-facing changelog.
	 */
	public synchronized FreenetURI getChangelogURI() {
		return this.updateURI.setDocName("changelog");
	}

	public synchronized FreenetURI getDeveloperChangelogURI() {
		return this.updateURI.setDocName("fullchangelog");
	}

	/**
	 * Add links to the changelog for the given version to the given node.
	 * @param version USK edition to point to
	 * @param node to add links to
	 */
	public synchronized void addChangelogLinks(long version, HTMLNode node) {
		String changelogUri = this.getChangelogURI().setSuggestedEdition(version).sskForUSK().toASCIIString();
		String developerDetailsUri = this.getDeveloperChangelogURI().setSuggestedEdition(version).sskForUSK()
				.toASCIIString();
		node.addChild("a", "href", '/' + changelogUri + "?type=text/plain",
				NodeL10n.getBase().getString("UpdatedVersionAvailableUserAlert.changelog"));
		node.addChild("br");
		node.addChild("a", "href", '/' + developerDetailsUri + "?type=text/plain",
				NodeL10n.getBase().getString("UpdatedVersionAvailableUserAlert.devchangelog"));
	}

	/**
	 * Set the URfrenet.jar should be updated from.
	 * @param uri The URI to set.
	 */
	public void setURI(FreenetURI uri) {
		// FIXME plugins!!
		NodeUpdater updater;
		Map<String, PluginJarUpdater> oldPluginUpdaters;
		synchronized (this) {
			if (this.updateURI.equals(uri)) {
				return;
			}
			this.updateURI = uri;
			this.updateURI = this.updateURI.setSuggestedEdition(Version.buildNumber());
			updater = this.mainUpdater;
			oldPluginUpdaters = this.pluginUpdaters;
			this.pluginUpdaters = new HashMap<>();
			if (updater == null) {
				return;
			}
		}
		updater.onChangeURI(uri);
		this.stopPluginUpdaters(oldPluginUpdaters);
		this.startPluginUpdaters();
	}

	/**
	 * @return The revocation URI.
	 */
	public synchronized FreenetURI getRevocationURI() {
		return this.revocationURI;
	}

	/**
	 * Set the revocation URI.
	 * @param uri The new revocation URI.
	 */
	public void setRevocationURI(FreenetURI uri) {
		synchronized (this) {
			if (this.revocationURI.equals(uri)) {
				return;
			}
			this.revocationURI = uri;
		}
		this.revocationChecker.onChangeRevocationURI();
	}

	/**
	 * @return Is auto-update currently enabled?
	 */
	public boolean isAutoUpdateAllowed() {
		return this.isAutoUpdateAllowed;
	}

	/**
	 * Enable or disable auto-update.
	 * @param val If true, enable auto-update (and immediately update if an update is
	 * ready). If false, disable it.
	 */
	public void setAutoUpdateAllowed(boolean val) {
		synchronized (this) {
			if (val == this.isAutoUpdateAllowed) {
				return;
			}
			this.isAutoUpdateAllowed = val;
			if (val) {
				if (!this.isReadyToDeployUpdate(false)) {
					return;
				}
			}
			else {
				return;
			}
		}
		this.deployOffThread(0, false);
	}

	private static final long WAIT_FOR_SECOND_FETCH_TO_COMPLETE = TimeUnit.MINUTES.toMillis(4);

	private static final long RECENT_REVOCATION_INTERVAL = TimeUnit.MINUTES.toMillis(2);

	/**
	 * After 5 minutes, deploy the update even if we haven't got 3 DNFs on the revocation
	 * key yet. Reason: we want to be able to deploy UOM updates on nodes with all TOO NEW
	 * or leaf nodes whose peers are overloaded/broken. Note that with UOM, revocation
	 * certs are automatically propagated node to node, so this should be *relatively*
	 * safe. Any better ideas, tell us.
	 */
	private static final long REVOCATION_FETCH_TIMEOUT = TimeUnit.MINUTES.toMillis(5);

	/**
	 * Does the updater have an update ready to deploy? May be called synchronized(this).
	 * @param ignoreRevocation If true, return whether we will deploy when the revocation
	 * check finishes. If false, return whether we can deploy now, and if not, deploy
	 * after a delay with deployOffThread().
	 */
	private boolean isReadyToDeployUpdate(boolean ignoreRevocation) {
		long now = System.currentTimeMillis();
		int waitForNextJar = -1;
		synchronized (this) {
			if (this.mainUpdater == null) {
				return false;
			}
			if (!(this.hasNewMainJar)) {
				return false; // no jar
			}
			if (this.hasBeenBlown) {
				return false; // Duh
			}
			if (this.peersSayBlown) {
				if (logMINOR) {
					Logger.minor(this, "Not deploying, peers say blown");
				}
				return false;
			}
			// Don't immediately deploy if still fetching
			if (this.startedFetchingNextMainJar > 0) {
				waitForNextJar = (int) (this.startedFetchingNextMainJar + WAIT_FOR_SECOND_FETCH_TO_COMPLETE - now);
				if (waitForNextJar > 0) {
					if (logMINOR) {
						Logger.minor(this, "Not ready: Still fetching");
					}
					// Wait for running fetch to complete
				}
			}

			// Check dependencies.
			if (this.latestMainJarDependencies == null) {
				if (logMINOR) {
					Logger.minor(this, "Dependencies not available");
				}
				return false;
			}
			if (this.fetchedMainJarVersion != this.dependenciesValidForBuild) {
				if (logMINOR) {
					Logger.minor(this,
							"Not deploying because dependencies are older version " + this.dependenciesValidForBuild
									+ " - new version " + this.fetchedMainJarVersion + " may not start");
				}
				return false;
			}

			// Check revocation.
			if (waitForNextJar <= 0) {
				if (!ignoreRevocation) {
					if (now - this.revocationChecker.lastSucceeded() < RECENT_REVOCATION_INTERVAL) {
						if (logMINOR) {
							Logger.minor(this, "Ready to deploy (revocation checker succeeded recently)");
						}
						return true;
					}
					if (this.gotJarTime > 0 && now - this.gotJarTime >= REVOCATION_FETCH_TIMEOUT) {
						if (logMINOR) {
							Logger.minor(this, "Ready to deploy (got jar before timeout)");
						}
						return true;
					}
				}
			}
		}
		if (logMINOR) {
			Logger.minor(this, "Still here in isReadyToDeployUpdate");
		}
		// Apparently everything is ready except the revocation fetch. So start
		// it.
		this.revocationChecker.start(true);
		if (ignoreRevocation) {
			if (logMINOR) {
				Logger.minor(this, "Returning true because of ignoreRevocation");
			}
			return true;
		}
		long waitTime = Math.max(REVOCATION_FETCH_TIMEOUT, waitForNextJar);
		if (logMINOR) {
			Logger.minor(this, "Will deploy in " + waitTime + "ms");
		}
		this.deployOffThread(waitTime, false);
		return false;
	}

	/** Check whether there is an update to deploy. If there is, do it. */
	private void deployUpdate() {
		boolean started = false;
		boolean success = false;
		try {
			MainJarDependenciesChecker.MainJarDependencies deps;
			synchronized (this) {
				if (this.disabledThisSession) {
					String msg = "Not deploying update because disabled for this session (bad java version??)";
					Logger.error(this, msg);
					System.err.println(msg);
					return;
				}
				if (this.hasBeenBlown) {
					String msg = "Trying to update but key has been blown! Not updating, message was "
							+ this.revocationMessage;
					Logger.error(this, msg);
					System.err.println(msg);
					return;
				}
				if (this.peersSayBlown) {
					String msg = "Trying to update but at least one peer says the key has been blown! Not updating.";
					Logger.error(this, msg);
					System.err.println(msg);
					return;

				}
				if (!this.isEnabled()) {
					if (logMINOR) {
						Logger.minor(this, "Not enabled");
					}
					return;
				}
				if (!(this.isAutoUpdateAllowed || this.armed)) {
					if (logMINOR) {
						Logger.minor(this, "Not armed");
					}
					return;
				}
				if (!this.isReadyToDeployUpdate(false)) {
					if (logMINOR) {
						Logger.minor(this, "Not ready to deploy update");
					}
					return;
				}
				if (this.isDeployingUpdate) {
					if (logMINOR) {
						Logger.minor(this, "Already deploying update");
					}
					return;
				}
				started = true;
				this.isDeployingUpdate = true;
				deps = this.latestMainJarDependencies;
			}

			synchronized (deployLock()) {
				success = this.innerDeployUpdate(deps);
				if (success) {
					waitForever();
				}
			}
			// isDeployingUpdate remains true as we are about to restart.
		}
		catch (Throwable ex) {
			Logger.error(this, "DEPLOYING UPDATE FAILED: " + ex, ex);
			System.err.println("UPDATE FAILED: CAUGHT " + ex);
			System.err.println(
					"YOUR NODE DID NOT UPDATE. THIS IS PROBABLY A BUG OR SERIOUS PROBLEM SUCH AS OUT OF MEMORY.");
			System.err.println("Cause of the problem: " + ex);
			ex.printStackTrace();
			this.failUpdate(ex.getMessage());
			String error = this.l10n("updateFailedInternalError", "reason", ex.getMessage());
			this.node.clientCore.alerts
					.register(new SimpleUserAlert(false, error, error, error, FCPUserAlert.CRITICAL_ERROR));
		}
		finally {
			if (started && !success) {
				Bucket toFree = null;
				synchronized (this) {
					this.isDeployingUpdate = false;
					if (this.maybeNextMainJarVersion > this.fetchedMainJarVersion) {
						// A newer version has been fetched in the meantime.
						toFree = this.fetchedMainJarData;
						this.fetchedMainJarVersion = this.maybeNextMainJarVersion;
						this.fetchedMainJarData = this.maybeNextMainJarData;
						this.maybeNextMainJarVersion = -1;
						this.maybeNextMainJarData = null;
					}
				}
				if (toFree != null) {
					toFree.free();
				}
			}
		}
	}

	/**
	 * Use this lock when deploying an update of any kind which will require us to
	 * restart. If the update succeeds, you should call waitForever() if you don't
	 * immediately exit. There could be rather nasty race conditions if we deploy two
	 * updates at once.
	 * @return A mutex for serialising update deployments.
	 */
	static Object deployLock() {
		return deployLock;
	}

	/**
	 * Does not return. Should be called, inside the deployLock(), if you are in a
	 * situation where you've deployed an update but the exit hasn't actually happened
	 * yet.
	 */
	static void waitForever() {
		// noinspection InfiniteLoopStatement
		while (true) {
			System.err.println("Waiting for shutdown after deployed update...");
			try {
				// noinspection BusyWait
				Thread.sleep(60 * 1000);
			}
			catch (InterruptedException ignored) {
				// Ignore.
			}
		}
	}

	/**
	 * Deploy the update. Inner method. Doesn't check anything, just does it.
	 */
	private boolean innerDeployUpdate(MainJarDependenciesChecker.MainJarDependencies deps) {
		System.err.println("Deploying update " + deps.build + " with " + deps.dependencies.size() + " dependencies...");
		// Write the jars, config etc.
		// Then restart

		UpdateDeployContext ctx;
		try {
			ctx = new UpdateDeployContext(deps);
		}
		catch (UpdaterParserException ex) {
			this.failUpdate("Could not determine which jars are in use: " + ex.getMessage());
			return false;
		}

		if (this.writeJars(ctx, deps)) {
			this.restart(ctx);
			return true;
		}
		else {
			if (logMINOR) {
				Logger.minor(this, "Did not write jars");
			}
			return false;
		}
	}

	/**
	 * Write the updated jars, if necessary rewrite the wrapper.conf.
	 * @return True if this part of the update succeeded.
	 */
	private boolean writeJars(UpdateDeployContext ctx, MainJarDependenciesChecker.MainJarDependencies deps) {
		/*
		 * What do we want to do here? 1. If we have a new main jar: - If on Windows,
		 * write it to a new jar file, update the wrapper.conf to point to it. -
		 * Otherwise, write to a new jar file, then move the new jar file over the old jar
		 * file. 2. If the dependencies have changed, we need to update wrapper.conf.
		 */

		boolean writtenNewJar = false;

		boolean tryEasyWay = File.pathSeparatorChar == ':' && (!deps.mustRewriteWrapperConf);

		if (this.hasNewMainJar) {
			File mainJar = ctx.getMainJar();
			File newMainJar = ctx.getNewMainJar();
			File backupJar = ctx.getBackupJar();
			try {
				if (this.writeJar(mainJar, newMainJar, backupJar, this.mainUpdater, "main", tryEasyWay)) {
					writtenNewJar = true;
				}
			}
			catch (UpdateFailedException ex) {
				this.failUpdate(ex.getMessage());
				return false;
			}
		}

		// Dependencies have been written for us already.
		// But we may need to modify wrapper.conf.

		if (!(writtenNewJar || deps.mustRewriteWrapperConf)) {
			return true;
		}
		try {
			ctx.rewriteWrapperConf(writtenNewJar);
		}
		catch (IOException ex) {
			this.failUpdate("Cannot rewrite wrapper.conf: " + ex);
			return false;
		}
		catch (UpdateDeployContext.UpdateCatastropheException ex) {
			this.failUpdate(ex.getMessage());
			this.node.clientCore.alerts.register(new SimpleUserAlert(false, this.l10n("updateCatastropheTitle"),
					ex.getMessage(), this.l10n("updateCatastropheTitle"), FCPUserAlert.CRITICAL_ERROR));
			return false;
		}
		catch (UpdaterParserException ex) {
			this.node.clientCore.alerts
					.register(new SimpleUserAlert(false, this.l10n("updateFailedTitle"), ex.getMessage(),
							this.l10n("updateFailedShort", "reason", ex.getMessage()), FCPUserAlert.CRITICAL_ERROR));
			return false;
		}

		return true;
	}

	/**
	 * Write a jar. Returns true if the caller needs to rewrite the config, false if he
	 * doesn't, or throws if it fails.
	 * @param mainJar The location of the current jar file.
	 * @param newMainJar The location of the new jar file.
	 * @param backupMainJar On Windows, we alternate between freenet.jar and
	 * freenet.jar.new, so we do not need to write a backup - the user can rename between
	 * these two. On Unix, we copy to freenet.jar.bak before updating, in case something
	 * horrible happens.
	 * @param mainUpdater The NodeUpdater for the file in question, so we can ask it to
	 * write the file.
	 * @param name The name of the jar for logging.
	 * @param tryEasyWay If true, attempt to rename the new file directly over the old
	 * one. This avoids the need to rewrite the wrapper config file.
	 * @return True if the caller needs to rewrite the config, false if he doesn't
	 * (because easy way worked).
	 * @throws UpdateFailedException If something breaks.
	 */
	private boolean writeJar(File mainJar, File newMainJar, File backupMainJar, NodeUpdater mainUpdater, String name,
			boolean tryEasyWay) throws UpdateFailedException {
		boolean writtenToTempFile = false;
		try {
			if (newMainJar.exists()) {
				if (!newMainJar.delete()) {
					if (newMainJar.exists()) {
						System.err.println("Cannot write to preferred new jar location " + newMainJar);
						if (tryEasyWay) {
							try {
								newMainJar = File.createTempFile("freenet", ".jar", mainJar.getParentFile());
							}
							catch (IOException ex) {
								throw new UpdateFailedException(
										"Cannot write to any other location either - disk full? " + ex);
							}
							// Try writing to it
							try {
								this.writeJarTo(newMainJar);
								writtenToTempFile = true;
							}
							catch (IOException ex) {
								// noinspection ResultOfMethodCallIgnored
								newMainJar.delete();
								throw new UpdateFailedException("Cannot write new jar - disk full? " + ex);
							}
						}
						else {
							// Try writing it to the new one even though we
							// can't delete it.
							this.writeJarTo(newMainJar);
						}
					}
					else {
						this.writeJarTo(newMainJar);
					}
				}
				else {
					if (logMINOR) {
						Logger.minor(NodeUpdateManager.class, "Deleted old jar " + newMainJar);
					}
					this.writeJarTo(newMainJar);
				}
			}
			else {
				this.writeJarTo(newMainJar);
			}
			System.out.println("Written new main jar to " + newMainJar);
		}
		catch (IOException ex) {
			throw new UpdateFailedException(
					"Cannot update: Cannot write to " + (tryEasyWay ? " temp file " : "new jar ") + newMainJar);
		}

		if (tryEasyWay) {
			// Do it the easy way. Just rewrite the main jar.
			// noinspection ResultOfMethodCallIgnored
			backupMainJar.delete();
			if (BucketFileUtil.copyFile(mainJar, backupMainJar)) {
				System.err.println("Written backup of current main jar to " + backupMainJar
						+ " (if freenet fails to start up try renaming " + backupMainJar + " over " + mainJar);
			}
			if (!newMainJar.renameTo(mainJar)) {
				Logger.error(NodeUpdateManager.class,
						"Cannot rename temp file " + newMainJar + " over original jar " + mainJar);
				if (writtenToTempFile) {
					// Fail the update - otherwise we will leak disk space
					// noinspection ResultOfMethodCallIgnored
					newMainJar.delete();
					throw new UpdateFailedException(
							"Cannot write to preferred new jar location and cannot rename temp file over old jar, update failed");
				}
				// Try the hard way
			}
			else {
				System.err.println("Completed writing new Freenet jar to " + mainJar + ".");
				return false;
			}
		}
		System.err.println("Rewriting wrapper.conf to point to " + newMainJar + " rather than " + mainJar
				+ " (if Freenet fails to start after the update you could try changing wrapper.conf to use the old jar)");
		return true;
	}

	public void writeJarTo(File fNew) throws IOException {
		if (!fNew.delete() && fNew.exists()) {
			System.err.println("Can't delete " + fNew + "!");
		}

		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(fNew);

			BucketTools.copyTo(this.fetchedMainJarData, fos, -1);

			fos.flush();
		}
		finally {
			Closer.close(fos);
		}
	}

	/** Restart the node. Does not return. */
	private void restart(UpdateDeployContext ctx) {
		if (logMINOR) {
			Logger.minor(this, "Restarting...");
		}
		this.node.getNodeStarter().restart();
		try {
			Thread.sleep(TimeUnit.MINUTES.toMillis(5));
		}
		catch (InterruptedException ignored) {
			// Break
		} // in case it's still restarting
		System.err.println("Failed to restart. Exiting, please restart the node.");
		System.exit(NodeInitException.EXIT_RESTART_FAILED);
	}

	private void failUpdate(String reason) {
		Logger.error(this, "Update failed: " + reason);
		System.err.println("Update failed: " + reason);
		this.killUpdateAlerts();
		this.node.clientCore.alerts.register(
				new SimpleUserAlert(true, this.l10n("updateFailedTitle"), this.l10n("updateFailed", "reason", reason),
						this.l10n("updateFailedShort", "reason", reason), FCPUserAlert.CRITICAL_ERROR));
	}

	private String l10n(String key) {
		return NodeL10n.getBase().getString("NodeUpdateManager." + key);
	}

	private String l10n(String key, String pattern, String value) {
		return NodeL10n.getBase().getString("NodeUpdateManager." + key, pattern, value);
	}

	/**
	 * Called when a new jar has been downloaded. The caller should process the
	 * dependencies *AFTER* this method has completed, and then call
	 * onDependenciesReady().
	 * @param fetched The build number we have fetched.
	 * @param result The actual data.
	 */
	void onDownloadedNewJar(Bucket result, int fetched, File savedBlob) {
		Bucket delete1 = null;
		Bucket delete2 = null;
		synchronized (this) {
			if (fetched > Version.buildNumber()) {
				this.hasNewMainJar = true;
				this.startedFetchingNextMainJar = -1;
				this.gotJarTime = System.currentTimeMillis();
				if (logMINOR) {
					Logger.minor(this, "Got main jar: " + fetched);
				}
			}
			if (!this.isDeployingUpdate) {
				delete1 = this.fetchedMainJarData;
				this.fetchedMainJarVersion = fetched;
				this.fetchedMainJarData = result;
				if (fetched == Version.buildNumber()) {
					if (savedBlob != null) {
						this.currentVersionBlobFile = savedBlob;
					}
					else {
						Logger.error(this, "No blob file for latest version?!", new Exception("error"));
					}
				}
			}
			else {
				delete2 = this.maybeNextMainJarData;
				this.maybeNextMainJarVersion = fetched;
				this.maybeNextMainJarData = result;
				System.out.println("Already deploying update, not using new main jar #" + fetched);
			}
		}
		if (delete1 != null) {
			delete1.free();
		}
		if (delete2 != null) {
			delete2.free();
		}
		// We cannot deploy yet, we must wait for the dependencies check.
	}

	/**
	 * Called when the NodeUpdater starts to fetch a new version of the jar.
	 */
	void onStartFetching() {
		long now = System.currentTimeMillis();
		synchronized (this) {
			this.startedFetchingNextMainJar = now;
		}
	}

	private boolean disabledNotBlown;

	/**
	 * @param msg
	 * @param disabledNotBlown If true, the auto-updating system is broken, and should be
	 * disabled, but the problem *could* be local e.g. out of disk space and a node sends
	 * us a revocation certificate.
	 */
	public void blow(String msg, boolean disabledNotBlown) {
		NodeUpdater main;
		synchronized (this) {
			if (this.hasBeenBlown) {
				if (this.disabledNotBlown && !disabledNotBlown) {
					disabledNotBlown = true;
				}
				Logger.error(this, "The key has ALREADY been marked as blown! Message was " + this.revocationMessage
						+ " new message " + msg);
				return;
			}
			else {
				this.revocationMessage = msg;
				this.hasBeenBlown = true;
				this.disabledNotBlown = disabledNotBlown;
				// We must get to the lower part, and show the user the message
				try {
					if (disabledNotBlown) {
						System.err.println("THE AUTO-UPDATING SYSTEM HAS BEEN DISABLED!");
						System.err.println(
								"We do not know whether this is a local problem or the auto-update system has in fact been compromised. What we do know:\n"
										+ this.revocationMessage);
					}
					else {
						System.err.println("THE AUTO-UPDATING SYSTEM HAS BEEN COMPROMISED!");
						System.err.println("The auto-updating system revocation key has been inserted. It says: "
								+ this.revocationMessage);
					}
				}
				catch (Throwable ex) {
					try {
						Logger.error(this, "Caught " + ex, ex);
					}
					catch (Throwable ignored) {
					}
				}
			}
			main = this.mainUpdater;
			if (main != null) {
				main.preKill();
			}
			this.mainUpdater = null;
		}
		if (main != null) {
			main.kill();
		}
		if (this.revocationAlert == null) {
			this.revocationAlert = new RevocationKeyFoundUserAlert(msg, disabledNotBlown);
			this.node.clientCore.alerts.register(this.revocationAlert);
			// we don't need to advertize updates : we are not going to do them
			this.killUpdateAlerts();
		}
		this.uom.killAlert();
		this.broadcastUOMAnnouncesOld();
		this.broadcastUOMAnnouncesNew();
	}

	/**
	 * Kill all UserAlerts asking the user whether he wants to update.
	 */
	private void killUpdateAlerts() {
		this.node.clientCore.alerts.unregister(this.alert);
	}

	/** Called when the RevocationChecker has got 3 DNFs on the revocation key */
	public void noRevocationFound() {
		this.deployUpdate(); // May have been waiting for the revocation.
		this.deployPluginUpdates();
		// If we're still here, we didn't update.
		this.broadcastUOMAnnouncesNew();
		this.node.ticker.queueTimedJob(() -> NodeUpdateManager.this.revocationChecker.start(false),
				this.node.random.nextInt((int) TimeUnit.DAYS.toMillis(1)));
	}

	private void deployPluginUpdates() {
		PluginJarUpdater[] updaters = null;
		synchronized (this) {
			if (this.pluginUpdaters != null) {
				updaters = this.pluginUpdaters.values().toArray(new PluginJarUpdater[0]);
			}
		}
		boolean restartRevocationFetcher = false;
		if (updaters != null) {
			for (PluginJarUpdater u : updaters) {
				if (u.onNoRevocation()) {
					restartRevocationFetcher = true;
				}
			}
		}
		if (restartRevocationFetcher) {
			this.revocationChecker.start(true, true);
		}
	}

	public void arm() {
		this.armed = true;
		OpennetManager om = this.node.getOpennet();
		if (om != null) {
			if (om.waitingForUpdater()) {
				synchronized (this) {
					// Reannounce and count it from now.
					if (this.gotJarTime > 0) {
						this.gotJarTime = System.currentTimeMillis();
					}
				}
				om.reannounce();
			}
		}
		this.deployOffThread(0, false);
	}

	void deployOffThread(long delay, final boolean announce) {
		this.node.ticker.queueTimedJob(new Runnable() {
			@Override
			public void run() {
				if (announce) {
					NodeUpdateManager.this.maybeBroadcastUOMAnnouncesNew();
				}
				if (logMINOR) {
					Logger.minor(this, "Running deployOffThread");
				}
				NodeUpdateManager.this.deployUpdate();
				if (logMINOR) {
					Logger.minor(this, "Run deployOffThread");
				}
			}
		}, delay);
	}

	protected void maybeBroadcastUOMAnnouncesNew() {
		if (logMINOR) {
			Logger.minor(this, "Maybe broadcast UOM announces new");
		}
		synchronized (NodeUpdateManager.this) {
			if (this.hasBeenBlown) {
				return;
			}
			if (this.peersSayBlown) {
				return;
			}
		}
		if (logMINOR) {
			Logger.minor(this, "Maybe broadcast UOM announces new (2)");
		}
		// If the node has no peers, noRevocationFound will never be called.
		this.broadcastUOMAnnouncesNew();
	}

	/**
	 * Has the private key been revoked?
	 */
	public boolean isBlown() {
		return this.hasBeenBlown;
	}

	public boolean hasNewMainJar() {
		return this.hasNewMainJar;
	}

	/**
	 * What version has been fetched?
	 *
	 * This includes jar's fetched via UOM, because the UOM code feeds its results through
	 * the mainUpdater.
	 */
	public int newMainJarVersion() {
		if (this.mainUpdater == null) {
			return -1;
		}
		return this.mainUpdater.getFetchedVersion();
	}

	public boolean fetchingNewMainJar() {
		return (this.mainUpdater != null && this.mainUpdater.isFetching());
	}

	public int fetchingNewMainJarVersion() {
		if (this.mainUpdater == null) {
			return -1;
		}
		return this.mainUpdater.fetchingVersion();
	}

	public boolean inFinalCheck() {
		return this.isReadyToDeployUpdate(true) && !this.isReadyToDeployUpdate(false);
	}

	public int getRevocationDNFCounter() {
		return this.revocationChecker.getRevocationDNFCounter();
	}

	/**
	 * What version is the node currently running?
	 */
	public int getMainVersion() {
		return Version.buildNumber();
	}

	public int getExtVersion() {
		return NodeStarter.extBuildNumber;
	}

	public boolean isArmed() {
		return this.armed || this.isAutoUpdateAllowed;
	}

	/**
	 * Is the node able to update as soon as the revocation fetch has been completed?
	 */
	public boolean canUpdateNow() {
		return this.isReadyToDeployUpdate(true);
	}

	/**
	 * Is the node able to update *immediately*? (i.e. not only is it ready in every other
	 * sense, but also a revocation fetch has completed recently enough not to need
	 * another one)
	 */
	public boolean canUpdateImmediately() {
		return this.isReadyToDeployUpdate(false);
	}

	/**
	 * Called when a peer indicates in its UOMAnnounce that it has fetched the revocation
	 * key (or failed to do so in a way suggesting that somebody knows the key).
	 */
	void peerClaimsKeyBlown() {
		// Note that UpdateOverMandatoryManager manages the list of peers who
		// think this.
		// All we have to do is cancel the update.

		this.peersSayBlown = true;
	}

	/** Called inside locks, so don't lock anything */
	public void notPeerClaimsKeyBlown() {
		this.peersSayBlown = false;
		this.node.executor.execute(() -> {
			if (NodeUpdateManager.this.isReadyToDeployUpdate(false)) {
				NodeUpdateManager.this.deployUpdate();
			}
		}, "Check for updates");
		this.node.getTicker().queueTimedJob(NodeUpdateManager.this::maybeBroadcastUOMAnnouncesNew,
				REVOCATION_FETCH_TIMEOUT);
	}

	boolean peersSayBlown() {
		return this.peersSayBlown;
	}

	public File getMainBlob(int version) {
		NodeUpdater updater;
		synchronized (this) {
			if (this.hasBeenBlown) {
				return null;
			}
			updater = this.mainUpdater;
			if (updater == null) {
				return null;
			}
		}
		return updater.getBlobFile(version);
	}

	public synchronized long timeRemainingOnCheck() {
		long now = System.currentTimeMillis();
		return Math.max(0, REVOCATION_FETCH_TIMEOUT - (now - this.gotJarTime));
	}

	final ByteCounter ctr = new ByteCounter() {

		@Override
		public void receivedBytes(int x) {
			// FIXME
		}

		@Override
		public void sentBytes(int x) {
			NodeUpdateManager.this.node.nodeStats.reportUOMBytesSent(x);
		}

		@Override
		public void sentPayload(int x) {
			// Ignore. It will be reported to sentBytes() as well.
		}

	};

	public void disableThisSession() {
		this.disabledThisSession = true;
	}

	protected long getStartedFetchingNextMainJarTimestamp() {
		return this.startedFetchingNextMainJar;
	}

	public void disconnected(PeerNode pn) {
		this.uom.disconnected(pn);
	}

	public void deployPlugin(String fn) throws IOException {
		PluginJarUpdater updater;
		synchronized (this) {
			if (this.hasBeenBlown) {
				Logger.error(this, "Not deploying update for " + fn + " because revocation key has been blown!");
				return;
			}
			updater = this.pluginUpdaters.get(fn);
		}
		updater.writeJar();
	}

	public void deployPluginWhenReady(String fn) {
		PluginJarUpdater updater;
		synchronized (this) {
			if (this.hasBeenBlown) {
				Logger.error(this, "Not deploying update for " + fn + " because revocation key has been blown!");
				return;
			}
			updater = this.pluginUpdaters.get(fn);
		}
		boolean wasRunning = this.revocationChecker.start(true, true);
		updater.arm(wasRunning);
	}

	public boolean dontAllowUOM() {
		if (this.node.isOpennetEnabled() && this.node.wantAnonAuth(true)) {
			// We are a seednode.
			// Normally this means we won't send UOM.
			// However, if something breaks severely, we need an escape route.
			return this.node.getUptime() <= TimeUnit.MINUTES.toMillis(5)
					|| this.node.peers.countCompatibleRealPeers() != 0;
		}
		return false;
	}

	public boolean fetchingFromUOM() {
		return this.uom.isFetchingMain();
	}

	/**
	 * Called when the dependencies have been verified and/or downloaded, and we can
	 * upgrade to the new build without dependency issues.
	 * @param deps The dependencies object. Used to rewrite wrapper.conf if necessary.
	 * Also contains the build number.
	 */
	public void onDependenciesReady(MainJarDependenciesChecker.MainJarDependencies deps) {
		synchronized (this) {
			this.latestMainJarDependencies = deps;
			this.dependenciesValidForBuild = deps.build;
		}
		this.revocationChecker.start(true);
		// Deploy immediately if the revocation checker has already reported in but we
		// were waiting for deps.
		// Otherwise wait for the revocation checker.
		this.deployOffThread(0, true);
	}

	public File getTransitionMainBlob() {
		return this.transitionMainJarFetcher.getBlobFile();
	}

	/** Show the progress of individual dependencies if possible */
	public void renderProgress(HTMLNode alertNode) {
		MainJarUpdater m;
		synchronized (this) {
			if (this.fetchedMainJarData == null) {
				return;
			}
			m = this.mainUpdater;
			if (m == null) {
				return;
			}
		}
		m.renderProperties(alertNode);
	}

	public boolean brokenDependencies() {
		MainJarUpdater m;
		synchronized (this) {
			m = this.mainUpdater;
			if (m == null) {
				return false;
			}
		}
		return m.brokenDependencies();
	}

	public void onStartFetchingUOM() {
		MainJarUpdater m;
		synchronized (this) {
			m = this.mainUpdater;
			if (m == null) {
				return;
			}
		}
		m.onStartFetchingUOM();
	}

	public synchronized File getCurrentVersionBlobFile() {
		if (this.hasNewMainJar) {
			return null;
		}
		if (this.isDeployingUpdate) {
			return null;
		}
		if (this.fetchedMainJarVersion != Version.buildNumber()) {
			return null;
		}
		return this.currentVersionBlobFile;
	}

	MainJarUpdater getMainUpdater() {
		return this.mainUpdater;
	}

	class SimplePuller implements ClientGetCallback {

		final FreenetURI freenetURI;

		final String filename;

		final ProgramDirectory directory;

		SimplePuller(FreenetURI freenetURI, NodeFile file) {
			this(freenetURI, file.getFilename(), file.getProgramDirectory(NodeUpdateManager.this.node));
		}

		private SimplePuller(FreenetURI freenetURI, String filename, ProgramDirectory directory) {
			this.freenetURI = freenetURI;
			this.filename = filename;
			this.directory = directory;
		}

		void start(short priority, long maxSize) {
			HighLevelSimpleClient hlsc = NodeUpdateManager.this.node.clientCore.makeClient(priority, false, false);
			FetchContext context = hlsc.getFetchContext();
			context.maxNonSplitfileRetries = -1;
			context.maxSplitfileBlockRetries = -1;
			context.maxTempLength = maxSize;
			context.maxOutputLength = maxSize;
			ClientGetter get = new ClientGetter(this, this.freenetURI, context, priority, null, null, null);
			try {
				NodeUpdateManager.this.node.clientCore.clientContext.start(get);
			}
			catch (PersistenceDisabledException ignored) {
				// Impossible
			}
			catch (FetchException ex) {
				this.onFailure(ex, null);
			}
		}

		@Override
		public void onFailure(FetchException e, ClientGetter state) {
			System.err.println("Failed to fetch " + this.filename + " : " + e);
		}

		@Override
		public void onSuccess(FetchResult result, ClientGetter state) {
			File temp;
			FileOutputStream fos = null;
			try {
				temp = File.createTempFile(this.filename, ".tmp", this.directory.dir());
				temp.deleteOnExit();
				fos = new FileOutputStream(temp);
				BucketTools.copyTo(result.asBucket(), fos, -1);
				fos.close();
				fos = null;
				for (int i = 0; i < 10; i++) {
					// FIXME add a callback in case it's being used on Windows.
					if (FileUtil.renameTo(temp, this.directory.file(this.filename))) {
						System.out.println(
								"Successfully fetched " + this.filename + " for version " + Version.buildNumber());
						break;
					}
					else {
						System.out.println("Failed to rename " + temp + " to " + this.filename
								+ " after fetching it from Freenet.");
						try {
							Thread.sleep(TimeUnit.SECONDS.toMillis(1) + NodeUpdateManager.this.node.fastWeakRandom
									.nextInt((int) TimeUnit.SECONDS.toMillis(
											(long) Math.min(Math.pow(2, i), TimeUnit.MINUTES.toSeconds(15)))));
						}
						catch (InterruptedException ignored) {
							// Ignore
						}
					}
				}
				// noinspection ResultOfMethodCallIgnored
				temp.delete();
			}
			catch (IOException ex) {
				System.err.println("Fetched but failed to write out " + this.filename
						+ " - please check that the node has permissions to write in " + this.directory.dir()
						+ " and particularly the file " + this.filename);
				System.err.println("The error was: " + ex);
				ex.printStackTrace();
			}
			finally {
				BucketCloser.close(fos);
				BucketCloser.close(result.asBucket());
			}
		}

		@Override
		public void onResume(ClientContext context) {
			// Not persistent.
		}

		@Override
		public RequestClient getRequestClient() {
			return NodeUpdateManager.this.node.nonPersistentClientBulk;
		}

	}

	private static class UpdateFailedException extends Exception {

		UpdateFailedException(String message) {
			super(message);
		}

	}

	// Config callbacks

	class UpdaterEnabledCallback extends BooleanCallback {

		@Override
		public Boolean get() {
			if (NodeUpdateManager.this.isEnabled()) {
				return true;
			}
			synchronized (NodeUpdateManager.this) {
				if (NodeUpdateManager.this.disabledNotBlown) {
					return true;
				}
			}
			return false;
		}

		@Override
		public void set(Boolean val) throws InvalidConfigValueException {
			NodeUpdateManager.this.enable(val);
		}

	}

	class AutoUpdateAllowedCallback extends BooleanCallback {

		@Override
		public Boolean get() {
			return NodeUpdateManager.this.isAutoUpdateAllowed();
		}

		@Override
		public void set(Boolean val) throws InvalidConfigValueException {
			NodeUpdateManager.this.setAutoUpdateAllowed(val);
		}

	}

	class UpdateURICallback extends StringCallback {

		@Override
		public String get() {
			return NodeUpdateManager.this.getURI().toString(false, false);
		}

		@Override
		public void set(String val) throws InvalidConfigValueException {
			FreenetURI uri;
			try {
				uri = new FreenetURI(val);
			}
			catch (MalformedURLException ex) {
				throw new InvalidConfigValueException(
						NodeUpdateManager.this.l10n("invalidUpdateURI", "error", ex.getLocalizedMessage()));
			}
			if (uri.hasMetaStrings()) {
				throw new InvalidConfigValueException(NodeUpdateManager.this.l10n("updateURIMustHaveNoMetaStrings"));
			}
			if (!uri.isUSK()) {
				throw new InvalidConfigValueException(NodeUpdateManager.this.l10n("updateURIMustBeAUSK"));
			}
			NodeUpdateManager.this.setURI(uri);
		}

	}

	public class UpdateRevocationURICallback extends StringCallback {

		@Override
		public String get() {
			return NodeUpdateManager.this.getRevocationURI().toString(false, false);
		}

		@Override
		public void set(String val) throws InvalidConfigValueException {
			FreenetURI uri;
			try {
				uri = new FreenetURI(val);
			}
			catch (MalformedURLException ex) {
				throw new InvalidConfigValueException(
						NodeUpdateManager.this.l10n("invalidRevocationURI", "error", ex.getLocalizedMessage()));
			}
			NodeUpdateManager.this.setRevocationURI(uri);
		}

	}

}
