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

package freenet.node;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;

import freenet.config.BooleanCallback;
import freenet.config.EnumerableOptionCallback;
import freenet.config.FilePersistentConfig;
import freenet.config.IntCallback;
import freenet.config.InvalidConfigValueException;
import freenet.config.LongCallback;
import freenet.config.NodeNeedRestartException;
import freenet.config.OptionFormatException;
import freenet.config.StringCallback;
import freenet.config.SubConfig;
import freenet.nodelogger.Logger;
import freenet.support.Dimension;
import freenet.support.Executor;
import freenet.support.FileLoggerHook;
import freenet.support.FileLoggerHook.IntervalParseException;
import freenet.support.Logger.LogLevel;
import freenet.support.LoggerHook;
import freenet.support.LoggerHook.InvalidThresholdException;
import freenet.support.LoggerHookChain;

public class LoggingConfigHandler {

	protected static final String LOG_PREFIX = "freenet";

	private final SubConfig config;

	private FileLoggerHook fileLoggerHook;

	private File logDir;

	private long maxZippedLogsSize;

	private String logRotateInterval;

	private long maxCachedLogBytes;

	private int maxCachedLogLines;

	private long maxBacklogNotBusy;

	private final Executor executor;

	public LoggingConfigHandler(SubConfig loggingConfig, Executor executor) throws InvalidConfigValueException {
		this.config = loggingConfig;
		this.executor = executor;

		loggingConfig.register("enabled", true, 1, true, false, "LogConfigHandler.enabled",
				"LogConfigHandler.enabledLong", new BooleanCallback() {
					@Override
					public Boolean get() {
						return LoggingConfigHandler.this.fileLoggerHook != null;
					}

					@Override
					public void set(Boolean val) {
						if (val == (LoggingConfigHandler.this.fileLoggerHook != null)) {
							return;
						}
						if (!val) {
							LoggingConfigHandler.this.disableLogger();
						}
						else {
							LoggingConfigHandler.this.enableLogger();
						}
					}
				});

		boolean loggingEnabled = loggingConfig.getBoolean("enabled");

		// Default logger dirname is the dir where freenet.ini locates
		String defaultLogDir;
		if (this.config.config instanceof FilePersistentConfig filePersistentConfig) {
			defaultLogDir = Paths.get(filePersistentConfig.getConfigFile().getParent(), "logs").toAbsolutePath()
					.toString();
		}
		else {
			defaultLogDir = "logs";
		}

		loggingConfig.register("dirname", defaultLogDir, 2, true, false, "LogConfigHandler.dirName",
				"LogConfigHandler.dirNameLong", new StringCallback() {
					@Override
					public String get() {
						return LoggingConfigHandler.this.logDir.getPath();
					}

					@Override
					public void set(String val) throws InvalidConfigValueException {
						File f = new File(val);
						if (f.equals(LoggingConfigHandler.this.logDir)) {
							return;
						}
						LoggingConfigHandler.this.preSetLogDir(f);
						// Still here
						if (LoggingConfigHandler.this.fileLoggerHook == null) {
							LoggingConfigHandler.this.logDir = f;
						}
						else {
							// Discard old data
							LoggingConfigHandler.this.fileLoggerHook
									.switchBaseFilename(f.getPath() + File.separator + LOG_PREFIX);
							LoggingConfigHandler.this.logDir = f;
							new Deleter(LoggingConfigHandler.this.logDir).start();
						}
					}
				});

		this.logDir = new File(this.config.getString("dirname"));
		if (loggingEnabled) {
			this.preSetLogDir(this.logDir);
		}
		// => enableLogger must run preSetLogDir

		// max space used by zipped logs

		this.config.register("maxZippedLogsSize", "10M", 3, true, true, "LogConfigHandler.maxZippedLogsSize",
				"LogConfigHandler.maxZippedLogsSizeLong", new LongCallback() {
					@Override
					public Long get() {
						return LoggingConfigHandler.this.maxZippedLogsSize;
					}

					@Override
					public void set(Long val) {
						if (val < 0) {
							val = 0L;
						}
						LoggingConfigHandler.this.maxZippedLogsSize = val;
						if (LoggingConfigHandler.this.fileLoggerHook != null) {
							LoggingConfigHandler.this.fileLoggerHook.setMaxOldLogsSize(val);
						}
					}
				}, true);

		this.maxZippedLogsSize = this.config.getLong("maxZippedLogsSize");

		// These two are forced below, so we don't need to check them now

		// priority

		// Node must override this to minor on testnet.
		this.config.register("priority", "warning", 4, false, false, "LogConfigHandler.minLoggingPriority",
				"LogConfigHandler.minLoggingPriorityLong", new PriorityCallback());

		// detailed priority

		this.config.register("priorityDetail", "", 5, true, false, "LogConfigHandler.detailedPriorityThreshold",
				"LogConfigHandler.detailedPriorityThresholdLong", new StringCallback() {
					@Override
					public String get() {
						LoggerHookChain chain = Logger.getChain();
						return chain.getDetailedThresholds();
					}

					@Override
					public void set(String val) throws InvalidConfigValueException {
						LoggerHookChain chain = Logger.getChain();
						try {
							chain.setDetailedThresholds(val);
						}
						catch (InvalidThresholdException ex) {
							throw new InvalidConfigValueException(ex.getMessage());
						}
					}
				});

		// interval

		this.config.register("interval", "1HOUR", 5, true, false, "LogConfigHandler.rotationInterval",
				"LogConfigHandler.rotationIntervalLong", new StringCallback() {
					@Override
					public String get() {
						return LoggingConfigHandler.this.logRotateInterval;
					}

					@Override
					public void set(String val) throws InvalidConfigValueException {
						if (val.equals(LoggingConfigHandler.this.logRotateInterval)) {
							return;
						}
						if (LoggingConfigHandler.this.fileLoggerHook != null) {
							try {
								LoggingConfigHandler.this.fileLoggerHook.setInterval(val);
							}
							catch (FileLoggerHook.IntervalParseException ex) {
								throw new OptionFormatException(ex.getMessage());
							}
						}
						LoggingConfigHandler.this.logRotateInterval = val;
					}
				});

		this.logRotateInterval = this.config.getString("interval");

		// max cached bytes in RAM
		this.config.register("maxCachedBytes", "1M", 6, true, false, "LogConfigHandler.maxCachedBytes",
				"LogConfigHandler.maxCachedBytesLong", new LongCallback() {
					@Override
					public Long get() {
						return LoggingConfigHandler.this.maxCachedLogBytes;
					}

					@Override
					public void set(Long val) {
						if (val < 0) {
							val = 0L;
						}
						if (val == LoggingConfigHandler.this.maxCachedLogBytes) {
							return;
						}
						LoggingConfigHandler.this.maxCachedLogBytes = val;
						if (LoggingConfigHandler.this.fileLoggerHook != null) {
							LoggingConfigHandler.this.fileLoggerHook.setMaxListBytes(val);
						}
					}
				}, true);

		this.maxCachedLogBytes = this.config.getLong("maxCachedBytes");

		// max cached lines in RAM
		this.config.register("maxCachedLines", "10k", 7, true, false, "LogConfigHandler.maxCachedLines",
				"LogConfigHandler.maxCachedLinesLong", new IntCallback() {
					@Override
					public Integer get() {
						return LoggingConfigHandler.this.maxCachedLogLines;
					}

					@Override
					public void set(Integer val) throws NodeNeedRestartException {
						if (val < 0) {
							val = 0;
						}
						if (val == LoggingConfigHandler.this.maxCachedLogLines) {
							return;
						}
						LoggingConfigHandler.this.maxCachedLogLines = val;
						throw new NodeNeedRestartException("logger.maxCachedLogLines");
					}
				}, Dimension.NOT);

		this.maxCachedLogLines = this.config.getInt("maxCachedLines");

		this.config.register("maxBacklogNotBusy", "60000", 8, true, false, "LogConfigHandler.maxBacklogNotBusy",
				"LogConfigHandler.maxBacklogNotBusy", new LongCallback() {

					@Override
					public Long get() {
						return LoggingConfigHandler.this.maxBacklogNotBusy;
					}

					@Override
					public void set(Long val) throws InvalidConfigValueException {
						if (val < 0) {
							throw new InvalidConfigValueException("Must be >= 0");
						}
						if (val == LoggingConfigHandler.this.maxBacklogNotBusy) {
							return;
						}
						LoggingConfigHandler.this.maxBacklogNotBusy = val;
						if (LoggingConfigHandler.this.fileLoggerHook != null) {
							LoggingConfigHandler.this.fileLoggerHook.setMaxBacklogNotBusy(val);
						}
					}

				}, false);

		this.maxBacklogNotBusy = this.config.getLong("maxBacklogNotBusy");

		if (loggingEnabled) {
			this.enableLogger();
		}
		this.config.finishedInitialization();
	}

	private final Object enableLoggerLock = new Object();

	/**
	 * Turn on the logger.
	 */
	private void enableLogger() {
		try {
			this.preSetLogDir(this.logDir);
		}
		catch (InvalidConfigValueException e3) {
			System.err.println("Cannot set log dir: " + this.logDir + ": " + e3);
			e3.printStackTrace();
		}
		synchronized (this.enableLoggerLock) {
			if (this.fileLoggerHook != null) {
				return;
			}
			Logger.setupChain();
			try {
				this.config.forceUpdate("priority");
				this.config.forceUpdate("priorityDetail");
			}
			catch (InvalidConfigValueException e2) {
				System.err.println("Invalid config value for logger.priority in config file: "
						+ this.config.getString("priority"));
				// Leave it at the default.
			}
			catch (NodeNeedRestartException ex) {
				// impossible
				System.err.println("impossible NodeNeedRestartException for logger.priority in config file: "
						+ this.config.getString("priority"));
			}
			FileLoggerHook hook;
			try {
				hook = new FileLoggerHook(true, new File(this.logDir, LOG_PREFIX).getAbsolutePath(), "d (c, t, p): m",
						"MMM dd, yyyy HH:mm:ss:SSS", this.logRotateInterval,
						LogLevel.DEBUG /* filtered by chain */, false, true,
						this.maxZippedLogsSize /* 1GB of old compressed logfiles */, this.maxCachedLogLines);
			}
			catch (IOException ex) {
				System.err.println("CANNOT START LOGGER: " + ex.getMessage());
				return;
			}
			catch (IntervalParseException ex) {
				System.err.println("INVALID LOGGING INTERVAL: " + ex.getMessage());
				this.logRotateInterval = "5MINUTE";
				try {
					hook = new FileLoggerHook(true, new File(this.logDir, LOG_PREFIX).getAbsolutePath(),
							"d (c, t, p): m", "MMM dd, yyyy HH:mm:ss:SSS", this.logRotateInterval,
							LogLevel.DEBUG /* filtered by chain */, false, true,
							this.maxZippedLogsSize /* 1GB of old compressed logfiles */, this.maxCachedLogLines);
				}
				catch (IntervalParseException e1) {
					System.err.println("CANNOT START LOGGER: IMPOSSIBLE: " + e1.getMessage());
					return;
				}
				catch (IOException e1) {
					System.err.println("CANNOT START LOGGER: " + e1.getMessage());
					return;
				}
			}
			hook.setMaxListBytes(this.maxCachedLogBytes);
			hook.setMaxBacklogNotBusy(this.maxBacklogNotBusy);
			this.fileLoggerHook = hook;
			Logger.globalAddHook(hook);
			hook.start();
		}
	}

	protected void disableLogger() {
		synchronized (this.enableLoggerLock) {
			if (this.fileLoggerHook == null) {
				return;
			}
			FileLoggerHook hook = this.fileLoggerHook;
			Logger.globalRemoveHook(hook);
			hook.close();
			this.fileLoggerHook = null;
			Logger.destroyChainIfEmpty();
		}
	}

	protected void preSetLogDir(File f) throws InvalidConfigValueException {
		boolean exists = f.exists();
		if (exists && !f.isDirectory()) {
			throw new InvalidConfigValueException("Cannot overwrite a file with a log directory");
		}
		if (!exists) {
			if (!f.mkdir()) {
				throw new InvalidConfigValueException("Cannot create log directory");
			}
		}
	}

	public FileLoggerHook getFileLoggerHook() {
		return this.fileLoggerHook;
	}

	public void forceEnableLogging() {
		this.enableLogger();
	}

	public long getMaxZippedLogFiles() {
		return this.maxZippedLogsSize;
	}

	public void setMaxZippedLogFiles(String maxSizeAsString)
			throws InvalidConfigValueException, NodeNeedRestartException {
		this.config.set("maxZippedLogsSize", maxSizeAsString);
	}

	class Deleter implements Runnable {

		File logDir;

		Deleter(File logDir) {
			this.logDir = logDir;
		}

		void start() {
			LoggingConfigHandler.this.executor.execute(this, "Old log directory " + this.logDir + " deleter");
		}

		@Override
		public void run() {
			Logger.OSThread.logPID(this);
			LoggingConfigHandler.this.fileLoggerHook.waitForSwitch();
			this.delete(this.logDir);
		}

		/**
		 * @return true if we can't delete due to presence of non-Freenet files
		 */
		private boolean delete(File dir) {
			boolean failed = false;
			File[] files = dir.listFiles();
			if (files == null) {
				Logger.error(this, "Unable to list files in dir: " + dir.getName());
				return false;
			}
			for (File f : files) {
				String s = f.getName();
				if (s.startsWith("freenet-") && (s.contains(".log"))) {
					if (f.isFile()) {
						if (!f.delete()) {
							failed = true;
						}
					}
					else if (f.isDirectory()) {
						if (this.delete(f)) {
							failed = true;
						}
					}
				}
				else {
					failed = true;
				}
			}
			if (!failed) {
				failed = !(dir.delete());
			}
			return failed;
		}

	}

	private static class PriorityCallback extends StringCallback implements EnumerableOptionCallback {

		@Override
		public String get() {
			LoggerHookChain chain = Logger.getChain();
			return chain.getThresholdNew().name();
		}

		@Override
		public void set(String val) throws InvalidConfigValueException {
			LoggerHookChain chain = Logger.getChain();
			try {
				chain.setThreshold(val);
			}
			catch (LoggerHook.InvalidThresholdException ex) {
				throw new OptionFormatException(ex.getMessage());
			}
		}

		@Override
		public String[] getPossibleValues() {
			LogLevel[] priorities = LogLevel.values();
			ArrayList<String> values = new ArrayList<>(priorities.length + 1);
			for (LogLevel p : priorities) {
				values.add(p.name());
			}

			return values.toArray(new String[0]);
		}

	}

}
