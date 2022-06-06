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

package freenet.config;

import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.SimpleFieldSet;
import freenet.support.io.Closer;
import freenet.support.io.FileUtil;
import freenet.support.io.LineReadingInputStream;

/**
 * Global Config object which persists to a file.
 *
 * Reads the config file into a SimpleFieldSet when created. During init, SubConfig's are
 * registered, and fed the relevant parts of the SFS. Once initialization has finished, we
 * check whether there are any options remaining. If so, we complain about them. And then
 * we write the config file back out.
 */
public class FilePersistentConfig extends PersistentConfig {

	final File configFile;

	final File tempFilename;

	protected final String header;

	protected final Object storeSync = new Object();

	protected boolean writeOnFinished;

	private static volatile boolean logMINOR;

	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback() {
			@Override
			public void shouldUpdate() {
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}

	public static FilePersistentConfig constructFilePersistentConfig(File f) throws IOException {
		return constructFilePersistentConfig(f, null);
	}

	public static FilePersistentConfig constructFilePersistentConfig(File f, String header) throws IOException {
		File tempFilename = new File(f.getPath() + ".tmp");
		return new FilePersistentConfig(load(f, tempFilename), f, tempFilename, header);
	}

	static SimpleFieldSet load(File filename, File tempFilename) throws IOException {
		boolean filenameExists = filename.exists();
		boolean tempFilenameExists = tempFilename.exists();
		if (filenameExists && !filename.canWrite()) {
			Logger.error(FilePersistentConfig.class, "Warning: Cannot write to config file: " + filename);
			System.err.println("Warning: Cannot write to config file: " + filename);
		}
		if (tempFilenameExists && !tempFilename.canWrite()) {
			Logger.error(FilePersistentConfig.class, "Warning: Cannot write to config tempfile: " + tempFilename);
			System.err.println("Warning: Cannot write to config tempfile: " + tempFilename);
		}
		if (filenameExists) {
			if (filename.canRead() && filename.length() > 0) {
				try {
					return initialLoad(filename);
				}
				catch (FileNotFoundException ex) {
					System.err.println("Cannot open config file " + filename + " : " + ex + " - checking for temp file "
							+ tempFilename);
				}
				catch (EOFException ignored) {
					System.err.println("Empty config file " + filename + " (end of file)");
				}
				// Other IOE's indicate a more serious problem.
			}
			else {
				// We probably won't be able to write it either.
				System.err.println("Cannot read config file " + filename);
			}
		}
		if (tempFilename.exists()) {
			if (tempFilename.canRead() && tempFilename.length() > 0) {
				try {
					return initialLoad(tempFilename);
				}
				catch (FileNotFoundException ex) {
					System.err.println("Cannot open temp config file either: " + tempFilename + " : " + ex);
				} // Other IOE's indicate a more serious problem.
			}
			else {
				System.err.println("Cannot read (temp) config file " + tempFilename);
				throw new IOException("Cannot read (temp) config file " + tempFilename);
			}
		}
		System.err.println("No config file found, creating new: " + filename);
		return null;
	}

	protected FilePersistentConfig(SimpleFieldSet origFS, File fnam, File temp) throws IOException {
		this(origFS, fnam, temp, null);
	}

	protected FilePersistentConfig(SimpleFieldSet origFS, File fnam, File temp, String header) throws IOException {
		super(origFS);
		this.configFile = fnam;
		this.tempFilename = temp;
		this.header = header;
	}

	/**
	 * Load the config file into a SimpleFieldSet.
	 * @throws IOException
	 */
	private static SimpleFieldSet initialLoad(File toRead) throws IOException {
		if (toRead == null) {
			return null;
		}
		FileInputStream fis = null;
		BufferedInputStream bis = null;
		LineReadingInputStream lis = null;
		try {
			fis = new FileInputStream(toRead);
			bis = new BufferedInputStream(fis);
			lis = new LineReadingInputStream(bis);
			// Config file is UTF-8 too!
			// FIXME? advanced users may edit the config file, hence true?
			return new SimpleFieldSet(lis, 1024 * 1024, 128, true, true, true);
		}
		finally {
			Closer.close(lis);
			Closer.close(bis);
			Closer.close(fis);
		}
	}

	@Override
	public void register(SubConfig sc) {
		super.register(sc);
	}

	@Override
	public void store() {
		if (!this.finishedInit) {
			this.writeOnFinished = true;
			return;
		}
		try {
			synchronized (this.storeSync) {
				this.innerStore();
			}
		}
		catch (IOException ex) {
			String err = "Cannot store config: " + ex;
			Logger.error(this, err, ex);
			System.err.println(err);
			ex.printStackTrace();
		}
	}

	/** Don't call without taking storeSync first */
	protected final void innerStore() throws IOException {
		if (!this.finishedInit) {
			throw new IllegalStateException("SHOULD NOT HAPPEN!!");
		}

		SimpleFieldSet fs = this.exportFieldSet();
		if (logMINOR) {
			Logger.minor(this, "fs = " + fs);
		}
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(this.tempFilename);
			synchronized (this) {
				fs.setHeader(this.header);
				fs.writeToBigBuffer(fos);
			}
			fos.close();
			fos = null;
			FileUtil.renameTo(this.tempFilename, this.configFile);
		}
		finally {
			Closer.close(fos);
		}
	}

	public void finishedInit() {
		super.finishedInit();
		if (this.writeOnFinished) {
			this.writeOnFinished = false;
			this.store();
		}
	}

	public File getConfigFile() {
		return this.configFile;
	}

}
