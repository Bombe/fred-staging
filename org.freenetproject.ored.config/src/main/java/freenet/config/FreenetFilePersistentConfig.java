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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import freenet.support.Logger;
import freenet.support.SimpleFieldSet;
import freenet.support.Ticker;

public class FreenetFilePersistentConfig extends FilePersistentConfig {

	protected static final String DEFAULT_HEADER = "This file is overwritten whenever Freenet shuts down, so only edit it when the node is not running.";

	private volatile boolean isWritingConfig = false;

	private volatile boolean hasNodeStarted = false;

	private Ticker ticker;

	public final Runnable thread = new Runnable() {
		@Override
		public void run() {
			synchronized (this) {
				while (!FreenetFilePersistentConfig.this.hasNodeStarted) {
					try {
						this.wait(1000);
					}
					catch (InterruptedException ignored) {
					}
				}
			}

			try {
				FreenetFilePersistentConfig.this.innerStore();
			}
			catch (IOException ex) {
				String err = "Cannot store config: " + ex;
				Logger.error(this, err, ex);
				System.err.println(err);
				ex.printStackTrace();
			}

			// Make freenet.ini world readable
			// No sensible information in freenet.ini
			// Other app (e.g. oredcli requires to read it)
			System.out.println("Setting worldwide read permission for config file.");
			var os = System.getProperty("os.name");
			try {
				var path = FreenetFilePersistentConfig.this.configFile.toPath();
				if (os.startsWith("Windows")) {
					UserPrincipal usersGroup = path.getFileSystem().getUserPrincipalLookupService()
							.lookupPrincipalByGroupName("Users");
					AclFileAttributeView view = Files.getFileAttributeView(path, AclFileAttributeView.class);
					AclEntry entry = AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(usersGroup)
							.setPermissions(Set.of(AclEntryPermission.READ_DATA, AclEntryPermission.READ_ACL,
									AclEntryPermission.READ_ATTRIBUTES, AclEntryPermission.READ_NAMED_ATTRS))
							.build();
					List<AclEntry> acl = view.getAcl();
					acl.add(0, entry);

					Files.setAttribute(path, "acl:acl", acl);
				}
				else {
					// Linux, macOS etc.
					PosixFileAttributeView posix = Files.getFileAttributeView(path, PosixFileAttributeView.class);
					if (posix == null) {
						throw new IOException("Posix file permissions are not supported.");
					}
					Set<PosixFilePermission> permissions = new HashSet<>(posix.readAttributes().permissions());
					var changed = permissions.add(PosixFilePermission.OTHERS_READ);
					posix.setPermissions(permissions);
				}
			}
			catch (IOException ex) {
				String err = "Cannot change config file permission: " + ex;
				Logger.error(this, err, ex);
				System.err.println(err);
			}

			synchronized (FreenetFilePersistentConfig.this.storeSync) {
				FreenetFilePersistentConfig.this.isWritingConfig = false;
			}
		}
	};

	public FreenetFilePersistentConfig(SimpleFieldSet set, File filename, File tempFilename) throws IOException {
		super(set, filename, tempFilename, DEFAULT_HEADER);
	}

	public static FreenetFilePersistentConfig constructFreenetFilePersistentConfig(File f) throws IOException {
		var parentDir = f.getParentFile();
		System.out.println("Config file parent dir: " + parentDir.getAbsolutePath());
		if (!parentDir.exists() || !parentDir.isDirectory()) {
			if (!parentDir.mkdirs()) {
				throw new IOException("Unable to create directory for config file");
			}
		}

		File tempFilename = new File(f.getPath() + ".tmp");
		return new FreenetFilePersistentConfig(load(f, tempFilename), f, tempFilename);
	}

	@Override
	public void store() {
		// FIXME how to do this without duplicating code and making finishedInit visible?
		synchronized (this) {
			if (!this.finishedInit) {
				this.writeOnFinished = true;
				return;
			}
		}
		synchronized (this.storeSync) {
			if (this.isWritingConfig || this.ticker == null) {
				Logger.normal(this,
						"Already writing the config file to disk or the node object hasn't been set : refusing to proceed");
				return;
			}
			this.isWritingConfig = true;

			this.ticker.queueTimedJob(this.thread, 0);
		}
	}

	public void finishedInit(Ticker ticker) {
		this.ticker = ticker;
		super.finishedInit();
	}

	public void setHasNodeStarted() {
		synchronized (this) {
			if (this.hasNodeStarted) {
				Logger.error(this, "It has already been called! that shouldn't happen!");
			}
			this.hasNodeStarted = true;
			this.notifyAll();
		}
	}

}
