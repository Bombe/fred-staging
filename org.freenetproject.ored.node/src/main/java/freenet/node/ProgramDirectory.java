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
import java.util.HashSet;

import freenet.config.InvalidConfigValueException;
import freenet.config.StringCallback;
import freenet.l10n.NodeL10n;

/**
 ** Represents a program directory, and keeps track of the files that freenet stores there.
 **
 ** @author infinity0
 ** @see <a href=http://new-wiki.freenetproject.org/Program_files>New wiki program files
 * documentation</a>
 ** @see <a href=http://wiki.freenetproject.org/Program_files>Old wiki program files
 * documentation</a>
 */
public class ProgramDirectory {

	/** Directory path */
	protected File dir = null;

	/** Keeps track of all the files saved in this directory */
	protected final HashSet<String> files = new HashSet<>();

	private final StringCallback callback;

	private final String moveErrMsg;

	private static int sortOrder = 0;

	protected static synchronized int nextOrder() {
		return sortOrder++;
	}

	public ProgramDirectory() {
		this(null);
	}

	public ProgramDirectory(String moveErrMsg) {
		this.moveErrMsg = moveErrMsg;
		this.callback = (moveErrMsg != null) ? new RWDirectoryCallback() : new DirectoryCallback();
	}

	/**
	 ** Move the directory. Currently not implemented, except in the initialisation case.
	 */
	public void move(String file) throws IOException {
		File dir = new File(file);
		if (this.dir != null && !dir.equals(this.dir)) {
			throw new IOException("move not implemented");
		}

		if (!((dir.exists() && dir.isDirectory()) || (dir.mkdir()))) {
			throw new IOException("Could not find or make a directory called: " + l10n(file));
		}

		this.dir = dir;
	}

	public StringCallback getStringCallback() {
		return this.callback;
	}

	/**
	 ** Return a {@link File} object from the given string basename.
	 */
	public File file(String base) {
		this.files.add(base);
		return new File(this.dir, base);
	}

	public File dir() {
		return this.dir;
	}

	private static String l10n(String key) {
		return NodeL10n.getBase().getString(key);
	}

	public class DirectoryCallback extends StringCallback {

		@Override
		public String get() {
			return ProgramDirectory.this.dir.getPath();
		}

		@Override
		public void set(String val) throws InvalidConfigValueException {
			if (ProgramDirectory.this.dir == null) {
				ProgramDirectory.this.dir = new File(val);
				return;
			}
			if (ProgramDirectory.this.dir.equals(new File(val))) {
				return;
			}
			// FIXME support it
			// Don't need to translate the below as very few users will use it.
			throw new InvalidConfigValueException("Moving program directory on the fly not supported at present");
		}

		@Override
		public boolean isReadOnly() {
			return true;
		}

	}

	public class RWDirectoryCallback extends DirectoryCallback {

		@Override
		public void set(String val) throws InvalidConfigValueException {
			if (ProgramDirectory.this.dir == null) {
				ProgramDirectory.this.dir = new File(val);
				return;
			}
			if (ProgramDirectory.this.dir.equals(new File(val))) {
				return;
			}
			File f = new File(val);
			if (!((f.exists() && f.isDirectory()) || (f.mkdir()))) {
				// Relatively commonly used, despite being advanced (i.e. not something we
				// want to show to newbies). So translate it.
				throw new InvalidConfigValueException(l10n(ProgramDirectory.this.moveErrMsg));
			}
			ProgramDirectory.this.dir = new File(val);
		}

		@Override
		public boolean isReadOnly() {
			return false;
		}

	}

}
