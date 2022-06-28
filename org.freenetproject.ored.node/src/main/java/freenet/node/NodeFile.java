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

/**
 * Mapping of files managed by the node to their respective locations.
 */
public enum NodeFile {

	Seednodes(InstallDirectory.Node, "seednodes.fref"),
	InstallerWindows(InstallDirectory.Run, "freenet-latest-installer-windows.exe"),
	InstallerNonWindows(InstallDirectory.Run, "freenet-latest-installer-nonwindows.jar"),
	IPv4ToCountry(InstallDirectory.Run, "IpToCountry.dat");

	private final InstallDirectory dir;

	private final String filename;

	/**
	 * Gets the absolute file path associated with this file for the given node instance.
	 */
	public File getFile(Node node) {
		return this.dir.getDir(node).file(this.filename);
	}

	/**
	 * Gets the filename associated with this file.
	 */
	public String getFilename() {
		return this.filename;
	}

	/**
	 * Gets the base directory with this file for the given node instance.
	 */
	public ProgramDirectory getProgramDirectory(Node node) {
		return this.dir.getDir(node);
	}

	NodeFile(InstallDirectory dir, String filename) {
		this.dir = dir;
		this.filename = filename;
	}

	private enum InstallDirectory {

		// node.install.nodeDir
		Node() {
			@Override
			ProgramDirectory getDir(Node node) {
				return node.nodeDir();
			}
		},
		// node.install.cfgDir
		Cfg() {
			@Override
			ProgramDirectory getDir(Node node) {
				return node.cfgDir();
			}
		},
		// node.install.userDir
		User() {
			@Override
			ProgramDirectory getDir(Node node) {
				return node.userDir();
			}
		},
		// node.install.runDir
		Run() {
			@Override
			ProgramDirectory getDir(Node node) {
				return node.runDir();
			}
		},
		// node.install.storeDir
		Store() {
			@Override
			ProgramDirectory getDir(Node node) {
				return node.storeDir();
			}
		},
		// node.install.pluginDir
		Plugin() {
			@Override
			ProgramDirectory getDir(Node node) {
				return node.pluginDir();
			}
		};

		abstract ProgramDirectory getDir(Node node);

	}

}
