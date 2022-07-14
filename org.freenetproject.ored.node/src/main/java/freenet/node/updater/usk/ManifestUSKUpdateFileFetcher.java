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

package freenet.node.updater.usk;

import freenet.keys.FreenetURI;
import freenet.node.Node;
import freenet.nodelogger.Logger;

/**
 * Manifest file updater.
 *
 * Manifest file is a SimpleFieldSet file that contains a list of package files. It's not
 * META-INF/MANIFEST.MF in jar files.
 *
 * Key format: os.arch.ext
 *
 * e.g.: linux.x86_64.deb
 *
 * Value: CHK of the file
 *
 * TODO: UoM
 *
 * @since 1.0.1493
 *
 */
public class ManifestUSKUpdateFileFetcher extends AbstractUSKUpdateFileFetcher {

	private static volatile boolean logMINOR;

	static {
		Logger.registerClass(ManifestUSKUpdateFileFetcher.class);
	}

	public static final long MAX_MANIFEST_LENGTH = 1024 * 1024; // 1MiB

	public static final long MAX_PACKAGE_LENGTH = 100 * 1024 * 1024; // 1MiB

	/**
	 * If we fetched the manifest locally, there is a 1 in RANDOM_INSERT_BLOB chance of
	 * inserting it. We always insert it if we downloaded it via UOM. We always reinsert
	 * revocations.
	 */
	protected static final int RANDOM_INSERT_BLOB = 10;

	public ManifestUSKUpdateFileFetcher(Node node, int currentVersion, int minDeployVersion, int maxDeployVersion,
			FreenetURI updateURI) {

		super(node, "manifest", currentVersion, minDeployVersion, maxDeployVersion, updateURI);
	}

	@Override
	public String getFileName() {
		return this.fileType;
	}

}
