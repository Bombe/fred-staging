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

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;

import com.sun.jna.Platform;
import freenet.client.FetchException;
import freenet.client.FetchResult;
import freenet.client.request.PriorityClasses;
import freenet.keys.FreenetURI;
import freenet.nodelogger.Logger;
import freenet.support.SimpleFieldSet;

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
 */
public class ManifestUpdater extends AbstractFileUpdater {

	public static final long MAX_MANIFEST_LENGTH = 1024 * 1024; // 1MiB

	public static final long MAX_PACKAGE_LENGTH = 100 * 1024 * 1024; // 1MiB

	private volatile boolean hasNewPackageFile;

	ManifestUpdater(NodeUpdateManager manager, FreenetURI URI, int current, int min, int max,
			String blobFilenamePrefix) {
		super(manager, URI, current, min, max, blobFilenamePrefix);
	}

	@Override
	public String fileName() {
		return "update.manifest";
	}

	@Override
	public void start() {
		this.maybeProcessOldBlob();
		super.start();
	}

	@Override
	protected void onStartFetching() {
		super.onStartFetching();
	}

	@Override
	protected void processSuccess(int fetched, FetchResult result, File blobFile) {
		super.processSuccess(fetched, result, blobFile);

		this.parseManifest(fetched, result);
	}

	private void parseManifest(int fetched, FetchResult result) {
		try (var is = result.asBucket().getInputStream()) {
			var fieldSet = new SimpleFieldSet(new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8)),
					false, true);

			var count = 0;
			var iter = fieldSet.keyIterator();
			while (iter.hasNext()) {
				count++;
				iter.next();
			}

			fieldSet.keyIterator().forEachRemaining((key) -> {
				// TODO: UoM
				try {
					String filenameForMe = null;
					switch (Platform.getOSType()) {
						case Platform.WINDOWS:
							filenameForMe = "windows." + Platform.ARCH + ".exe";
							break;
						case Platform.LINUX:
							// TODO
							break;
						case Platform.MAC:
							// TODO
							break;
						default:
							Logger.error(this, "Unsupported OS");
					}
					final String finalFilenameForMe = filenameForMe;
					var puller = new SimplePuller(this.node, new FreenetURI(fieldSet.get(key)), fetched + "/" + key,
							this.node.runDir(), (pullerResult, state) -> {
								if (key.equals(finalFilenameForMe)) {
									// TODO: make isReadyToDeployUpdate return true
									this.hasNewPackageFile = true;
								}
							}, (ex, state) -> {
								if (key.equals(finalFilenameForMe)) {
									// We just care about this platform. Ignore errors of
									// fetching other packages
									if (ex instanceof FetchException fetchException) {
										ManifestUpdater.this.onFailure(fetchException, state);
									}
									else {
										var fe = new FetchException(FetchException.FetchExceptionMode.INTERNAL_ERROR);
										ManifestUpdater.this.onFailure(fe, state);
									}
								}
							});
					puller.start(PriorityClasses.IMMEDIATE_SPLITFILE_PRIORITY_CLASS, MAX_PACKAGE_LENGTH);
				}
				catch (MalformedURLException ex) {
					throw new RuntimeException(ex);
				}
			});

		}
		catch (IOException ex) {
			Logger.error(this, "IOException trying to read manifest on update");
		}
	}

	@Override
	public void cleanup() {

	}

	@Override
	public boolean isHasNewFile() {
		return super.isHasNewFile() && this.hasNewPackageFile;
	}

	public void onStartFetchingUOM() {
		// TODO: fetch package files
	}

	protected void maybeProcessOldBlob() {
		File oldBlob = this.getBlobFile(this.currentVersion);
		if (oldBlob.exists()) {
			File temp;
			try {
				temp = File.createTempFile(this.blobFilenamePrefix + this.availableVersion + "-", ".fblob.tmp",
						this.manager.node.clientCore.getPersistentTempDir());
			}
			catch (IOException ex) {
				Logger.error(this, "Unable to process old blob: " + ex, ex);
				return;
			}
			if (oldBlob.renameTo(temp)) {
				FreenetURI uri = this.URI.setSuggestedEdition(this.currentVersion);
				uri = uri.sskForUSK();
				try {
					this.manager.uom.processManifestBlob(temp, null, this.currentVersion, uri);
				}
				catch (Throwable ex) {
					// Don't disrupt startup.
					Logger.error(this, "Unable to process old blob, caught " + ex, ex);
				}
				// noinspection ResultOfMethodCallIgnored
				temp.delete();
			}
			else {
				Logger.error(this,
						"Unable to rename old blob file " + oldBlob + " to " + temp + " so can't process it.");
			}
		}

	}

}