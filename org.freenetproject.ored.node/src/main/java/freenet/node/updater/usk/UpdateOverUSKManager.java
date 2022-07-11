/*
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

import freenet.bucket.Bucket;
import freenet.keys.FreenetURI;
import freenet.node.Version;
import freenet.node.updater.NodeUpdateManager;

public class UpdateOverUSKManager {

	private final NodeUpdateManager nodeUpdateManager;

	private final ManifestUSKUpdateFileFetcher manifestUSKUpdateFileFetcher;

	public UpdateOverUSKManager(NodeUpdateManager nodeUpdateManager) {
		this.nodeUpdateManager = nodeUpdateManager;
		this.manifestUSKUpdateFileFetcher = new ManifestUSKUpdateFileFetcher(this.nodeUpdateManager.node,
				Version.buildNumber(), -1, Integer.MAX_VALUE, this.nodeUpdateManager.getUpdateURI());
	}

	public void start() {
		this.manifestUSKUpdateFileFetcher.start();
	}

	public void preKill() {
		this.manifestUSKUpdateFileFetcher.preKill();
	}

	public void kill() {
		this.manifestUSKUpdateFileFetcher.kill();
	}

	public void cleanup() {
		this.manifestUSKUpdateFileFetcher.cleanup();
	}

	public void onChangeURI(FreenetURI uri) {
		this.manifestUSKUpdateFileFetcher.onChangeURI(uri);
	}

	public long getStartedFetchingNextFile() {
		return this.manifestUSKUpdateFileFetcher.getStartedFetchingNextFile();
	}

	// TODO: should be the time we got the install package. we need a field to track this
	// time
	public long getGotFileTime() {
		return this.manifestUSKUpdateFileFetcher.getGotFileTime();
	}

	public void setGotFileTime(long gotFileTime) {
		this.manifestUSKUpdateFileFetcher.setGotFileTime(gotFileTime);
	}

	public int getMaybeNextFileVersion() {
		return this.manifestUSKUpdateFileFetcher.getMaybeNextFileVersion();
	}

	public Bucket getMaybeNextFileData() {
		return this.manifestUSKUpdateFileFetcher.getMaybeNextFileData();
	}

	public int getFetchedFileVersion() {
		return this.manifestUSKUpdateFileFetcher.getFetchedFileVersion();
	}

	public Bucket getFetchedFileData() {
		return this.manifestUSKUpdateFileFetcher.getFetchedFileData();
	}

	public void setFetchedFileVersion(int fetchedFileVersion) {
		this.manifestUSKUpdateFileFetcher.setFetchedFileVersion(fetchedFileVersion);
	}

	public void setFetchedFileData(Bucket fetchedFileData) {
		this.manifestUSKUpdateFileFetcher.setFetchedFileData(fetchedFileData);
	}

	public void setMaybeNextFileVersion(int maybeNextFileVersion) {
		this.manifestUSKUpdateFileFetcher.setMaybeNextFileVersion(maybeNextFileVersion);
	}

	public void setMaybeNextFileData(Bucket maybeNextFileData) {
		this.manifestUSKUpdateFileFetcher.setMaybeNextFileData(maybeNextFileData);
	}

	public int getFetchedVersion() {
		return this.manifestUSKUpdateFileFetcher.getFetchedVersion();
	}

	// TODO: also consider package fetchers
	public boolean isFetching() {
		return this.manifestUSKUpdateFileFetcher.isFetching();
	}

	public int fetchingVersion() {
		return this.manifestUSKUpdateFileFetcher.fetchingVersion();
	}

}
