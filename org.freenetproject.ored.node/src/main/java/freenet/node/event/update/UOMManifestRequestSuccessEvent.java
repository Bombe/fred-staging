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

package freenet.node.event.update;

import java.io.File;

import freenet.client.FetchResult;
import freenet.client.async.ClientGetter;
import freenet.node.PeerNode;

/**
 * Event posted after node sent UOMRequestManifest message and received the manifest file
 * successfully.
 *
 * @since 1.0.1493
 */
public class UOMManifestRequestSuccessEvent {

	private final FetchResult result;

	private final ClientGetter state;

	private final File cleanedBlobFile;

	private final int version;

	private PeerNode source;

	public FetchResult getResult() {
		return this.result;
	}

	public ClientGetter getState() {
		return this.state;
	}

	public File getCleanedBlobFile() {
		return this.cleanedBlobFile;
	}

	public int getVersion() {
		return this.version;
	}

	public PeerNode getSource() {
		return this.source;
	}

	public UOMManifestRequestSuccessEvent(FetchResult result, ClientGetter state, File cleanedBlobFile, int version,
			PeerNode source) {

		this.result = result;
		this.state = state;
		this.cleanedBlobFile = cleanedBlobFile;
		this.version = version;
		this.source = source;
	}

}
