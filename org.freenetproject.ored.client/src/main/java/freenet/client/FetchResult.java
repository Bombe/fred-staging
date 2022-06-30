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

package freenet.client;

import java.io.IOException;

import freenet.bucket.Bucket;
import freenet.bucket.BucketTools;

/**
 * Class to contain the result of a key fetch.
 */
public class FetchResult {

	/** The ClientMetadata, i.e. MIME type. Must not be null. */
	final ClientMetadata metadata;

	/** The data. */
	final Bucket data;

	public FetchResult(ClientMetadata dm, Bucket fetched) {
		if (dm == null)
			throw new IllegalArgumentException();
		assert (fetched != null);
		this.metadata = dm;
		this.data = fetched;
	}

	/**
	 * Create a FetchResult with a new Bucket of data, but everything else the same as the
	 * old one.
	 */
	public FetchResult(FetchResult fr, Bucket output) {
		this.data = output;
		this.metadata = fr.metadata;
	}

	/**
	 * Get the MIME type of the fetched data. If unknown, returns
	 * application/octet-stream.
	 */
	public String getMimeType() {
		return this.metadata.getMIMEType();
	}

	/** Get the client-level metadata. */
	public ClientMetadata getMetadata() {
		return this.metadata;
	}

	/**
	 * @return The size of the data fetched, in bytes.
	 */
	public long size() {
		return this.data.size();
	}

	/**
	 * Get the result as a simple byte array, even if we don't have it as one. @throws
	 * OutOfMemoryError !!
	 * @throws IOException If it was not possible to read the data.
	 */
	public byte[] asByteArray() throws IOException {
		return BucketTools.toByteArray(this.data);
	}

	/**
	 * Get the result as a Bucket.
	 *
	 * You have to call Closer.close(bucket) to free() the obtained Bucket to prevent
	 * resource leakage!
	 */
	public Bucket asBucket() {
		return this.data;
	}

}
