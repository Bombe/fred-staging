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

package freenet.client.async;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serial;
import java.util.ArrayList;
import java.util.HashSet;

import freenet.bucket.Bucket;
import freenet.bucket.BucketFactory;
import freenet.bucket.BucketTools;
import freenet.clientlogger.Logger;
import freenet.keys.ClientKeyBlock;
import freenet.keys.Key;

/**
 * Helper class to write FBlobs. Threadsafe, allows multiple getters to write to the same
 * BinaryBlobWriter.
 *
 * @author saces
 */
public final class BinaryBlobWriter {

	private static volatile boolean logMINOR;

	static {
		Logger.registerClass(BinaryBlobWriter.class);
	}

	private final HashSet<Key> _binaryBlobKeysAddedAlready;

	private final BucketFactory _bf;

	private final ArrayList<Bucket> _buckets;

	private final Bucket _out;

	private final boolean _isSingleBucket;

	private boolean _started = false;

	private boolean _finalized = false;

	private transient DataOutputStream _stream_cache = null;

	/**
	 * Persistent/'BigFile' constructor
	 * @param bf BucketFactory to generate internal buckets from
	 */
	public BinaryBlobWriter(BucketFactory bf) {
		this._binaryBlobKeysAddedAlready = new HashSet<Key>();
		this._buckets = new ArrayList<Bucket>();
		this._bf = bf;
		this._out = null;
		this._isSingleBucket = false;
	}

	/**
	 * Transient constructor
	 * @param out Bucket to write the result to
	 */
	public BinaryBlobWriter(Bucket out) {
		this._binaryBlobKeysAddedAlready = new HashSet<Key>();
		this._buckets = null;
		this._bf = null;
		assert out != null;
		this._out = out;
		this._isSingleBucket = true;
	}

	private DataOutputStream getOutputStream() throws IOException, BinaryBlobAlreadyClosedException {
		if (this._finalized) {
			throw new BinaryBlobAlreadyClosedException("Already finalized (getting final data) on " + this);
		}
		if (this._stream_cache == null) {
			if (this._isSingleBucket) {
				assert this._out != null;
				this._stream_cache = new DataOutputStream(this._out.getOutputStream());
			}
			else {
				assert this._bf != null;
				Bucket newBucket = this._bf.makeBucket(-1);
				assert this._buckets != null;
				this._buckets.add(newBucket);
				this._stream_cache = new DataOutputStream(newBucket.getOutputStream());
			}
		}
		if (!this._started) {
			BinaryBlob.writeBinaryBlobHeader(this._stream_cache);
			this._started = true;
		}
		return this._stream_cache;
	}

	/**
	 * Add a block to the binary blob.
	 */
	public synchronized void addKey(ClientKeyBlock block, ClientContext context)
			throws IOException, BinaryBlobAlreadyClosedException {
		Key key = block.getKey();
		if (this._binaryBlobKeysAddedAlready.contains(key)) {
			return;
		}
		BinaryBlob.writeKey(this.getOutputStream(), block.getBlock(), key);
		this._binaryBlobKeysAddedAlready.add(key);
	}

	/**
	 * finalize the return bucket
	 */
	public void finalizeBucket() throws IOException, BinaryBlobAlreadyClosedException {
		if (this._finalized) {
			throw new BinaryBlobAlreadyClosedException("Already finalized (closing blob).");
		}
		this.finalizeBucket(true);
	}

	private void finalizeBucket(boolean mark) throws IOException, BinaryBlobAlreadyClosedException {
		if (this._finalized) {
			throw new BinaryBlobAlreadyClosedException("Already finalized (closing blob - 2).");
		}
		if (logMINOR) {
			Logger.minor(this, "Finalizing binary blob " + this, new Exception("debug"));
		}
		if (!this._isSingleBucket) {
			if (!mark) {
				assert this._buckets != null;
				if (this._buckets.size() == 1) {
					return;
				}
			}
			assert this._bf != null;
			Bucket out = this._bf.makeBucket(-1);
			this.getSnapshot(out, mark);
			assert this._buckets != null;
			for (Bucket bucket : this._buckets) {
				bucket.free();
			}
			if (mark) {
				out.setReadOnly();
			}
			this._buckets.clear();
			this._buckets.add(0, out);
		}
		else if (mark) {
			try (DataOutputStream out = new DataOutputStream(this.getOutputStream())) {
				BinaryBlob.writeEndBlob(out);
			}
		}
		if (mark) {
			this._finalized = true;
		}
	}

	public synchronized void getSnapshot(Bucket bucket) throws IOException, BinaryBlobAlreadyClosedException {
		assert this._buckets != null;
		if (this._buckets.isEmpty()) {
			return;
		}
		if (this._finalized) {
			BucketTools.copy(this._buckets.get(0), bucket);
			return;
		}
		this.getSnapshot(bucket, true);
	}

	private void getSnapshot(Bucket bucket, boolean addEndmarker) throws IOException, BinaryBlobAlreadyClosedException {
		assert this._buckets != null;
		if (this._buckets.isEmpty()) {
			return;
		}
		if (this._finalized) {
			throw new BinaryBlobAlreadyClosedException("Already closed (getting final data snapshot)");
		}
		try (OutputStream out = bucket.getOutputStream()) {
			for (Bucket value : this._buckets) {
				BucketTools.copyTo(value, out, -1);
			}
			if (addEndmarker) {
				DataOutputStream dout = new DataOutputStream(out);
				BinaryBlob.writeEndBlob(dout);
				dout.flush();
			}
		}
	}

	public synchronized Bucket getFinalBucket() {
		if (!this._finalized) {
			throw new IllegalStateException("Not finalized!");
		}
		if (this._isSingleBucket) {
			return this._out;
		}
		else {
			assert this._buckets != null;
			return this._buckets.get(0);
		}
	}

	public boolean isFinalized() {
		return this._finalized;
	}

	public static class BinaryBlobAlreadyClosedException extends Exception {

		@Serial
		private static final long serialVersionUID = -1L;

		public BinaryBlobAlreadyClosedException(String message) {
			super(message);
		}

	}

}
