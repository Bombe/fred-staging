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

package freenet.lockablebuffer;

import java.io.IOException;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Proxy LockableRandomAccessBuffer allowing changing the pointer to the underlying RAT.
 *
 * @author Matthew Toseland
 */
public abstract class SwitchableProxyRandomAccessBuffer implements LockableRandomAccessBuffer {

	/**
	 * Size of the temporary storage. Note that this may be smaller than
	 * underlying.size(), and will be enforced before passing requests on.
	 */
	public final long size;

	/**
	 * Underlying temporary storage. May change! Will be thread-safe as with all RAT's.
	 * Current implementations just lock all writes/reads.
	 */
	private LockableRandomAccessBuffer underlying;

	/**
	 * Number of currently valid RAFLock's on this RAF. We centralise this here so that we
	 * only have to take a single new lock when migrating.
	 */
	private int lockOpenCount;

	/** Lock we took on the underlying when the first caller called lockOpen(). */
	private RAFLock underlyingLock;

	private boolean closed;

	/**
	 * Read/write lock for the pointer to underlying and lockOpenCount. That is, we take a
	 * write lock when we want to change the underlying pointer or other mutable fields,
	 * e.g. during migration or freeing the data, and a read lock for any other operation,
	 * hence we ensure that there is no other I/O going on during a migration.
	 */
	private final ReadWriteLock lock = new ReentrantReadWriteLock();

	public SwitchableProxyRandomAccessBuffer(LockableRandomAccessBuffer initialWrap, long size) throws IOException {
		this.underlying = initialWrap;
		this.size = size;
		if (this.underlying.size() < size) {
			throw new IOException("Underlying must be >= size given");
		}
	}

	@Override
	public long size() {
		return this.size;
	}

	@Override
	public void pread(long fileOffset, byte[] buf, int bufOffset, int length) throws IOException {
		if (fileOffset < 0) {
			throw new IllegalArgumentException();
		}
		if (fileOffset + length > this.size) {
			throw new IOException("Tried to read past end of file");
		}
		try {
			this.lock.readLock().lock();
			if (this.underlying == null || this.closed) {
				throw new IOException("Already closed");
			}
			this.underlying.pread(fileOffset, buf, bufOffset, length);
		}
		finally {
			this.lock.readLock().unlock();
		}
	}

	@Override
	public void pwrite(long fileOffset, byte[] buf, int bufOffset, int length) throws IOException {
		if (fileOffset < 0) {
			throw new IllegalArgumentException();
		}
		if (fileOffset + length > this.size) {
			throw new IOException("Tried to write past end of file");
		}
		try {
			this.lock.readLock().lock();
			if (this.underlying == null || this.closed) {
				throw new IOException("Already closed");
			}
			this.underlying.pwrite(fileOffset, buf, bufOffset, length);
		}
		finally {
			this.lock.readLock().unlock();
		}
	}

	@Override
	public void close() {
		try {
			this.lock.writeLock().lock();
			if (this.underlying == null) {
				return;
			}
			if (this.closed) {
				return;
			}
			this.closed = true;
			this.underlying.close();
		}
		finally {
			this.lock.writeLock().unlock();
		}
	}

	@Override
	public void free() {
		innerFree();
	}

	/**
	 * Free the underlying buffer.
	 * @return true unless the buffer has already been freed.
	 */
	protected boolean innerFree() {
		try {
			// Write lock as we're going to change the underlying pointer.
			this.lock.writeLock().lock();
			this.closed = true; // Effectively ...
			if (this.underlying == null) {
				return false;
			}
			this.underlying.free();
			this.underlying = null;
		}
		finally {
			this.lock.writeLock().unlock();
		}
		afterFreeUnderlying();
		return true;
	}

	public boolean hasBeenFreed() {
		try {
			this.lock.readLock().lock();
			return this.underlying == null;
		}
		finally {
			this.lock.readLock().unlock();
		}
	}

	/**
	 * Called after freeing the underlying storage. That includes when migrating, not just
	 * when free() is called!
	 */
	protected void afterFreeUnderlying() {
		// Do nothing.
	}

	@Override
	public RAFLock lockOpen() throws IOException {
		try {
			this.lock.writeLock().lock();
			if (this.closed || this.underlying == null) {
				throw new IOException("Already closed");
			}
			RAFLock lock = new RAFLock() {

				@Override
				protected void innerUnlock() {
					externalUnlock();
				}

			};
			this.lockOpenCount++;
			if (this.lockOpenCount == 1) {
				assert (this.underlyingLock == null);
				this.underlyingLock = this.underlying.lockOpen();
			}
			return lock;
		}
		finally {
			this.lock.writeLock().unlock();
		}
	}

	/** Called when an external lock-open RAFLock is closed. */
	protected void externalUnlock() {
		try {
			this.lock.writeLock().lock();
			this.lockOpenCount--;
			if (this.lockOpenCount == 0) {
				this.underlyingLock.unlock();
				this.underlyingLock = null;
			}
		}
		finally {
			this.lock.writeLock().unlock();
		}
	}

	/** Migrate from one underlying LockableRandomAccessBuffer to another. */
	protected final void migrate() throws IOException {
		try {
			this.lock.writeLock().lock();
			if (this.closed) {
				return;
			}
			if (this.underlying == null) {
				throw new IOException("Already freed");
			}
			LockableRandomAccessBuffer successor = innerMigrate(this.underlying);
			if (successor == null) {
				throw new NullPointerException();
			}
			RAFLock newLock = null;
			if (this.lockOpenCount > 0) {
				try {
					newLock = successor.lockOpen();
				}
				catch (IOException ex) {
					successor.close();
					successor.free();
					throw ex;
				}
			}
			if (this.lockOpenCount > 0) {
				this.underlyingLock.unlock();
			}
			this.underlying.close();
			this.underlying.free();
			this.underlying = successor;
			this.underlyingLock = newLock;
		}
		finally {
			this.lock.writeLock().unlock();
		}
		afterFreeUnderlying();
	}

	/**
	 * Create a new LockableRandomAccessBuffer containing the same data as the current
	 * underlying.
	 * @param underlying underlying buffer.
	 * @return the new created buffer.
	 * @throws IOException if the migrate failed.
	 */
	protected abstract LockableRandomAccessBuffer innerMigrate(LockableRandomAccessBuffer underlying)
			throws IOException;

	/**
	 * For unit tests only.
	 * @return current underlying buffer.
	 */
	public synchronized LockableRandomAccessBuffer getUnderlying() {
		return this.underlying;
	}

	// Default hashCode() and equals() i.e. comparison by identity are correct for this
	// type.

}
