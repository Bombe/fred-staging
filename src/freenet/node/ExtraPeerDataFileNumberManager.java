package freenet.node;

import java.util.Collection;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Supplier;

/**
 * Manages file numbers for extra peer data.
 * <p>
 * This is basically a thin wrapper around a {@link Set}, adding an
 * {@link #allocateNextFileNumber() allocation function} that searches for
 * the next free file number.
 * <p>
 * This class is thread-safe.
 */
public class ExtraPeerDataFileNumberManager {

	public void addFileNumber(int fileNumber) {
		withLock(lock.writeLock(), () -> fileNumbers.add(fileNumber));
	}

	public void removeFileNumber(int fileNumber) {
		withLock(lock.writeLock(), () -> fileNumbers.remove(fileNumber));
	}

	public int allocateNextFileNumber() {
		return withLock(lock.writeLock(), () -> {
			int nextFileNumber = 0;
			for (int fileNumber : fileNumbers) {
				if (fileNumber > nextFileNumber) {
					break;
				}
				nextFileNumber++;
			}
			fileNumbers.add(nextFileNumber);
			return nextFileNumber;
		});
	}

	public Collection<Integer> getFileNumbers() {
		return withLock(lock.readLock(), () -> new TreeSet<>(fileNumbers));
	}

	private static <T> T withLock(Lock lock, Supplier<T> supplier) {
		lock.lock();
		try {
			return supplier.get();
		} finally {
			lock.unlock();
		}
	}

	private final ReadWriteLock lock = new ReentrantReadWriteLock();
	private final Set<Integer> fileNumbers = new TreeSet<>();

}
