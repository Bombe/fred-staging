package freenet.node.stats;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static freenet.node.stats.CompressionStats.OperationRun.failed;
import static freenet.node.stats.CompressionStats.OperationRun.failedTooBig;
import static java.lang.String.format;
import static java.time.Clock.systemUTC;
import static java.time.Duration.between;

/**
 * Compression- and decompression-related stats.
 * <p>
 * Usage example:
 * </p>
 * <pre>
 * CompressionRunRecorder recorder = compressionStats.startCompressionRun("GZIP", 123456);
 * // do the compression
 * recorder.finish(result.size());
 * </pre>
 */
public class CompressionStats {

	public interface OperationRunRecorder {
		void finish(long sizeAfterOperation);
		void fail();
		void failTooBig();
	}

	public static class OperationRun {
		public final String algorithm;
		public final long duration;
		public final long sizeBeforeOperation;
		public final long sizeAfterOperation;

		public OperationRun(String algorithm, long duration, long sizeBeforeOperation, long sizeAfterOperation) {
			this.algorithm = algorithm;
			this.duration = duration;
			this.sizeBeforeOperation = sizeBeforeOperation;
			this.sizeAfterOperation = sizeAfterOperation;
		}

		public static OperationRun failed(String algorithm, long duration, long sizeBeforeOperation) {
			return new OperationRun(algorithm, duration, sizeBeforeOperation, -1);
		}

		public static OperationRun failedTooBig(String algorithm, long duration, long sizeBeforeOperation) {
			return new OperationRun(algorithm, duration, sizeBeforeOperation, -2);
		}

		@Override
		public String toString() {
			return format("CompressionRun[algorithm=%s,duration=%d,sizeBeforeOperation=%d,sizeAfterOperation=%d]", algorithm, duration, sizeBeforeOperation, sizeAfterOperation);
		}

	}

	public OperationRunRecorder startCompressionRun(String algorithm, long sizeBeforeOperation) {
		return recordOperation(algorithm, sizeBeforeOperation, compressionRuns);
	}

	public OperationRunRecorder startDecompressionRun(String algorithm, long sizeBeforeOperation) {
		return recordOperation(algorithm, sizeBeforeOperation, decompressionRuns);
	}

	private OperationRunRecorder recordOperation(String algorithm, long sizeBeforeOperation, List<OperationRun> recordingTarget) {
		Instant startTime = clock.instant();
		return new OperationRunRecorder() {
			@Override
			public void finish(long sizeAfterOperation) {
				Instant endTime = clock.instant();
				recordingTarget.add(new OperationRun(algorithm, between(startTime, endTime).toMillis(), sizeBeforeOperation, sizeAfterOperation));
			}

			@Override
			public void fail() {
				Instant endTime = clock.instant();
				recordingTarget.add(failed(algorithm, between(startTime, endTime).toMillis(), sizeBeforeOperation));
			}

			@Override
			public void failTooBig() {
				Instant endTime = clock.instant();
				recordingTarget.add(failedTooBig(algorithm, between(startTime, endTime).toMillis(), sizeBeforeOperation));
			}
		};
	}

	public CompressionStats() {
		this(systemUTC());
	}

	public CompressionStats(Clock clock) {
		this.clock = clock;
	}

	public List<OperationRun> getCompressionRuns() {
		return compressionRuns;
	}

	public List<OperationRun> getDecompressionRuns() {
		return decompressionRuns;
	}

	private final Clock clock;
	private final List<OperationRun> compressionRuns = new ArrayList<>();
	private final List<OperationRun> decompressionRuns = new ArrayList<>();

}
