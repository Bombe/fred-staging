package freenet.node.stats;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static freenet.node.stats.CompressionStats.CompressionRun.failed;
import static freenet.node.stats.CompressionStats.CompressionRun.failedTooBig;
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

	public interface CompressionRunRecorder {
		void finish(long sizeAfterCompression);
		void fail();
		void failTooBig();
	}

	public static class CompressionRun {
		public final String algorithm;
		public final long duration;
		public final long sizeBeforeCompression;
		public final long sizeAfterCompression;

		public CompressionRun(String algorithm, long duration, long sizeBeforeCompression, long sizeAfterCompression) {
			this.algorithm = algorithm;
			this.duration = duration;
			this.sizeBeforeCompression = sizeBeforeCompression;
			this.sizeAfterCompression = sizeAfterCompression;
		}

		public static CompressionRun failed(String algorithm, long duration, long sizeBeforeCompression) {
			return new CompressionRun(algorithm, duration, sizeBeforeCompression, -1);
		}

		public static CompressionRun failedTooBig(String algorithm, long duration, long sizeBeforeCompression) {
			return new CompressionRun(algorithm, duration, sizeBeforeCompression, -2);
		}

		@Override
		public String toString() {
			return format("CompressionRun[algorithm=%s,duration=%d,sizeBeforeCompression=%d,sizeAfterCompression=%d]", algorithm, duration, sizeBeforeCompression, sizeAfterCompression);
		}

	}

	public CompressionRunRecorder startCompressionRun(String algorithm, long sizeBeforeCompression) {
		Instant startTime = clock.instant();
		return new CompressionRunRecorder() {
			@Override
			public void finish(long sizeAfterCompression) {
				Instant endTime = clock.instant();
				compressionRuns.add(new CompressionRun(algorithm, between(startTime, endTime).toMillis(), sizeBeforeCompression, sizeAfterCompression));
			}

			@Override
			public void fail() {
				Instant endTime = clock.instant();
				compressionRuns.add(failed(algorithm, between(startTime, endTime).toMillis(), sizeBeforeCompression));
			}

			@Override
			public void failTooBig() {
				Instant endTime = clock.instant();
				compressionRuns.add(failedTooBig(algorithm, between(startTime, endTime).toMillis(), sizeBeforeCompression));
			}
		};
	}

	public CompressionStats() {
		this(systemUTC());
	}

	public CompressionStats(Clock clock) {
		this.clock = clock;
	}

	public List<CompressionRun> getCompressionRuns() {
		return compressionRuns;
	}

	private final Clock clock;
	private final List<CompressionRun> compressionRuns = new ArrayList<>();

}
