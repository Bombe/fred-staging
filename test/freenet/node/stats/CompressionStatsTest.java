package freenet.node.stats;

import java.time.Instant;

import freenet.node.stats.CompressionStats.OperationRunRecorder;
import freenet.test.time.SettableClock;
import org.junit.Test;

import static freenet.test.matcher.OperationRunMatcher.matchesOperationRun;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;

/**
 * Unit test for {@link CompressionStats}.
 */
public class CompressionStatsTest {

	@Test
	public void successfulCompressionRunCanBeCreated() {
		CompressionStats compressionStats = new CompressionStats();
		compressionStats.startCompressionRun("GZIP", 1024).finish(29);
		assertThat(compressionStats.getCompressionRuns(), contains(
				matchesOperationRun("GZIP", 1024, 29)
		));
	}

	@Test
	public void durationOfACompressionRunIsRecordedCorrectly() {
		testClock.setInstant(now.plusMillis(23));
		compressionRunRecorder.finish(29);
		assertThat(compressionStats.getCompressionRuns(), contains(
				matchesOperationRun("GZIP", equalTo(23L), 1024, 29)
		));
	}

	@Test
	public void compresionRunWithExceptionIsRecordedCorrectly() {
		compressionRunRecorder.fail();
		assertThat(compressionStats.getCompressionRuns(), contains(
				matchesOperationRun("GZIP", equalTo(0L), 1024, -1)
		));
	}

	@Test
	public void compresionRunResultingInTooMuchDataIsRecordedCorrectly() {
		compressionRunRecorder.failTooBig();
		assertThat(compressionStats.getCompressionRuns(), contains(
				matchesOperationRun("GZIP", equalTo(0L), 1024, -2)
		));
	}

	@Test
	public void decompressionRunsAreCountedCorrectly() {
		decompressionRunRecorder.finish(1024);
		assertThat(compressionStats.getDecompressionRuns(), contains(
				matchesOperationRun("GZIP", 29, 1024)
		));
	}

	@Test
	public void decompresionRunWithFailureIsRecordedCorrectly() {
		decompressionRunRecorder.fail();
		assertThat(compressionStats.getDecompressionRuns(), contains(
				matchesOperationRun("GZIP", 29, -1)
		));
	}

	@Test
	public void durationOfADecompressionRunIsRecordedCorrectly() {
		testClock.setInstant(now.plusMillis(23));
		decompressionRunRecorder.finish(1024);
		assertThat(compressionStats.getDecompressionRuns(), contains(
				matchesOperationRun("GZIP", equalTo(23L), 29, 1024)
		));
	}

	private final Instant now = Instant.now();
	private final SettableClock testClock = new SettableClock(now);
	private final CompressionStats compressionStats = new CompressionStats(testClock);
	private final OperationRunRecorder compressionRunRecorder = compressionStats.startCompressionRun("GZIP", 1024);
	private final OperationRunRecorder decompressionRunRecorder = compressionStats.startDecompressionRun("GZIP", 29);

}
