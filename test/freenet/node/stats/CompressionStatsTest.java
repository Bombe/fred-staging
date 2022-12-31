package freenet.node.stats;

import java.time.Instant;

import freenet.node.stats.CompressionStats.CompressionRunRecorder;
import freenet.test.time.SettableClock;
import org.junit.Test;

import static freenet.test.matcher.CompressionRunMatcher.matchesCompressionRun;
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
				matchesCompressionRun("GZIP", 1024, 29)
		));
	}

	@Test
	public void durationOfACompressionRunIsRecordedCorrectly() {
		testClock.setInstant(now.plusMillis(23));
		compressionRunRecorder.finish(29);
		assertThat(compressionStats.getCompressionRuns(), contains(
				matchesCompressionRun("GZIP", equalTo(23L), 1024, 29)
		));
	}

	@Test
	public void compresionRunWithExceptionIsRecordedCorrectly() {
		compressionRunRecorder.fail();
		assertThat(compressionStats.getCompressionRuns(), contains(
				matchesCompressionRun("GZIP", equalTo(0L), 1024, -1)
		));
	}

	@Test
	public void compresionRunResultingInTooMuchDataIsRecordedCorrectly() {
		compressionRunRecorder.failTooBig();
		assertThat(compressionStats.getCompressionRuns(), contains(
				matchesCompressionRun("GZIP", equalTo(0L), 1024, -2)
		));
	}

	private final Instant now = Instant.now();
	private final SettableClock testClock = new SettableClock(now);
	private final CompressionStats compressionStats = new CompressionStats(testClock);
	private final CompressionRunRecorder compressionRunRecorder = compressionStats.startCompressionRun("GZIP", 1024);

}
