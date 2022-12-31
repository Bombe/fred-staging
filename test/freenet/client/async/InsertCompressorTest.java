package freenet.client.async;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Random;

import freenet.client.InsertContext;
import freenet.config.Config;
import freenet.config.SubConfig;
import freenet.node.stats.CompressionStats;
import freenet.support.Executor;
import freenet.support.api.BucketFactory;
import freenet.support.api.IntCallback;
import freenet.support.api.RandomAccessBucket;
import freenet.support.io.ArrayBucketFactory;
import org.junit.Test;

import static freenet.client.InsertContext.CompatibilityMode.COMPAT_DEFAULT;
import static freenet.support.io.BucketTools.toRandomAccessBucket;
import static freenet.test.matcher.CompressionRunMatcher.matchesCompressionRun;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;

/**
 * Unit test for {@link InsertCompressor}.
 */
public class InsertCompressorTest {

	@Test
	public void canCreateInsertCompressorWithoutCompressionStats() {
		new InsertCompressor(inserter, null, 0, null, false, 0, false, null);
	}

	@Test
	public void compressionStatisticsAreCorrect() throws Exception {
		initializeDataToCompress(new byte[1024]);
		insertCompressor.tryCompress(clientContext);
		/* this needs to be adjusted every time we change compression algorithms. */
		assertThat(compressionStats.getCompressionRuns(), containsInAnyOrder(
				matchesCompressionRun("GZIP", 1024, 29),
				matchesCompressionRun("BZIP2", 1024, 40),
				matchesCompressionRun("LZMA_NEW", 1024, 23)
		));
	}

	@Test
	public void uncompressableContentIsRecordedCorrectly() throws Exception {
		initializeDataToCompress(generateRandomData());
		insertCompressor.tryCompress(clientContext);
		/* this needs to be adjusted every time we change compression algorithms. */
		assertThat(compressionStats.getCompressionRuns(), containsInAnyOrder(
				matchesCompressionRun("GZIP", 1024, -2),
				matchesCompressionRun("BZIP2", 1024, -2),
				matchesCompressionRun("LZMA_NEW", 1024, -2)
		));
	}

	private void initializeDataToCompress(byte[] b) throws IOException {
		try (OutputStream bucketOutputStream = originalData.getOutputStream()) {
			bucketOutputStream.write(b);
		}
	}

	private static byte[] generateRandomData() {
		byte[] buffer = new byte[1024];
		// hardcoded seed so we always generate the same data
		new Random(0).nextBytes(buffer);
		return buffer;
	}

	private static SingleFileInserter createSingleFileInserter() {
		InsertContext insertContext = new InsertContext(0, 0, 0, 0, null, false, false, false, null, 0, 0, COMPAT_DEFAULT);
		return new SingleFileInserter(null, null, null, false, insertContext, false, false, false, null, null, false, null, false, false, 0, 0, null, (byte) 0, null, 0);
	}

	private static Executor createNullExecutor() {
		return new Executor() {
			@Override
			public void execute(Runnable job) {
			}

			@Override
			public void execute(Runnable job, String jobName) {
			}

			@Override
			public void execute(Runnable job, String jobName, boolean fromTicker) {
			}

			@Override
			public int[] waitingThreads() {
				return new int[0];
			}

			@Override
			public int[] runningThreads() {
				return new int[0];
			}

			@Override
			public int getWaitingThreadsCount() {
				return 0;
			}
		};
	}

	private final SingleFileInserter inserter = createSingleFileInserter();
	private final BucketFactory bucketFactory = new ArrayBucketFactory();
	private final RandomAccessBucket originalData = toRandomAccessBucket(bucketFactory.makeBucket(1024), bucketFactory);
	private final Config config = new Config();
	private final CompressionStats compressionStats = new CompressionStats();
	private final Executor mainExecutor = createNullExecutor();
	private final ClientContext clientContext = new ClientContext(0, null, mainExecutor, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, config);

	{
		SubConfig nodeConfig = config.createSubConfig("node");
		nodeConfig.register("amountOfDataToCheckCompressionRatio", 0L, 0, false, false, "", "", null, false);
		nodeConfig.register("minimumCompressionPercentage", 0, 0, false, false, "", "", (IntCallback) null, false);
		nodeConfig.register("maxTimeForSingleCompressor", Integer.MAX_VALUE, 0, false, false, "", "", (IntCallback) null, false);
	}

	private final InsertCompressor insertCompressor = new InsertCompressor(inserter, originalData, 0, bucketFactory, false, 0, false, config, compressionStats);

	public InsertCompressorTest() throws IOException {
		// needed for the exception declared by bucketFactory.makeBucket()
	}

}
