package freenet.client.async;

import java.io.IOException;
import java.io.OutputStream;

import freenet.client.InsertContext;
import freenet.client.InsertException;
import freenet.client.async.InsertCompressor.CompressionMetrics;
import freenet.config.Config;
import freenet.config.InvalidConfigValueException;
import freenet.config.NodeNeedRestartException;
import freenet.config.SubConfig;
import freenet.support.Executor;
import freenet.support.api.BucketFactory;
import freenet.support.api.IntCallback;
import freenet.support.api.RandomAccessBucket;
import freenet.support.compress.Compressor.COMPRESSOR_TYPE;
import freenet.support.compress.InvalidCompressionCodecException;
import freenet.support.io.ArrayBucketFactory;
import org.junit.Test;

import static freenet.client.InsertContext.CompatibilityMode.COMPAT_DEFAULT;
import static freenet.support.io.BucketTools.toRandomAccessBucket;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;

public class InsertCompressorTest {

	@Test
	public void canCreateInsertCompressorWithoutCompressionMetrics() {
		SingleFileInserter inserter = createSingleFileInserter();
		new InsertCompressor(inserter, null, 0, null, false, 0, false, null);
	}

	@Test
	public void startingACompressorIsCounted() throws InsertException, IOException, NodeNeedRestartException, InvalidConfigValueException, InvalidCompressionCodecException {
		SingleFileInserter inserter = createSingleFileInserter();
		BucketFactory bucketFactory = new ArrayBucketFactory();
		RandomAccessBucket originalData = toRandomAccessBucket(bucketFactory.makeBucket(1024), bucketFactory);
		try (OutputStream bucketOutputStream = originalData.getOutputStream()) {
			bucketOutputStream.write(new byte[1024]);
		}
		Config config = new Config();
		SubConfig nodeConfig = config.createSubConfig("node");
		nodeConfig.register("amountOfDataToCheckCompressionRatio", 0L, 0, false, false, "", "", null, false);
		nodeConfig.register("minimumCompressionPercentage", 0, 0, false, false, "", "", (IntCallback) null, false);
		nodeConfig.register("maxTimeForSingleCompressor", Integer.MAX_VALUE, 0, false, false, "", "", (IntCallback) null, false);
		CompressionMetrics compressionMetrics = new CompressionMetrics();
		InsertCompressor insertCompressor = new InsertCompressor(inserter, originalData, 0, bucketFactory, false, 0, false, config, compressionMetrics);
		Executor mainExecutor = createNullExecutor();
		ClientContext clientContext = new ClientContext(0, null, mainExecutor, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, config);
		insertCompressor.tryCompress(clientContext);
		assertThat(compressionMetrics.getRuns(), hasSize(COMPRESSOR_TYPE.getCompressorsArray(null).length));
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

}
