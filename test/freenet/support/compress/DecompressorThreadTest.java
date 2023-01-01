package freenet.support.compress;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PipedInputStream;

import freenet.node.stats.CompressionStats;
import freenet.support.compress.DecompressorThreadManager.DecompressorThread;
import org.junit.Test;

import static freenet.support.compress.Compressor.COMPRESSOR_TYPE.GZIP;
import static freenet.test.matcher.OperationRunMatcher.matchesOperationRun;
import static java.util.Collections.emptyList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;

/**
 * Unit test for {@link DecompressorThread}.
 */
public class DecompressorThreadTest {

	@Test
	public void canCreateDecompressorThread() {
		new DecompressorThread(null, null, null, null, 0);
	}

	@Test
	public void decompressionStatsAreCountedCorrectly() throws IOException {
		byte[] compressedBuffer = createGzipCompressedEmptyData();
		runDecompressionAndVerifySizeAfterOperation(compressedBuffer, 0);
	}

	@Test
	public void decompressionWithErrorIsCountedCorrectly() throws IOException {
		byte[] compressedBuffer = createGzipCompressedEmptyData();
		compressedBuffer[0]++; // invalid to decode
		runDecompressionAndVerifySizeAfterOperation(compressedBuffer, -1);
	}

	private static byte[] createGzipCompressedEmptyData() {
		return new byte[] { 0x1f, (byte) 0x8b, 0x08, 0x00, (byte) 0xbf, 0x55, (byte) 0xb0, 0x63, 0x02, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0x00 };
	}

	private static void runDecompressionAndVerifySizeAfterOperation(byte[] buffer, int sizeAfterOperation) throws IOException {
		DecompressorThreadManager manager = new DecompressorThreadManager(new PipedInputStream(), emptyList(), 100);
		CompressionStats compressionStats = new CompressionStats();
		DecompressorThread decompressorThread;
		try (ByteArrayInputStream inputStream = new ByteArrayInputStream(buffer);
			 ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
			decompressorThread = new DecompressorThread(GZIP, manager, inputStream, outputStream, 20, compressionStats);
			decompressorThread.run();
		}
		assertThat(compressionStats.getDecompressionRuns(), contains(
				matchesOperationRun("GZIP", 20, sizeAfterOperation)
		));
	}

}
