package freenet.client.async;

import freenet.bucket.RandomAccessBucket;
import freenet.crypt.HashResult;
import freenet.compress.Compressor.COMPRESSOR_TYPE;

class CompressionOutput {
	public CompressionOutput(RandomAccessBucket bestCompressedData, COMPRESSOR_TYPE bestCodec2, HashResult[] hashes) {
		this.data = bestCompressedData;
		this.bestCodec = bestCodec2;
		this.hashes = hashes;
	}
	final RandomAccessBucket data;
	final COMPRESSOR_TYPE bestCodec;
	final HashResult[] hashes;
}