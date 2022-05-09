package freenet.clients.fcp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import freenet.bucket.Bucket;
import freenet.bucket.BucketFactory;
import freenet.bucket.BucketTools;
import freenet.node.Node;
import freenet.support.SimpleFieldSet;

public class GeneratedMetadataMessage extends BaseDataCarryingMessage {

	GeneratedMetadataMessage(String identifier, boolean global, Bucket data) {
		this.identifier = identifier;
		this.global = global;
		this.data = data;
	}

	private final Bucket data;

	final String identifier;

	final boolean global;

	static final String NAME = "GeneratedMetadata";

	@Override
	long dataLength() {
		return data.size();
	}

	@Override
	public void readFrom(InputStream is, BucketFactory bf, FCPServer server)
			throws IOException, MessageInvalidException {
		throw new UnsupportedOperationException();
	}

	@Override
	protected void writeData(OutputStream os) throws IOException {
		BucketTools.copyTo(data, os, data.size());
	}

	@Override
	public SimpleFieldSet getFieldSet() {
		SimpleFieldSet fs = new SimpleFieldSet(true);
		fs.putSingle("Identifier", identifier);
		fs.put("Global", global);
		fs.put("DataLength", data.size());
		return fs;
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
		throw new UnsupportedOperationException();
	}

}
