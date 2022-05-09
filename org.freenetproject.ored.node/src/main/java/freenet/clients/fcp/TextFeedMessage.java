package freenet.clients.fcp;

import java.io.UnsupportedEncodingException;

import freenet.bucket.Bucket;
import freenet.bucket.ArrayBucket;
import freenet.bucket.NullBucket;

public class TextFeedMessage extends N2NFeedMessage {

	public static final String NAME = "TextFeed";

	public TextFeedMessage(String header, String shortText, String text, short priorityClass, long updatedTime,
			String sourceNodeName, long composed, long sent, long received, String messageText) {
		super(header, shortText, text, priorityClass, updatedTime, sourceNodeName, composed, sent, received);
		final Bucket messageTextBucket;
		try {
			if (messageText != null)
				messageTextBucket = new ArrayBucket(messageText.getBytes("UTF-8"));
			else
				messageTextBucket = new NullBucket();
		}
		catch (UnsupportedEncodingException e) {
			throw new Error("Impossible: JVM doesn't support UTF-8: " + e, e);
		}
		buckets.put("MessageText", messageTextBucket);
	}

	@Override
	public String getName() {
		return NAME;
	}

}
