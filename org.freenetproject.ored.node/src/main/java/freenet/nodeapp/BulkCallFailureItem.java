package freenet.nodeapp;

import freenet.client.request.LowLevelGetException;

public class BulkCallFailureItem {
	
	public final LowLevelGetException e;
	public final Object token;
	
	public BulkCallFailureItem(LowLevelGetException e, Object token) {
		this.e = e;
		this.token = token;
	}

}
