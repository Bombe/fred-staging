package freenet.node;

import freenet.client.HighLevelSimpleClient;
import freenet.client.async.USKManager;
import freenet.client.request.PriorityClasses;
import freenet.clients.http.FProxyToadlet;

public class NodeUSKManager extends USKManager {

	public NodeUSKManager(NodeClientCore core) {
		super(newClientFromCore(core), core.getExecutor());
	}

	private static HighLevelSimpleClient newClientFromCore(NodeClientCore core) {
		HighLevelSimpleClient client = core.makeClient(PriorityClasses.UPDATE_PRIORITY_CLASS, false, false);
		client.setMaxIntermediateLength(FProxyToadlet.MAX_LENGTH_NO_PROGRESS);
		client.setMaxLength(FProxyToadlet.MAX_LENGTH_NO_PROGRESS);
		return client;
	}

}
