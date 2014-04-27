package freenet.clients.http;

import freenet.client.HighLevelSimpleClient;
import freenet.node.NodeClientCore;
import freenet.node.fcp.FCPServer;

/**
 * {@link Toadlet} implementation that manages downloads.
 *
 * @author <a href="mailto:bombe@pterodactylus.net">David ‘Bombe’ Roden</a>
 */
public class DownloadToadlet extends QueueToadlet {

	public DownloadToadlet(NodeClientCore core, FCPServer fcp, HighLevelSimpleClient client) {
		super(core, fcp, client, false);
	}

}
