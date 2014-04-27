package freenet.clients.http;

import java.io.IOException;
import java.net.URI;

import freenet.client.HighLevelSimpleClient;
import freenet.node.NodeClientCore;
import freenet.node.fcp.FCPServer;
import freenet.support.api.HTTPRequest;

/**
 * {@link Toadlet} implementation that manages downloads.
 *
 * @author <a href="mailto:bombe@pterodactylus.net">David ‘Bombe’ Roden</a>
 */
public class DownloadToadlet extends QueueToadlet {

	public DownloadToadlet(NodeClientCore core, FCPServer fcp, HighLevelSimpleClient client) {
		super(core, fcp, client, false);
	}

	public void handleMethodPOST(URI uri, HTTPRequest request, final ToadletContext toadletContext) throws ToadletContextClosedException, IOException, RedirectException {
		if (container.publicGatewayMode() && !toadletContext.isAllowedFullAccess()) {
			sendUnauthorizedPage(toadletContext);
			return;
		}

		super.handleMethodPOST(uri, request, toadletContext);
	}

}
