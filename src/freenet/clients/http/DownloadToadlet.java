package freenet.clients.http;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

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

		if (request.isPartSet("select-location")) {
			try {
				throw new RedirectException(LocalDirectoryConfigToadlet.basePath() + "/downloads/");
			} catch (URISyntaxException use1) {
				/* The path should really not be invalid. */
			}
		}

		super.handleMethodPOST(uri, request, toadletContext);
	}

}
