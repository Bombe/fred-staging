package freenet.clients.http;

import java.io.IOException;
import java.net.URI;

import freenet.client.HighLevelSimpleClient;
import freenet.node.NodeClientCore;
import freenet.node.fcp.FCPServer;
import freenet.support.api.HTTPRequest;

/**
 * {@link Toadlet} implementation that manages inserts.
 *
 * @author <a href="mailto:bombe@pterodactylus.net">David ‘Bombe’ Roden</a>
 */
public class UploadToadlet extends QueueToadlet {

	public UploadToadlet(NodeClientCore core, FCPServer fcp, HighLevelSimpleClient client, FileInsertWizardToadlet fileInsertWizardToadlet) {
		super(core, fcp, client, true);
		setFIW(fileInsertWizardToadlet);
	}

	public void handleMethodPOST(URI uri, HTTPRequest request, final ToadletContext toadletContext) throws ToadletContextClosedException, IOException, RedirectException {
		if (container.publicGatewayMode() && !toadletContext.isAllowedFullAccess()) {
			sendUnauthorizedPage(toadletContext);
			return;
		}

		super.handleMethodPOST(uri, request, toadletContext);
	}

}
