package freenet.clients.http;

import freenet.client.HighLevelSimpleClient;
import freenet.node.NodeClientCore;
import freenet.node.fcp.FCPServer;

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

}
