package freenet.clients.fcp;

import freenet.clients.fcp.FCPMessage;
import freenet.support.node.UserAlert;

public interface FCPUserAlert extends UserAlert {

	/**
	 * @return A FCPMessage that is sent subscribing FCPClients
	 */
	public FCPMessage getFCPMessage();

}
