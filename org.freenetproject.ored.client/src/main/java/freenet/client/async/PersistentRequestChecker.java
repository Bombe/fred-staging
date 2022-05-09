package freenet.client.async;

import freenet.support.fcp.RequestIdentifier;

public interface PersistentRequestChecker {

	boolean hasRequest(RequestIdentifier req);

}
