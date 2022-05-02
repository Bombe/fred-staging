package freenet.client.async;

import freenet.support.fcp.RequestIdentifier;

// TODO: Modularity: Make PersistentRequestRoot implement this
public interface PersistentRequestChecker {
    boolean hasRequest(RequestIdentifier req);
}
