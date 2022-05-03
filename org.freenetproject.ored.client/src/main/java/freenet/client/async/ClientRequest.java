package freenet.client.async;

import freenet.checksum.ChecksumChecker;
import freenet.support.fcp.RequestIdentifier;
import freenet.support.io.ResumeFailedException;
import freenet.support.io.StorageFormatException;

import java.io.DataInputStream;
import java.io.IOException;

public interface ClientRequest extends PersistentClientCallback {

    /** Called just before the final write when the node is shutting down. Should write any dirty
     * data to disk etc. */
    void onShutdown(ClientContext context);

    /** Get the RequestIdentifier. This just includes the queue and the identifier. */
    RequestIdentifier getRequestIdentifier();

    /** Return true if we resumed the original fetch from stored data (usually a file for a
     * splitfile download), rather than having to restart it (which happens in most other cases
     * when we resume). */
    boolean fullyResumed();

    /** Start the request, if it has not already been started. */
    void start(ClientContext context);

    void cancel(ClientContext context);

}
