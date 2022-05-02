package freenet.client.async;

import freenet.checksum.ChecksumChecker;
import freenet.support.fcp.RequestIdentifier;
import freenet.support.io.ResumeFailedException;
import freenet.support.io.StorageFormatException;

import java.io.DataInputStream;
import java.io.IOException;

@FunctionalInterface
public interface ClientRequestRestarter {
    ClientRequest restartFrom(DataInputStream dis, RequestIdentifier reqID,
                              ClientContext context, ChecksumChecker checker) throws StorageFormatException, IOException, ResumeFailedException;
}
