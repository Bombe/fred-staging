package freenet.client.request;

import freenet.support.LightweightException;

abstract public class LowLevelException extends LightweightException {
    public LowLevelException() {
        super();
    }

    public LowLevelException(String message) {
        super(message);
    }

    public LowLevelException(Throwable cause) {
        super(cause);
    }

    public LowLevelException(String message, Throwable cause) {
        super(message, cause);
    }

}
