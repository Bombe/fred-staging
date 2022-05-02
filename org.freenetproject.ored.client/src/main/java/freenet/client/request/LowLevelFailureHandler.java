package freenet.client.request;

import freenet.client.async.ClientContext;

public interface LowLevelFailureHandler {
    void onFailure(LowLevelException e, SendableRequestItem keyNum, ClientContext context);
}
