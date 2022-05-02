package freenet.client.request;

import freenet.keys.Key;
import freenet.keys.KeyBlock;
import freenet.keys.KeyBlockStore;

public interface NodeClientRequest {

    KeyBlockStore getKeyBlockStore();

    void asyncGet(final Key key, boolean offersOnly, final RequestCompletionListener listener, boolean canReadClientCache, boolean canWriteClientCache, final boolean realTimeFlag, boolean localOnly, boolean ignoreStore);
    void realPut(KeyBlock block, boolean canWriteClientCache, boolean forkOnCacheable, boolean preferInsert, boolean ignoreLowBackoff, boolean realTimeFlag) throws LowLevelPutException;
}
