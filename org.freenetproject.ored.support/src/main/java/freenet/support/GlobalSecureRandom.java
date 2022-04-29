package freenet.support;

import java.security.SecureRandom;

public class GlobalSecureRandom {
    /** Static instance of SecureRandom, as opposed to Node's copy. @see getSecureRandom() */
    private static SecureRandom globalSecureRandom;

    // TODO: Modularity: remove getGlobalSecureRandom from NodeStarter
    public static synchronized SecureRandom getGlobalSecureRandom() {
        if(globalSecureRandom == null) {
            globalSecureRandom = new SecureRandom();
            globalSecureRandom.nextBytes(new byte[16]); // Force it to seed itself so it blocks now not later.
        }
        return globalSecureRandom;
    }
}
