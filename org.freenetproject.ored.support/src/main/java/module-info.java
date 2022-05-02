module org.freenetproject.ored.support {
    exports freenet.support;
    exports freenet.support.api;
    exports freenet.support.client;
    exports freenet.support.io;
    exports freenet.support.math;
    exports freenet.support.node;
    exports freenet.support.fcp;

    requires org.bouncycastle.provider;
    requires freenet.ext;
    requires com.sun.jna;
    requires com.sun.jna.platform;
}