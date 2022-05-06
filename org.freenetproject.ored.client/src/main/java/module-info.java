module org.freenetproject.ored.client {
    exports freenet.keys;
    exports freenet.bucket;
    exports freenet.checksum;
    exports freenet.client;
    exports freenet.client.async;
    exports freenet.client.events;
    exports freenet.client.filter;
    exports freenet.client.request;
    exports freenet.compress;
    exports freenet.lockablebuffer;
    exports freenet.http;

    requires org.freenetproject.ored.support;
    requires org.freenetproject.ored.crypt;
    requires org.freenetproject.ored.l10n;
    requires org.freenetproject.ored.config;
    requires org.bouncycastle.provider;
    requires org.apache.commons.compress;
    requires org.freenetproject.ext;
    requires org.tanukisoftware.wrapper;
    requires java.naming;
}