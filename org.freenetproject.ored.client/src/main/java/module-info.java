module org.freenetproject.ored.client {
    requires org.freenetproject.ored.support;
    requires org.freenetproject.ored.crypt;
    requires org.freenetproject.ored.l10n;
    requires org.freenetproject.ored.config;
    requires org.bouncycastle.provider;
    requires freenet.ext;
    requires java.naming;

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
}