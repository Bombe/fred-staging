module org.freenetproject.ored.node {
    requires org.freenetproject.ored.support;
    requires org.freenetproject.ored.crypt;
    requires org.freenetproject.ored.l10n;
    requires org.freenetproject.ored.config;
    requires org.freenetproject.ored.client;
    requires org.freenetproject.ored.store;
    requires org.freenetproject.ext;
    requires org.tanukisoftware.wrapper;
    requires com.sun.jna;
    requires com.sun.jna.platform;
    requires jdk.management;
    requires java.naming;
    requires net.harawata.appdirs;

    exports freenet.pluginmanager;
    exports freenet.clients.http;
    exports freenet.clients.fcp;
}