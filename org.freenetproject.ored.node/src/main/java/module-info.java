module org.freenetproject.ored.node {
    requires java.naming;
    requires jdk.management;
    requires jdk.management.agent;

    requires org.freenetproject.ored.support;
    requires org.freenetproject.ored.crypt;
    requires org.freenetproject.ored.l10n;
    requires org.freenetproject.ored.config;
    requires org.freenetproject.ored.client;
    requires org.freenetproject.ored.store;
    requires org.freenetproject.ored.cli;
    requires org.freenetproject.ext;

    requires org.tanukisoftware.wrapper;
    requires com.sun.jna;
    requires com.sun.jna.platform;
    requires net.harawata.appdirs;
    requires org.greenrobot.eventbus;

    exports freenet.pluginmanager;
    exports freenet.clients.http;
    exports freenet.clients.fcp;

    opens freenet.node to org.greenrobot.eventbus;
}