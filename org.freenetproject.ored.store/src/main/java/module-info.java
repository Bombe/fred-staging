module org.freenetproject.ored.store {
    exports freenet.store;
    exports freenet.store.caching;
    exports freenet.store.saltedhash;

    requires org.freenetproject.ored.support;
    requires org.freenetproject.ored.crypt;
    requires org.freenetproject.ored.l10n;
    requires org.freenetproject.ored.client;
    requires org.freenetproject.ext;
    requires org.tanukisoftware.wrapper;
}