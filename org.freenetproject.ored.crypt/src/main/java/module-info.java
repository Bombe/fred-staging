module org.freenetproject.ored.crypt {
    exports freenet.crypt;
    exports freenet.crypt.ciphers;

    requires org.freenetproject.ored.support;
    requires org.bouncycastle.provider;
    requires org.freenetproject.ext;
    requires org.tanukisoftware.wrapper;
}