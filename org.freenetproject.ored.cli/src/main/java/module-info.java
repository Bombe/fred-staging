module org.freenetproject.ored.cli {
    requires java.net.http;
    requires jdk.attach;
    requires java.management;
    requires info.picocli;
    requires org.freenetproject.ored.support;
    requires net.harawata.appdirs;
    requires com.sun.jna;
    requires com.sun.jna.platform;
    requires org.tanukisoftware.wrapper;

    opens freenet.cli to info.picocli;
    opens freenet.cli.subcommand to info.picocli, com.sun.jna;
    opens freenet.cli.mixin to info.picocli;
}