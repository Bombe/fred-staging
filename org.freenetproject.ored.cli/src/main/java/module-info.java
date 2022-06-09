module org.freenetproject.ored.cli {
    requires java.net.http;
    requires info.picocli;
    requires org.apache.commons.lang3;
    requires org.freenetproject.ored.support;
    requires net.harawata.appdirs;

    opens freenet.cli to info.picocli;
    opens freenet.cli.subcommand to info.picocli;
}