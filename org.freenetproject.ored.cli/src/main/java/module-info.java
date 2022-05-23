module org.freenetproject.ored.cli {
    requires info.picocli;

    opens freenet.cli to info.picocli;
    opens freenet.cli.subcommand to info.picocli;
}