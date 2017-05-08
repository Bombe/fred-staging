## Building Freenet from source: Short version

Install Gradle:
        For Debian based distros, `sudo apt-get install gradle`.
        For CentOS, `sudo yum install gradle`.

Then just execute `gradle jar`.

You can run your version of Freenet by stopping your node, copying `build/libs/freenet.jar` into your Freenet folder and starting your node again.

To override values of variables set in build.gradle by putting them into the file gradle.properties in the format `variable = value`.

Mine looks like the following:

org.gradle.parallel = true
org.gradle.daemon = true
org.gradle.jvmargs=-Xms256m -Xmx1024m
org.gradle.configureondemand=true

tasks.withType(Test)  {
  maxParallelForks = Runtime.runtime.availableProcessors()
}

## Using the `use-geoip2-database` branch

This branch replaces our support for the legacy GeoIP database with support for the more modern GeoIP2 database. In a single file it includes country data for both IPv4 and IPv6 addresses.

Build it using Gradle, just like described above. However, for running it you need to include the four JAR files “maxmind-db-*version*.jar,” “jackson-core-*version*.jar,” “jackson-annotations-*version*.jar,” and “jackson-databind-*version*.jar” in the CLASSPATH. After running Gradle they are located somewhere in your `~/.gradle` folder.

You will also need the GeoLite2-Country database (`GeoLite2-Country.mmdb`, get it from [maxmind.com](http://dev.maxmind.com/geoip/geoip2/geolite2/)) in the `geoip2` folder in the root of the project. Only if the file is found there it will be included in the `freenet.jar` file.
