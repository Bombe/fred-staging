package freenet.support;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import static freenet.support.TimeUtil.TZ_UTC;

public class Toadlet {

    // TODO: Modularity: Remove these constants from class FProxyToadlet
    public static class FProxy {
        /** Maximum size for transparent pass-through. See config passthroughMaxSizeProgress */
        public static long MAX_LENGTH_WITH_PROGRESS = (100*1024*1024) * 11 / 10; // 100MiB plus a bit due to buggy inserts, because our Windows installer is >70 MiB nowadays
        public static long MAX_LENGTH_NO_PROGRESS = (2*1024*1024) * 11 / 10; // 2MiB plus a bit due to buggy inserts
    }

    // TODO: Modularity: Remove these code from class ExternalLinkToadlet
    public static class ExternalLink {
        public static final String PATH = "/external-link/";
        public static final String magicHTTPEscapeString = "_CHECKED_HTTP_";

        /**
         * Prepends a given URI with the path and parameter names to get this external link confirmation page.
         * @param uri URI to prompt for confirmation.
         * @return String appropriate for a link.
         */
        public static String escape(String uri) {
            return PATH+"?" + magicHTTPEscapeString + '=' + uri;
        }
    }

    // TODO: Modularity: Remove these constants from class StaticToadlet
    public static class Static {
        public static final String ROOT_URL = "/static/";
        public static final String ROOT_PATH = "staticfiles/";
        public static final String OVERRIDE = "override/";
        public static final String OVERRIDE_URL = ROOT_URL + OVERRIDE;
    }

    // TODO: Modularity: Remove this method from class ToadletContextImpl
    public static Date parseHTTPDate(String httpDate) throws java.text.ParseException{
        SimpleDateFormat sdf = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US);
        sdf.setTimeZone(TZ_UTC);
        return sdf.parse(httpDate);
    }
}
