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

    // TODO: Modularity: Remove this method from class ToadletContextImpl
    public static Date parseHTTPDate(String httpDate) throws java.text.ParseException{
        SimpleDateFormat sdf = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US);
        sdf.setTimeZone(TZ_UTC);
        return sdf.parse(httpDate);
    }
}
