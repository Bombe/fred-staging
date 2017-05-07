package freenet.clients.http.geoip2;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;

import freenet.support.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.maxmind.db.CHMCache;
import com.maxmind.db.Reader;

/**
 * Handles a GeoIP2 database file and can look up the country for an {@link InetAddress}.
 */
public class GeoIP2 implements CountryLookup {

    private final Reader reader;

    public GeoIP2(InputStream inputStream) throws IOException {
        reader = new Reader(inputStream, new CHMCache());
    }

    @Override
    public String getCountry(InetAddress address) {
        if (address == null) {
            throw new NullPointerException("address must not be null");
        }
        try {
            JsonNode result = reader.get(address);
            if (result != null) {
                if (result.has("country")) {
                    if (result.get("country").has("iso_code")) {
                        return result.get("country").get("iso_code").asText();
                    }
                }
            }
        } catch (IOException ioe1) {
            Logger.warning(GeoIP2.class, "Could not read GeoIP2 database", ioe1);
        }
        return null;
    }

}
