package freenet.clients.http.geoip2;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;

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
    public Country getCountry(InetAddress address) {
        if (address == null) {
            throw new NullPointerException("address must not be null");
        }
        try {
            JsonNode result = reader.get(address);
            if (result != null) {
                if (result.has("country")) {
                    if (result.get("country").has("iso_code")) {
                        return createCountry(result);
                    }
                }
            }
        } catch (IOException ioe1) {
            Logger.warning(GeoIP2.class, "Could not read GeoIP2 database", ioe1);
        }
        return null;
    }

    private static Country createCountry(JsonNode result) {
        CountryImpl country = new CountryImpl(result.get("country").get("iso_code").asText());
        for (Iterator<Entry<String, JsonNode>> names = result.get("country").get("names").fields(); names.hasNext(); ) {
            Entry<String, JsonNode> name = names.next();
            country.addName(name.getKey(), name.getValue().asText());
        }
        return country;
    }

    private static class CountryImpl implements Country {

        private final String isoCode;
        private final Map<String, String> names = new HashMap<>();

        private CountryImpl(String isoCode) {
            this.isoCode = isoCode;
        }

        private void addName(String locale, String name) {
            names.put(locale, name);
        }

        @Override
        public String getIsoCode() {
            return isoCode;
        }

        @Override
        public String getName(Locale locale) {
            String name = names.get(locale.getLanguage());
            return (name != null) ? name : names.get("en");
        }

    }

}
