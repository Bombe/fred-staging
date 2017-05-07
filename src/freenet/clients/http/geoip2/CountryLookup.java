package freenet.clients.http.geoip2;

import java.net.InetAddress;

/**
 * A {@code CountryLookup} can convert an {@link InetAddress} to an ISO 3166-1 alpha-2 country code.
 */
public interface CountryLookup {

    /**
     * Looks up the given address and returns the ISO 3166-1 alpha-2 code for the country the
     * address is believed to be in.
     *
     * @param address
     *         The address to look up
     * @return The ISO 3166-1 alpha-2 country code, or {@code null} if the address could not be
     * located.
     */
    String getCountry(InetAddress address);

}
