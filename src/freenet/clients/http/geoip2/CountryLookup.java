package freenet.clients.http.geoip2;

import java.net.InetAddress;

/**
 * A {@code CountryLookup} can convert an {@link InetAddress} to a {@link Country}.
 */
public interface CountryLookup {

    /**
     * Looks up the given address and returns the country the address is believed to be in.
     *
     * @param address
     *         The address to look up
     * @return The country, or {@code null} if the address could not be located.
     */
    Country getCountry(InetAddress address);

}
