package freenet.clients.http.geoip2;

import java.util.Locale;

/**
 * Contains information about a country.
 */
public interface Country {

    /**
     * Returns the 2-letter ISO 3166-1 alpha-2 code for this country.
     *
     * @return The ISO 3166-1 alpha-2 code for this country
     */
    String getIsoCode();

    /**
     * Returns the name for this country in the specified locale. If no name exists for the given
     * locale, the English name is returned.
     *
     * @param locale
     *         The locale to get the name of this country for
     * @return The name of this country for the given locale, or the English name if there is no
     * name for the given locale
     */
    String getName(Locale locale);

}
