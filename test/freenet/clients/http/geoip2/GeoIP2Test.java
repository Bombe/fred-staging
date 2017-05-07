package freenet.clients.http.geoip2;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 * Unit test for {@link GeoIP2}.
 */
public class GeoIP2Test {

    @Rule
    public final ExpectedException expectedException = ExpectedException.none();

    private final GeoIP2 geoIP2;

    public GeoIP2Test() throws IOException {
        /* FIXME – in a better world we could use getClass().getResourceAsStream(…) here. */
        geoIP2 = new GeoIP2(new FileInputStream("test/freenet/clients/http/geoip2/freenet-test-db.mmdb"));
    }

    @Test
    public void lookupThrowsNPEIfAddressIsNull() {
        expectedException.expect(NullPointerException.class);
        geoIP2.getCountry(null);
    }

    @Test
    public void lookingUpADefinedIpV4AddressReturnsExpectedResult() throws UnknownHostException {
        InetAddress inetAddress = InetAddress.getByName("1.2.3.4");
        assertThat(geoIP2.getCountry(inetAddress), equalTo("X0"));
    }

    @Test
    public void lookingUpAnUndefinedIpV4AddressReturnsNull() throws UnknownHostException {
        InetAddress inetAddress = InetAddress.getByName("1.2.3.5");
        assertThat(geoIP2.getCountry(inetAddress), nullValue());
    }

    @Test
    public void lookingUpADefinedIpV4AddressBySubnetReturnsExpectedResult() throws UnknownHostException {
        InetAddress inetAddress = InetAddress.getByName("2.3.4.5");
        assertThat(geoIP2.getCountry(inetAddress), equalTo("X1"));
    }

    @Test
    public void lookingUpADefinedIpV6AddressReturnsExpectedResult() throws UnknownHostException {
        InetAddress inetAddress = InetAddress.getByName("1:2:3:4:5:6:7:8");
        assertThat(geoIP2.getCountry(inetAddress), equalTo("X2"));
    }

    @Test
    public void lookingUpAnIpV6AddressInADefinedSubnetReturnsExpectedResult() throws UnknownHostException {
        InetAddress inetAddress = InetAddress.getByName("2:3:5:6:7:8:9:10");
        assertThat(geoIP2.getCountry(inetAddress), equalTo("X3"));
    }

    @Test
    public void lookingUpAnUndefinedIpV6AddressReturnsNull() throws UnknownHostException {
        InetAddress inetAddress = InetAddress.getByName("3:4:5:6:7:8:9:10");
        assertThat(geoIP2.getCountry(inetAddress), nullValue());
    }

}
