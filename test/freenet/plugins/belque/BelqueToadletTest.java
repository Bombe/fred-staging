package freenet.plugins.belque;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;

import freenet.client.HighLevelSimpleClient;
import freenet.clients.http.RedirectException;
import freenet.clients.http.ToadletContext;
import freenet.clients.http.ToadletContextClosedException;
import freenet.support.api.HTTPRequest;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import org.junit.Test;

public class BelqueToadletTest {

	private final HighLevelSimpleClient highLevelSimpleClient = mock(HighLevelSimpleClient.class);
	private final BelqueToadlet belqueToadlet = new BelqueToadlet(highLevelSimpleClient);

	@Test
	public void pathIsReturnedCorrectly() {
		assertThat(belqueToadlet.path(), equalTo("/belque/"));
	}

	@Test
	public void getRequestCanBeProcessed()
			throws IOException, ToadletContextClosedException, RedirectException, URISyntaxException {
		URI uri = new URI("");
		HTTPRequest httpRequest = mock(HTTPRequest.class);
		ToadletContext toadletContext = mock(ToadletContext.class);
		belqueToadlet.handleMethodGET(uri, httpRequest, toadletContext);
	}

}
