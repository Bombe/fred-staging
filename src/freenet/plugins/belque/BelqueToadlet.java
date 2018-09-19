package freenet.plugins.belque;

import freenet.client.HighLevelSimpleClient;
import freenet.clients.http.RedirectException;
import freenet.clients.http.Toadlet;
import freenet.clients.http.ToadletContext;
import freenet.clients.http.ToadletContextClosedException;
import freenet.support.api.HTTPRequest;
import java.io.IOException;
import java.net.URI;

public class BelqueToadlet extends Toadlet {

	public BelqueToadlet(HighLevelSimpleClient highLevelSimpleClient) {
		super(highLevelSimpleClient);
	}

	@Override
	public void handleMethodGET(URI uri, HTTPRequest httpRequest, ToadletContext toadletContext)
			throws ToadletContextClosedException, IOException, RedirectException {

	}

	@Override
	public String path() {
		return "/belque/";
	}

}
