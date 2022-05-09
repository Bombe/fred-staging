/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.clients.http;

import freenet.bucket.Bucket;
import freenet.http.SimpleHTTPRequest;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Used for passing all HTTP request information to the FredPlugin that handles the
 * request. It parses the query string and has several methods for accessing the request
 * parameter values.
 *
 * @author nacktschneck
 */
public class ToadletHTTPRequest extends SimpleHTTPRequest {

	public ToadletHTTPRequest(URI uri, String method) {
		super(uri, method);
	}

	public ToadletHTTPRequest(String path, String encodedQueryString, String method) throws URISyntaxException {
		super(path, encodedQueryString, method);
	}

	/**
	 * Creates a new HTTPRequest for the given URI and data.
	 * @param uri The URI being requested
	 * @param d The data
	 * @param ctx The toadlet context (for headers and bucket factory)
	 * @throws URISyntaxException if the URI is invalid
	 */
	public ToadletHTTPRequest(URI uri, Bucket d, ToadletContext ctx, String method) {
		super(uri, ctx.getHeaders(), d, ctx.getBucketFactory(), method);
	}

}
