package freenet.clients.http;

import static freenet.support.Logger.registerLogThresholdCallback;
import static freenet.support.Logger.shouldLog;
import static java.lang.String.format;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;

import freenet.client.HighLevelSimpleClient;
import freenet.keys.FreenetURI;
import freenet.node.NodeClientCore;
import freenet.node.fcp.FCPServer;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.MultiValueTable;
import freenet.support.api.HTTPRequest;

/**
 * {@link Toadlet} implementation that manages inserts.
 *
 * @author <a href="mailto:bombe@pterodactylus.net">David ‘Bombe’ Roden</a>
 */
public class UploadToadlet extends QueueToadlet {

	private static volatile boolean logMINOR;

	static {
		registerLogThresholdCallback(new LogThresholdCallback() {
			@Override
			public void shouldUpdate() {
				logMINOR = shouldLog(LogLevel.MINOR, this);
			}
		});
	}

	private final FileInsertWizardToadlet fileInsertWizardToadlet;

	public UploadToadlet(NodeClientCore core, FCPServer fcp, HighLevelSimpleClient client, FileInsertWizardToadlet fileInsertWizardToadlet) {
		super(core, fcp, client, true);
		this.fileInsertWizardToadlet = fileInsertWizardToadlet;
		setFIW(fileInsertWizardToadlet);
	}

	public void handleMethodPOST(URI uri, HTTPRequest request, final ToadletContext toadletContext) throws ToadletContextClosedException, IOException, RedirectException {
		if (container.publicGatewayMode() && !toadletContext.isAllowedFullAccess()) {
			sendUnauthorizedPage(toadletContext);
			return;
		}

		if (request.isPartSet("insert-local")) {
			redirectToInsertToadlet(request, toadletContext);
			return;
		}

		super.handleMethodPOST(uri, request, toadletContext);
	}

	private void redirectToInsertToadlet(HTTPRequest request, ToadletContext toadletContext) throws ToadletContextClosedException, IOException {
		FreenetURI insertURI = getInsertUriForRequest(request, toadletContext);
		if (insertURI != null) {
			generateRedirectToInsertToadlet(request, toadletContext, insertURI);
		}
	}

	private void generateRedirectToInsertToadlet(HTTPRequest request, ToadletContext toadletContext, FreenetURI insertURI) throws ToadletContextClosedException, IOException {
		MultiValueTable<String, String> responseHeaders = new MultiValueTable<String, String>();
		String insertToadletPath = format("%s?key=%s&compress=%s&compatibilityMode=%s&overrideSplitfileKey=%s",
				LocalFileInsertToadlet.PATH,
				insertURI.toASCIIString(),
				request.getPartAsStringFailsafe("compress", 128).length() > 0,
				request.getPartAsStringFailsafe("compatibilityMode", 100),
				request.getPartAsStringFailsafe("overrideSplitfileKey", 65)
		);
		responseHeaders.put("Location", insertToadletPath);
		toadletContext.sendReplyHeaders(302, "Found", responseHeaders, null, 0);
	}

	private FreenetURI getInsertUriForRequest(HTTPRequest request, ToadletContext toadletContext) throws ToadletContextClosedException, IOException {
		String keyType = request.getPartAsStringFailsafe("keytype", 10);
		if ("CHK".equals(keyType)) {
			fileInsertWizardToadlet.reportCanonicalInsert();
			return new FreenetURI("CHK@");
		} else if ("SSK".equals(keyType)) {
			fileInsertWizardToadlet.reportRandomInsert();
			return new FreenetURI("SSK@");
		} else if ("specify".equals(keyType)) {
			try {
				String u = request.getPartAsStringFailsafe("key", MAX_KEY_LENGTH);
				FreenetURI insertURI = new FreenetURI(u);
				if (logMINOR) {
					Logger.minor(this, "Inserting key: " + insertURI + " (" + u + ")");
				}
				return insertURI;
			} catch (MalformedURLException mue1) {
				writeError(l10n("errorInvalidURI"), l10n("errorInvalidURIToU"), toadletContext, false, true);
			}
		} else {
			writeError(l10n("errorMustSpecifyKeyTypeTitle"), l10n("errorMustSpecifyKeyType"), toadletContext, false, true);
		}
		return null;
	}

}
