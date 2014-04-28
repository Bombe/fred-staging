package freenet.clients.http;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import freenet.client.HighLevelSimpleClient;
import freenet.client.async.DatabaseDisabledException;
import freenet.keys.FreenetURI;
import freenet.l10n.NodeL10n;
import freenet.node.NodeClientCore;
import freenet.node.fcp.FCPServer;
import freenet.node.fcp.NotAllowedException;
import freenet.support.HTMLNode;
import freenet.support.Logger;
import freenet.support.api.HTTPRequest;

/**
 * {@link Toadlet} implementation that manages downloads.
 *
 * @author <a href="mailto:bombe@pterodactylus.net">David ‘Bombe’ Roden</a>
 */
public class DownloadToadlet extends QueueToadlet {

	public DownloadToadlet(NodeClientCore core, FCPServer fcp, HighLevelSimpleClient client) {
		super(core, fcp, client, false);
	}

	public void handleMethodPOST(URI uri, HTTPRequest request, final ToadletContext toadletContext) throws ToadletContextClosedException, IOException, RedirectException {
		if (container.publicGatewayMode() && !toadletContext.isAllowedFullAccess()) {
			sendUnauthorizedPage(toadletContext);
			return;
		}

		if (request.isPartSet("select-location")) {
			try {
				throw new RedirectException(LocalDirectoryConfigToadlet.basePath() + "/downloads/");
			} catch (URISyntaxException use1) {
				/* The path should really not be invalid. */
			}
		}

		if (request.isPartSet("download")) {
			queueDownload(request, toadletContext);
			return;
		}
		if (request.isPartSet("bulkDownloads")) {
			queueBulkDownloads(request, toadletContext);
			return;
		}

		super.handleMethodPOST(uri, request, toadletContext);
	}

	private void queueDownload(HTTPRequest request, ToadletContext ctx) throws ToadletContextClosedException, IOException {
		if (!request.isPartSet("key")) {
			writeError(l10n("errorNoKey"), l10n("errorNoKeyToD"), ctx);
			return;
		}
		String expectedMIMEType = null;
		if (request.isPartSet("type")) {
			expectedMIMEType = request.getPartAsStringFailsafe("type", MAX_TYPE_LENGTH);
		}
		FreenetURI fetchURI;
		try {
			fetchURI = new FreenetURI(request.getPartAsStringFailsafe("key", MAX_KEY_LENGTH));
		} catch (MalformedURLException e) {
			writeError(l10n("errorInvalidURI"), l10n("errorInvalidURIToD"), ctx);
			return;
		}
		String persistence = request.getPartAsStringFailsafe("persistence", 32);
		String returnType = request.getPartAsStringFailsafe("return-type", 32);
		boolean filterData = request.isPartSet("filterData");
		File downloadsDir = null;
		//Download to disk disabled and initialized.
		if (request.isPartSet("path") && !core.isDownloadDisabled()) {
			String downloadPath = request.getPartAsStringFailsafe("path", MAX_FILENAME_LENGTH);
			try {
				downloadsDir = getDownloadsDir(downloadPath);
			} catch (NotAllowedException e) {
				downloadDisallowedPage(e, downloadPath, ctx);
				return;
			}
			//Downloading to disk not initialized and/or disabled.
		} else {
			returnType = "direct";
		}
		try {
			fcp.makePersistentGlobalRequestBlocking(fetchURI, filterData, expectedMIMEType, persistence, returnType, false, downloadsDir);
			writePermanentRedirect(ctx, "Done", path());
		} catch (NotAllowedException e) {
			writeError(l10n("QueueToadlet.errorDToDisk"), l10n("QueueToadlet.errorDToDiskConfig"), ctx);
		} catch (DatabaseDisabledException e) {
			sendPersistenceDisabledError(ctx);
		}
	}

	private void queueBulkDownloads(HTTPRequest request, ToadletContext ctx) throws ToadletContextClosedException, IOException {
		String target = request.getPartAsStringFailsafe("target", 128);
		if (target == null) {
			target = "direct";
		}
		File downloadsDir = null;
		if (request.isPartSet("path") && !core.isDownloadDisabled()) {
			String downloadPath = request.getPartAsStringFailsafe("path", MAX_FILENAME_LENGTH);
			try {
				downloadsDir = getDownloadsDir(downloadPath);
			} catch (NotAllowedException e) {
				downloadDisallowedPage(e, downloadPath, ctx);
				return;
			}
		} else {
			target = "direct";
		}

		String bulkDownloadsAsString = request.getPartAsStringFailsafe("bulkDownloads", 262144);
		String[] keys = bulkDownloadsAsString.split("\n");
		if (("".equals(bulkDownloadsAsString)) || (keys.length < 1)) {
			writePermanentRedirect(ctx, "Done", path());
			return;
		}

		List<String> queuedRequests = new ArrayList<String>();
		List<String> failedRequests = new ArrayList<String>();
		boolean filterData = request.isPartSet("filterData");

		for (String key : keys) {
			String currentKey = key;
			if (currentKey.length() == 0) {
				continue;
			}

			try {
				FreenetURI fetchURI = new FreenetURI(currentKey);
				fcp.makePersistentGlobalRequestBlocking(fetchURI, filterData, null, "forever", target, false, downloadsDir);
				queuedRequests.add(fetchURI.toString(true, false));
			} catch (Exception e) {
				failedRequests.add(currentKey);
				Logger.error(this, "An error occured while attempting to download key: " + currentKey + " : " + e.getMessage());
			}
		}

		writeQueueingResults(ctx, queuedRequests, failedRequests);
	}

	private void writeQueueingResults(ToadletContext ctx, List<String> queuedRequests, List<String> failedRequests) throws ToadletContextClosedException, IOException {
		PageNode page = ctx.getPageMaker().getPageNode(l10n("downloadFiles"), ctx);
		HTMLNode pageNode = page.outer;
		HTMLNode contentNode = page.content;

		HTMLNode alertContent = ctx.getPageMaker().getInfobox(
				(!failedRequests.isEmpty() ? "infobox-warning" : "infobox-info"),
				l10n("downloadFiles"), contentNode, "grouped-downloads", true);
		if (!queuedRequests.isEmpty()) {
			HTMLNode successDiv = alertContent.addChild("ul");
			successDiv.addChild("#", l10n("enqueuedSuccessfully", "number", String.valueOf(queuedRequests.size())));
			for (String successfulRequest : queuedRequests) {
				HTMLNode line = successDiv.addChild("li");
				line.addChild("#", successfulRequest);
			}
			successDiv.addChild("br");
		}
		if (!failedRequests.isEmpty()) {
			HTMLNode failureDiv = alertContent.addChild("ul");
			failureDiv.addChild("#", l10n("enqueuedFailure", "number", String.valueOf(failedRequests.size())));
			for (String failedRequest : failedRequests) {
				HTMLNode line = failureDiv.addChild("li");
				line.addChild("#", failedRequest);
			}
			failureDiv.addChild("br");
		}
		alertContent.addChild("a", "href", path(), NodeL10n.getBase().getString("Toadlet.returnToQueuepage"));
		writeHTMLReply(ctx, 200, "OK", pageNode.generate());
	}

	private void downloadDisallowedPage(NotAllowedException e, String downloadPath, ToadletContext ctx) throws IOException, ToadletContextClosedException {
		PageNode page = ctx.getPageMaker().getPageNode(l10n("downloadFiles"), ctx);
		HTMLNode pageNode = page.outer;
		HTMLNode contentNode = page.content;
		Logger.warning(this, e.toString());
		HTMLNode alert = ctx.getPageMaker().getInfobox("infobox-alert",
				l10n("downloadFiles"), contentNode, "grouped-downloads", true);
		alert.addChild("ul", l10n("downloadDisallowed", "directory", downloadPath));
		alert.addChild("a", "href", path(),
				NodeL10n.getBase().getString("Toadlet.returnToQueuepage"));
		writeHTMLReply(ctx, 200, "OK", pageNode.generate());
	}

	private File getDownloadsDir (String downloadPath) throws NotAllowedException {
		File downloadsDir = new File(downloadPath);
		//Invalid if it's disallowed, doesn't exist, isn't a directory, or can't be created.
		if(!core.allowDownloadTo(downloadsDir) || !((downloadsDir.exists() &&
				downloadsDir.isDirectory()) || !downloadsDir.mkdirs())) {
			throw new NotAllowedException();
		}
		return downloadsDir;
	}

}
