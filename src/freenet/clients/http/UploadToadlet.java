package freenet.clients.http;

import static freenet.support.Logger.registerLogThresholdCallback;
import static freenet.support.Logger.shouldLog;
import static java.lang.String.format;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.util.concurrent.CountDownLatch;

import freenet.client.DefaultMIMETypes;
import freenet.client.HighLevelSimpleClient;
import freenet.client.HighLevelSimpleClientImpl;
import freenet.client.InsertContext.CompatibilityMode;
import freenet.client.MetadataUnresolvedException;
import freenet.client.async.ClientContext;
import freenet.client.async.DBJob;
import freenet.client.async.DatabaseDisabledException;
import freenet.client.async.TooManyFilesInsertException;
import freenet.keys.FreenetURI;
import freenet.node.Node;
import freenet.node.NodeClientCore;
import freenet.node.RequestStarter;
import freenet.node.fcp.ClientPut;
import freenet.node.fcp.ClientPutDir;
import freenet.node.fcp.ClientPutMessage;
import freenet.node.fcp.ClientRequest;
import freenet.node.fcp.FCPServer;
import freenet.node.fcp.IdentifierCollisionException;
import freenet.node.fcp.NotAllowedException;
import freenet.support.HexUtil;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.MultiValueTable;
import freenet.support.api.Bucket;
import freenet.support.api.HTTPRequest;
import freenet.support.api.HTTPUploadedFile;
import freenet.support.io.BucketTools;
import freenet.support.io.FileBucket;
import freenet.support.io.NativeThread;
import com.db4o.ObjectContainer;

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
		if (request.getPartAsStringFailsafe("insert", 128).length() > 0) {
			queueInsertFromBrowser(request, toadletContext);
			return;
		}
		if (request.isPartSet(LocalFileBrowserToadlet.selectFile)) {
			queueInsertFromFile(request, toadletContext);
			return;
		}
		if (request.isPartSet(LocalFileBrowserToadlet.selectDir)) {
			queueInsertFromDirectory(request, toadletContext);
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

	private void queueInsertFromBrowser(HTTPRequest request, final ToadletContext ctx) throws ToadletContextClosedException, IOException {
		final FreenetURI insertURI;
		String keyType = request.getPartAsStringFailsafe("keytype", 10);
		if ("CHK".equals(keyType)) {
			insertURI = new FreenetURI("CHK@");
			fileInsertWizardToadlet.reportCanonicalInsert();
		} else if ("SSK".equals(keyType)) {
			insertURI = new FreenetURI("SSK@");
			fileInsertWizardToadlet.reportRandomInsert();
		} else if ("specify".equals(keyType)) {
			try {
				String u = request.getPartAsStringFailsafe("key", MAX_KEY_LENGTH);
				insertURI = new FreenetURI(u);
				if (logMINOR) {
					Logger.minor(this, "Inserting key: " + insertURI + " (" + u + ")");
				}
			} catch (MalformedURLException mue1) {
				writeError(l10n("errorInvalidURI"), l10n("errorInvalidURIToU"), ctx, false, true);
				return;
			}
		} else {
			writeError(l10n("errorMustSpecifyKeyTypeTitle"),
					l10n("errorMustSpecifyKeyType"), ctx, false, true);
			return;
		}
		final HTTPUploadedFile file = request.getUploadedFile("filename");
		if (file == null || file.getFilename().trim().length() == 0) {
			writeError(l10n("errorNoFileSelected"), l10n("errorNoFileSelectedU"), ctx, false, true);
			return;
		}
		final boolean compress = request.getPartAsStringFailsafe("compress", 128).length() > 0;
		final String identifier = file.getFilename() + "-fred-" + System.currentTimeMillis();
		final String compatibilityMode = request.getPartAsStringFailsafe("compatibilityMode", 100);
		final CompatibilityMode cmode;
		if (compatibilityMode.equals("")) {
			cmode = CompatibilityMode.COMPAT_CURRENT;
		} else {
			cmode = CompatibilityMode.valueOf(compatibilityMode);
		}
		String s = request.getPartAsStringFailsafe("overrideSplitfileKey", 65);
		final byte[] overrideSplitfileKey;
		if (s != null && !s.equals("")) {
			overrideSplitfileKey = HexUtil.hexToBytes(s);
		} else {
			overrideSplitfileKey = null;
		}
		final String fnam;
		if (insertURI.getKeyType().equals("CHK") || keyType.equals("SSK")) {
			fnam = file.getFilename();
		} else {
			fnam = null;
		}
				/* copy bucket data */
		final Bucket copiedBucket = core.persistentTempBucketFactory.makeBucket(file.getData().size());
		BucketTools.copy(file.getData(), copiedBucket);
		final CountDownLatch done = new CountDownLatch(1);
		try {
			core.queue(new DBJob() {

				@Override
				public String toString() {
					return "QueueToadlet StartInsert";
				}

				@Override
				public boolean run(ObjectContainer container, ClientContext context) {
					try {
						final ClientPut clientPut;
						try {
							clientPut = new ClientPut(fcp.getGlobalForeverClient(), insertURI, identifier, Integer.MAX_VALUE, null, RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS, ClientRequest.PERSIST_FOREVER, null, false, !compress, -1, ClientPutMessage.UPLOAD_FROM_DIRECT, null, file.getContentType(), copiedBucket, null, fnam, false, false, Node.FORK_ON_CACHEABLE_DEFAULT, HighLevelSimpleClientImpl.EXTRA_INSERTS_SINGLE_BLOCK, HighLevelSimpleClientImpl.EXTRA_INSERTS_SPLITFILE_HEADER, false, cmode, overrideSplitfileKey, fcp, container);
							if (clientPut != null) {
								try {
									fcp.startBlocking(clientPut, container, context);
								} catch (IdentifierCollisionException e) {
									Logger.error(this, "Cannot put same file twice in same millisecond");
									writePermanentRedirect(ctx, "Done", path());
									return false;
								}
							}
							writePermanentRedirect(ctx, "Done", path());
							return true;
						} catch (IdentifierCollisionException e) {
							Logger.error(this, "Cannot put same file twice in same millisecond");
							writePermanentRedirect(ctx, "Done", path());
							return false;
						} catch (NotAllowedException e) {
							writeError(l10n("errorAccessDenied"), l10n("errorAccessDeniedFile", "file", file.getFilename()), ctx, false, true);
							return false;
						} catch (FileNotFoundException e) {
							writeError(l10n("errorNoFileOrCannotRead"), l10n("errorAccessDeniedFile", "file", file.getFilename()), ctx, false, true);
							return false;
						} catch (MalformedURLException mue1) {
							writeError(l10n("errorInvalidURI"), l10n("errorInvalidURIToU"), ctx, false, true);
							return false;
						} catch (MetadataUnresolvedException e) {
							Logger.error(this, "Unresolved metadata in starting insert from data uploaded from browser: " + e, e);
							writePermanentRedirect(ctx, "Done", path());
							return false;
							// FIXME should this be a proper localised message? It shouldn't happen... but we'd like to get reports if it does.
						} catch (Throwable t) {
							writeInternalError(t, ctx);
							return false;
						} finally {
							done.countDown();
						}
					} catch (IOException e) {
						// Ignore
						return false;
					} catch (ToadletContextClosedException e) {
						// Ignore
						return false;
					}
				}

			}, NativeThread.HIGH_PRIORITY + 1, false);
		} catch (DatabaseDisabledException e1) {
			sendPersistenceDisabledError(ctx);
			return;
		}
		while (done.getCount() > 0) {
			try {
				done.await();
			} catch (InterruptedException e) {
				// Ignore
			}
		}
	}

	private void queueInsertFromFile(HTTPRequest request, final ToadletContext ctx) throws ToadletContextClosedException, IOException {
		final String filename = request.getPartAsStringFailsafe("filename", MAX_FILENAME_LENGTH);
		if (logMINOR) {
			Logger.minor(this, "Inserting local file: " + filename);
		}
		final File file = new File(filename);
		final String identifier = file.getName() + "-fred-" + System.currentTimeMillis();
		final String contentType = DefaultMIMETypes.guessMIMEType(filename, false);
		final FreenetURI furi;
		final String key = request.getPartAsStringFailsafe("key", MAX_KEY_LENGTH);
		final boolean compress = request.isPartSet("compress");
		final String compatibilityMode = request.getPartAsStringFailsafe("compatibilityMode", 100);
		final CompatibilityMode cmode;
		if (compatibilityMode.equals("")) {
			cmode = CompatibilityMode.COMPAT_CURRENT;
		} else {
			cmode = CompatibilityMode.valueOf(compatibilityMode);
		}
		String s = request.getPartAsStringFailsafe("overrideSplitfileKey", 65);
		final byte[] overrideSplitfileKey;
		if (s != null && !s.equals("")) {
			overrideSplitfileKey = HexUtil.hexToBytes(s);
		} else {
			overrideSplitfileKey = null;
		}
		if (key != null) {
			try {
				furi = new FreenetURI(key);
			} catch (MalformedURLException e) {
				writeError(l10n("errorInvalidURI"), l10n("errorInvalidURIToU"), ctx);
				return;
			}
		} else {
			furi = new FreenetURI("CHK@");
		}
		final String target;
		if (furi.getDocName() != null) {
			target = null;
		} else {
			target = file.getName();
		}
		final CountDownLatch done = new CountDownLatch(1);
		try {
			core.queue(new DBJob() {

				@Override
				public String toString() {
					return "QueueToadlet StartLocalFileInsert";
				}

				@Override
				public boolean run(ObjectContainer container, ClientContext context) {
					final ClientPut clientPut;
					try {
						try {
							clientPut = new ClientPut(fcp.getGlobalForeverClient(), furi, identifier, Integer.MAX_VALUE, null, RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS, ClientRequest.PERSIST_FOREVER, null, false, !compress, -1, ClientPutMessage.UPLOAD_FROM_DISK, file, contentType, new FileBucket(file, true, false, false, false, false), null, target, false, false, Node.FORK_ON_CACHEABLE_DEFAULT, HighLevelSimpleClientImpl.EXTRA_INSERTS_SINGLE_BLOCK, HighLevelSimpleClientImpl.EXTRA_INSERTS_SPLITFILE_HEADER, false, cmode, overrideSplitfileKey, fcp, container);
							if (logMINOR) {
								Logger.minor(this, "Started global request to insert " + file + " to CHK@ as " + identifier);
							}
							if (clientPut != null) {
								try {
									fcp.startBlocking(clientPut, container, context);
								} catch (IdentifierCollisionException e) {
									Logger.error(this, "Cannot put same file twice in same millisecond");
									writePermanentRedirect(ctx, "Done", path());
									return false;
								} catch (DatabaseDisabledException e) {
									// Impossible???
								}
							}
							writePermanentRedirect(ctx, "Done", path());
							return true;
						} catch (IdentifierCollisionException e) {
							Logger.error(this, "Cannot put same file twice in same millisecond");
							writePermanentRedirect(ctx, "Done", path());
							return false;
						} catch (MalformedURLException e) {
							writeError(l10n("errorInvalidURI"), l10n("errorInvalidURIToU"), ctx);
							return false;
						} catch (FileNotFoundException e) {
							writeError(l10n("errorNoFileOrCannotRead"), l10n("errorAccessDeniedFile", "file", target), ctx);
							return false;
						} catch (NotAllowedException e) {
							writeError(l10n("errorAccessDenied"), l10n("errorAccessDeniedFile", new String[] { "file" }, new String[] { file.getName() }), ctx);
							return false;
						} catch (MetadataUnresolvedException e) {
							Logger.error(this, "Unresolved metadata in starting insert from data from file: " + e, e);
							writePermanentRedirect(ctx, "Done", path());
							return false;
							// FIXME should this be a proper localised message? It shouldn't happen... but we'd like to get reports if it does.
						} finally {
							done.countDown();
						}
					} catch (IOException e) {
						// Ignore
						return false;
					} catch (ToadletContextClosedException e) {
						// Ignore
						return false;
					}
				}

			}, NativeThread.HIGH_PRIORITY + 1, false);
		} catch (DatabaseDisabledException e1) {
			sendPersistenceDisabledError(ctx);
			return;
		}
		while (done.getCount() > 0) {
			try {
				done.await();
			} catch (InterruptedException e) {
				// Ignore
			}
		}
	}

	private void queueInsertFromDirectory(HTTPRequest request, final ToadletContext ctx) throws ToadletContextClosedException, IOException {
		final String filename = request.getPartAsStringFailsafe("filename", MAX_FILENAME_LENGTH);
		if (logMINOR) {
			Logger.minor(this, "Inserting local directory: " + filename);
		}
		final File file = new File(filename);
		final String identifier = file.getName() + "-fred-" + System.currentTimeMillis();
		final FreenetURI furi;
		final String key = request.getPartAsStringFailsafe("key", MAX_KEY_LENGTH);
		final boolean compress = request.isPartSet("compress");
		String s = request.getPartAsStringFailsafe("overrideSplitfileKey", 65);
		final byte[] overrideSplitfileKey;
		if (s != null && !s.equals("")) {
			overrideSplitfileKey = HexUtil.hexToBytes(s);
		} else {
			overrideSplitfileKey = null;
		}
		if (key != null) {
			try {
				furi = new FreenetURI(key);
			} catch (MalformedURLException e) {
				writeError(l10n("errorInvalidURI"), l10n("errorInvalidURIToU"), ctx);
				return;
			}
		} else {
			furi = new FreenetURI("CHK@");
		}
		final CountDownLatch done = new CountDownLatch(1);
		try {
			core.queue(new DBJob() {

				@Override
				public String toString() {
					return "QueueToadlet StartLocalDirInsert";
				}

				@Override
				public boolean run(ObjectContainer container, ClientContext context) {
					ClientPutDir clientPutDir;
					try {
						try {
							clientPutDir = new ClientPutDir(fcp.getGlobalForeverClient(), furi, identifier, Integer.MAX_VALUE, RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS, ClientRequest.PERSIST_FOREVER, null, false, !compress, -1, file, null, false, /* make include hidden files configurable? FIXME */ false, true, false, false, Node.FORK_ON_CACHEABLE_DEFAULT, HighLevelSimpleClientImpl.EXTRA_INSERTS_SINGLE_BLOCK, HighLevelSimpleClientImpl.EXTRA_INSERTS_SPLITFILE_HEADER, false, overrideSplitfileKey, fcp, container);
							if (logMINOR) {
								Logger.minor(this, "Started global request to insert dir " + file + " to " + furi + " as " + identifier);
							}
							if (clientPutDir != null) {
								try {
									fcp.startBlocking(clientPutDir, container, context);
								} catch (IdentifierCollisionException e) {
									Logger.error(this, "Cannot put same file twice in same millisecond");
									writePermanentRedirect(ctx, "Done", path());
									return false;
								} catch (DatabaseDisabledException e) {
									sendPersistenceDisabledError(ctx);
									return false;
								}
							}
							writePermanentRedirect(ctx, "Done", path());
							return true;
						} catch (IdentifierCollisionException e) {
							Logger.error(this, "Cannot put same directory twice in same millisecond");
							writePermanentRedirect(ctx, "Done", path());
							return false;
						} catch (MalformedURLException e) {
							writeError(l10n("errorInvalidURI"), l10n("errorInvalidURIToU"), ctx);
							return false;
						} catch (FileNotFoundException e) {
							writeError(l10n("errorNoFileOrCannotRead"), l10n("QueueToadlet.errorAccessDeniedFile", "file", file.toString()), ctx);
							return false;
						} catch (TooManyFilesInsertException e) {
							writeError(l10n("tooManyFilesInOneFolder"), l10n("tooManyFilesInOneFolder"), ctx);
							return false;
						} finally {
							done.countDown();
						}
					} catch (IOException e) {
						// Ignore
						return false;
					} catch (ToadletContextClosedException e) {
						// Ignore
						return false;
					}
				}

			}, NativeThread.HIGH_PRIORITY + 1, false);
		} catch (DatabaseDisabledException e1) {
			sendPersistenceDisabledError(ctx);
			return;
		}
		while (done.getCount() > 0) {
			try {
				done.await();
			} catch (InterruptedException e) {
				// Ignore
			}
		}
	}

}
