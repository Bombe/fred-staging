/*
 * Copyright 1999-2022 The Freenet Project
 * Copyright 2022 Marine Master
 *
 * This file is part of Oldenet.
 *
 * Oldenet is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or any later version.
 *
 * Oldenet is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with Oldenet.
 * If not, see <https://www.gnu.org/licenses/>.
 */

package freenet.node.updater;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;

import freenet.bucket.BucketCloser;
import freenet.bucket.BucketTools;
import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.FetchResult;
import freenet.client.HighLevelSimpleClient;
import freenet.client.async.ClientContext;
import freenet.client.async.ClientGetCallback;
import freenet.client.async.ClientGetter;
import freenet.client.async.PersistenceDisabledException;
import freenet.client.request.RequestClient;
import freenet.keys.FreenetURI;
import freenet.node.Node;
import freenet.node.NodeFile;
import freenet.node.ProgramDirectory;
import freenet.node.Version;
import freenet.support.io.FileUtil;

class SimplePuller implements ClientGetCallback {

	private final Node node;

	final FreenetURI freenetURI;

	final File file;

	final BiConsumer<FetchResult, ClientGetter> cbSuccess;

	final BiConsumer<Exception, ClientGetter> cbFailure;

	SimplePuller(Node node, FreenetURI freenetURI, NodeFile file) {
		this(node, freenetURI, file.getFilename(), file.getProgramDirectory(node));
	}

	SimplePuller(Node node, FreenetURI freenetURI, String fileRelPath, ProgramDirectory directory) {
		this(node, freenetURI, fileRelPath, directory, null, null);
	}

	SimplePuller(Node node, FreenetURI freenetURI, String fileRelPath, ProgramDirectory directory,
			BiConsumer<FetchResult, ClientGetter> cbSuccess, BiConsumer<Exception, ClientGetter> cbFailure) {
		this.node = node;
		this.freenetURI = freenetURI;
		this.file = directory.file(fileRelPath);
		this.cbSuccess = cbSuccess;
		this.cbFailure = cbFailure;
	}

	void start(short priority, long maxSize) {
		HighLevelSimpleClient hlsc = this.node.clientCore.makeClient(priority, false, false);
		FetchContext context = hlsc.getFetchContext();
		context.maxNonSplitfileRetries = -1;
		context.maxSplitfileBlockRetries = -1;
		context.maxTempLength = maxSize;
		context.maxOutputLength = maxSize;
		ClientGetter get = new ClientGetter(this, this.freenetURI, context, priority, null, null, null);
		try {
			this.node.clientCore.clientContext.start(get);
		}
		catch (PersistenceDisabledException ignored) {
			// Impossible
		}
		catch (FetchException ex) {
			this.onFailure(ex, null);
		}
	}

	@Override
	public void onFailure(FetchException ex, ClientGetter state) {
		System.err.println("Failed to fetch " + this.file.getName() + " : " + ex);
		this.cbFailure.accept(ex, state);
	}

	@Override
	public void onSuccess(FetchResult result, ClientGetter state) {
		File temp;
		FileOutputStream fos = null;
		try {
			temp = File.createTempFile(this.file.getName(), ".tmp", this.file.getParentFile());
			temp.deleteOnExit();
			fos = new FileOutputStream(temp);
			BucketTools.copyTo(result.asBucket(), fos, -1);
			fos.close();
			fos = null;
			for (int i = 0; i < 10; i++) {
				// FIXME add a callback in case it's being used on Windows.
				if (FileUtil.renameTo(temp, this.file)) {
					System.out.println(
							"Successfully fetched " + this.file.getName() + " for version " + Version.buildNumber());
					this.cbSuccess.accept(result, state);
					break;
				}
				else {
					System.out.println("Failed to rename " + temp + " to " + this.file.getName()
							+ " after fetching it from Freenet.");
					try {
						Thread.sleep(
								TimeUnit.SECONDS.toMillis(1) + this.node.fastWeakRandom.nextInt((int) TimeUnit.SECONDS
										.toMillis((long) Math.min(Math.pow(2, i), TimeUnit.MINUTES.toSeconds(15)))));
					}
					catch (InterruptedException ignored) {
						// Ignore
					}
				}
			}
			// noinspection ResultOfMethodCallIgnored
			temp.delete();
		}
		catch (IOException ex) {
			System.err.println("Fetched but failed to write out " + this.file.getName()
					+ " - please check that the node has permissions to write in " + this.file.getParent()
					+ " and particularly the file " + this.file.getName());
			System.err.println("The error was: " + ex);
			ex.printStackTrace();
			this.cbFailure.accept(ex, state);
		}
		finally {
			BucketCloser.close(fos);
			BucketCloser.close(result.asBucket());
		}
	}

	@Override
	public void onResume(ClientContext context) {
		// Not persistent.
	}

	@Override
	public RequestClient getRequestClient() {
		return this.node.nonPersistentClientBulk;
	}

}
