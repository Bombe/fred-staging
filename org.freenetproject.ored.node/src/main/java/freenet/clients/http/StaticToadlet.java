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

package freenet.clients.http;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.Date;

import freenet.bucket.Bucket;
import freenet.bucket.FileBucket;
import freenet.http.HTTPRequest;
import freenet.l10n.NodeL10n;
import freenet.nodelogger.Logger;
import freenet.support.client.DefaultMIMETypes;

/**
 * Static Toadlet. Serve up static files
 */
public class StaticToadlet extends Toadlet {

	StaticToadlet() {
		super(null);
	}

	public static final String ROOT_URL = "/static/";

	public static final String ROOT_PATH = "/staticfiles/";

	public static final String OVERRIDE = "override/";

	public static final String OVERRIDE_URL = ROOT_URL + OVERRIDE;

	public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
			throws ToadletContextClosedException, IOException {
		String path = uri.getPath();

		if (!path.startsWith(ROOT_URL)) {
			// we should never get any other path anyway
			return;
		}
		try {
			path = path.substring(ROOT_URL.length());
		}
		catch (IndexOutOfBoundsException ioobe) {
			this.sendErrorPage(ctx, 404, this.l10n("pathNotFoundTitle"), this.l10n("pathNotFound"));
			return;
		}

		// be very strict about what characters we allow in the path, since
		if (!path.matches("^[A-Za-z\\d._/\\-]*$") || (path.contains(".."))) {
			this.sendErrorPage(ctx, 404, this.l10n("pathNotFoundTitle"), this.l10n("pathInvalidChars"));
			return;
		}

		if (path.startsWith(OVERRIDE)) {
			File f = this.container.getOverrideFile();
			if (f == null || (!f.exists()) || (f.isDirectory()) || (!f.isFile())) {
				this.sendErrorPage(ctx, 404, this.l10n("pathNotFoundTitle"), this.l10n("pathInvalidChars"));
				return;
			}
			f = f.getAbsoluteFile();
			if (!f.exists() || f.isDirectory() || !f.isFile()) {
				this.sendErrorPage(ctx, 404, this.l10n("pathNotFoundTitle"), this.l10n("pathInvalidChars"));
				return;
			}
			File parent = f.getParentFile();
			// Basic sanity check.
			// Prevents user from specifying root dir.
			// They can still shoot themselves in the foot, but only when developing
			// themes/using custom themes.
			// Because of the .. check above, any malicious thing cannot break out of the
			// dir anyway.
			if (parent.getParentFile() == null) {
				this.sendErrorPage(ctx, 404, this.l10n("pathNotFoundTitle"), this.l10n("pathInvalidChars"));
				return;
			}
			File from = new File(parent, path.substring(OVERRIDE.length()));
			if ((!from.exists()) && (!from.isFile())) {
				this.sendErrorPage(ctx, 404, this.l10n("pathNotFoundTitle"), this.l10n("pathInvalidChars"));
				return;
			}
			try {
				FileBucket fb = new FileBucket(from, true, false, false, false);
				ctx.sendReplyHeadersStatic(200, "OK", null, DefaultMIMETypes.guessMIMEType(path, false), fb.size(),
						new Date(System.currentTimeMillis() - 1000)); // Already expired,
																		// we want it to
																		// reload it.
				ctx.writeData(fb);
				return;
			}
			catch (IOException ex) {
				// Not strictly accurate but close enough
				this.sendErrorPage(ctx, 404, this.l10n("pathNotFoundTitle"), this.l10n("pathNotFound"));
				return;
			}
		}

		InputStream strm = this.getClass().getResourceAsStream(ROOT_PATH + path);
		if (strm == null) {
			this.sendErrorPage(ctx, 404, this.l10n("pathNotFoundTitle"), this.l10n("pathNotFound"));
			return;
		}
		Bucket data = ctx.getBucketFactory().makeBucket(strm.available());
		OutputStream os = data.getOutputStream();
		try {
			byte[] cbuf = new byte[4096];
			while (true) {
				int r = strm.read(cbuf);
				if (r == -1) {
					break;
				}
				os.write(cbuf, 0, r);
			}
		}
		finally {
			strm.close();
			os.close();
		}

		URL url = this.getClass().getResource(ROOT_PATH + path);
		Date mTime = this.getUrlMTime(url);

		ctx.sendReplyHeadersStatic(200, "OK", null, DefaultMIMETypes.guessMIMEType(path, false), data.size(), mTime);

		ctx.writeData(data);
	}

	/**
	 * Try to find the modification time for a URL, or return null if not possible We
	 * usually load our resources from the JAR, or possibly from a file in some setups, so
	 * we check the modification time of the JAR for resources in a jar and the mtime for
	 * files. If we build custom java runtime with jlink, we should check JRT File System
	 * instead of JAR.
	 */
	private Date getUrlMTime(URL url) {
		if (url == null) {
			return null;
		}

		switch (url.getProtocol()) {
		case "jrt":
			try {
				Path p = Path.of(url.toURI());
				BasicFileAttributes attr = Files.readAttributes(p, BasicFileAttributes.class);
				FileTime fileTime = attr.lastModifiedTime();
				return new Date(fileTime.toMillis());
			}
			catch (URISyntaxException ex) {
				Logger.error(this, "Invalid url: " + url);
				return null;
			}
			catch (IOException ex) {
				Logger.error(this, "Unable to read file attributes from: " + url);
				return null;
			}
		case "jar": {
			File f = new File(url.getPath().substring(0, url.getPath().indexOf('!')));
			return new Date(f.lastModified());
		}
		case "file": {
			File f = new File(url.getPath());
			return new Date(f.lastModified());
		}
		default:
			return null;
		}
	}

	private String l10n(String key) {
		return NodeL10n.getBase().getString("StaticToadlet." + key);
	}

	@Override
	public String path() {
		return ROOT_URL;
	}

	/**
	 * Do we have a specific static file? Note that override files are not supported here
	 * as it is a static method.
	 * @param path The path to the file, relative to the staticfiles directory.
	 */
	public static boolean haveFile(String path) {
		URL url = StaticToadlet.class.getResource(ROOT_PATH + path);
		return url != null;
	}

}
