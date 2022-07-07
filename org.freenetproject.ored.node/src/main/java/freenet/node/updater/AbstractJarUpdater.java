package freenet.node.updater;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import freenet.client.FetchResult;
import freenet.keys.FreenetURI;
import freenet.nodelogger.Logger;
import freenet.support.io.Closer;
import freenet.support.io.FileUtil;
import freenet.support.io.NullOutputStream;

public abstract class AbstractJarUpdater extends AbstractFileUpdater {

	private static boolean logMINOR;

	AbstractJarUpdater(NodeUpdateManager manager, FreenetURI URI, int current, int min, int max,
			String blobFilenamePrefix) {
		super(manager, URI, current, min, max, blobFilenamePrefix);
	}

	@Override
	protected void processSuccess(int fetched, FetchResult result, File blobFile) {
		super.processSuccess(fetched, result, blobFile);

		synchronized (this) {
			this.maybeParseManifest(result, this.fetchedVersion);
		}
	}

	/**
	 * Called with locks held
	 * @param result
	 */
	protected abstract void maybeParseManifest(FetchResult result, int build);

	protected void parseManifest(FetchResult result) {
		InputStream is = null;
		try {
			is = result.asBucket().getInputStream();
			ZipInputStream zis = new ZipInputStream(is);
			try {
				ZipEntry ze;
				while (true) {
					ze = zis.getNextEntry();
					if (ze == null) {
						break;
					}
					if (ze.isDirectory()) {
						continue;
					}
					String name = ze.getName();

					if (name.equals("META-INF/MANIFEST.MF")) {
						if (logMINOR) {
							Logger.minor(this, "Found manifest");
						}
						long size = ze.getSize();
						if (logMINOR) {
							Logger.minor(this, "Manifest size: " + size);
						}
						if (size > MAX_MANIFEST_SIZE) {
							Logger.error(this,
									"Manifest is too big: " + size + " bytes, limit is " + MAX_MANIFEST_SIZE);
							break;
						}
						byte[] buf = new byte[(int) size];
						DataInputStream dis = new DataInputStream(zis);
						dis.readFully(buf);
						ByteArrayInputStream bais = new ByteArrayInputStream(buf);
						InputStreamReader isr = new InputStreamReader(bais, StandardCharsets.UTF_8);
						BufferedReader br = new BufferedReader(isr);
						String line;
						while ((line = br.readLine()) != null) {
							this.parseManifestLine(line);
						}
					}
					else {
						zis.closeEntry();
					}
				}
			}
			finally {
				Closer.close(zis);
			}
		}
		catch (IOException ex) {
			Logger.error(this, "IOException trying to read manifest on update");
		}
		catch (Throwable ex) {
			Logger.error(this, "Failed to parse update manifest: " + ex, ex);
		}
		finally {
			Closer.close(is);
		}
	}

	static final String DEPENDENCIES_FILE = "dependencies.properties";

	/**
	 * Read the jar file. Parse the Properties. Read every file in the ZIP; if it is
	 * corrupted, we will get a CRC error and therefore an IOException, and so the update
	 * won't be deployed. This is not entirely foolproof because ZipInputStream doesn't
	 * check the CRC for stored files, only for deflated files, and it's only a CRC32
	 * anyway. But it should reduce the chances of accidental corruption breaking an
	 * update.
	 * @param is The InputStream for the jar file.
	 * @param filename The filename of the manifest file containing the properties
	 * (normally META-INF/MANIFEST.MF).
	 * @throws IOException If there is a temporary files error or the jar is corrupted.
	 */
	static Properties parseProperties(InputStream is, String filename) throws IOException {
		Properties props = new Properties();
		ZipInputStream zis = new ZipInputStream(is);
		try {
			ZipEntry ze;
			while (true) {
				ze = zis.getNextEntry();
				if (ze == null) {
					break;
				}
				if (ze.isDirectory()) {
					continue;
				}
				String name = ze.getName();

				if (name.equals(filename)) {
					if (logMINOR) {
						Logger.minor(AbstractFileUpdater.class, "Found manifest");
					}
					long size = ze.getSize();
					if (logMINOR) {
						Logger.minor(AbstractFileUpdater.class, "Manifest size: " + size);
					}
					if (size > MAX_MANIFEST_SIZE) {
						Logger.error(AbstractFileUpdater.class,
								"Manifest is too big: " + size + " bytes, limit is " + MAX_MANIFEST_SIZE);
						break;
					}
					byte[] buf = new byte[(int) size];
					DataInputStream dis = new DataInputStream(zis);
					dis.readFully(buf);
					ByteArrayInputStream bais = new ByteArrayInputStream(buf);
					props.load(bais);
				}
				else {
					// Read the file. Throw if there is a CRC error.
					// Note that java.util.zip.ZipInputStream only checks the CRC for
					// compressed
					// files, so this is not entirely foolproof.
					long size = ze.getSize();
					FileUtil.copy(zis, new NullOutputStream(), size);
					zis.closeEntry();
				}
			}
		}
		finally {
			Closer.close(zis);
		}
		return props;
	}

	protected void parseDependencies(FetchResult result, int build) {
		InputStream is = null;
		try {
			is = result.asBucket().getInputStream();
			this.parseDependencies(parseProperties(is, DEPENDENCIES_FILE), build);
		}
		catch (IOException ignored) {
			Logger.error(this, "IOException trying to read manifest on update");
		}
		catch (Throwable ex) {
			Logger.error(this, "Failed to parse update manifest: " + ex, ex);
		}
		finally {
			Closer.close(is);
		}
	}

	/** Override if you want to deal with the file dependencies.properties */
	protected void parseDependencies(Properties props, int build) {
		// Do nothing
	}

	protected void parseManifestLine(String line) {
		// Do nothing by default, only some NodeUpdater's will use this, those that don't
		// won't call parseManifest().
	}

	private static final int MAX_MANIFEST_SIZE = 1024 * 1024;

}
