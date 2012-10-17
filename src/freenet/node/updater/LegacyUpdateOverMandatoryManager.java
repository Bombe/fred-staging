/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node.updater;

import java.io.File;
import java.io.FileFilter;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.db4o.ObjectContainer;

import freenet.io.comm.AsyncMessageCallback;
import freenet.io.comm.DMT;
import freenet.io.comm.DisconnectedException;
import freenet.io.comm.Message;
import freenet.io.comm.NotConnectedException;
import freenet.io.xfer.BulkTransmitter;
import freenet.io.xfer.PartiallyReceivedBulk;
import freenet.node.Node;
import freenet.node.NodeStarter;
import freenet.node.PeerNode;
import freenet.node.RequestClient;
import freenet.node.Version;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.io.RandomAccessFileWrapper;

/**
 * Legacy UOM. This class simply enables older nodes to pull the transition
 * version (main jar and ext jar) so they can update to the transition 
 * version. Once they've done that they'll use the new system. Revocations
 * are handled by UpdateOverMandatoryManager.
 * @author toad
 */
public class LegacyUpdateOverMandatoryManager implements RequestClient {

	private static volatile boolean logMINOR;

	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}

	final NodeUpdateManager updateManager;
	private static final Pattern extBuildNumberPattern = Pattern.compile("^ext(?:-jar)?-(\\d+)\\.fblob$");
	private static final Pattern mainBuildNumberPattern = Pattern.compile("^main(?:-jar)?-(\\d+)\\.fblob$");
	private static final Pattern extTempBuildNumberPattern = Pattern.compile("^ext(?:-jar)?-(\\d+-)?(\\d+)\\.fblob\\.tmp*$");
	private static final Pattern mainTempBuildNumberPattern = Pattern.compile("^main(?:-jar)?-(\\d+-)?(\\d+)\\.fblob\\.tmp*$");
	private static final Pattern revocationTempBuildNumberPattern = Pattern.compile("^revocation(?:-jar)?-(\\d+-)?(\\d+)\\.fblob\\.tmp*$");

	public LegacyUpdateOverMandatoryManager(NodeUpdateManager manager) {
		this.updateManager = manager;
	}
	
	public void handleRequestJar(Message m, final PeerNode source, final boolean isExt) {
		final String name = isExt ? "ext" : "main";
		
		Message msg;
		final BulkTransmitter bt;
		final RandomAccessFileWrapper raf;

		if (source.isOpennet() && updateManager.dontAllowUOM()) {
			Logger.normal(this, "Peer " + source
					+ " asked us for the blob file for " + name
					+ "; We are a seenode, so we ignore it!");
			return;
		}
		// Do we have the data?

		int version = isExt ? NodeUpdateManager.TRANSITION_VERSION_EXT : NodeUpdateManager.TRANSITION_VERSION;
		File data = isExt ? updateManager.getTransitionExtBlob() : updateManager.getTransitionMainBlob();

		if(data == null) {
			Logger.normal(this, "Peer " + source + " asked us for the blob file for the "+name+" jar but we don't have it!");
			// Probably a race condition on reconnect, hopefully we'll be asked again
			return;
		}

		final long uid = m.getLong(DMT.UID);

		if(!source.sendingUOMJar(isExt)) {
			Logger.error(this, "Peer "+source+" asked for UOM "+(isExt?"ext":"main")+" jar twice");
			return;
		}
		
		try {
			
			try {
				raf = new RandomAccessFileWrapper(data, "r");
			} catch(FileNotFoundException e) {
				Logger.error(this, "Peer " + source + " asked us for the blob file for the "+name+" jar, we have downloaded it but don't have the file even though we did have it when we checked!: " + e, e);
				return;
			}
			
			final PartiallyReceivedBulk prb;
			long length;
			try {
				length = raf.size();
				prb = new PartiallyReceivedBulk(updateManager.node.getUSM(), length,
						Node.PACKET_SIZE, raf, true);
			} catch(IOException e) {
				Logger.error(this, "Peer " + source + " asked us for the blob file for the "+name+" jar, we have downloaded it but we can't determine the file size: " + e, e);
				raf.close();
				return;
			}
			
			try {
				bt = new BulkTransmitter(prb, source, uid, false, updateManager.ctr, true);
			} catch(DisconnectedException e) {
				Logger.error(this, "Peer " + source + " asked us for the blob file for the "+name+" jar, then disconnected: " + e, e);
				raf.close();
				return;
			}
			
			msg =
				isExt ? DMT.createUOMSendingExtra(uid, length, NodeUpdateManager.LEGACY_EXT_URI.toString(), version) :
					DMT.createUOMSendingMain(uid, length, NodeUpdateManager.LEGACY_UPDATE_URI.toString(), version);
			
		} catch (RuntimeException e) {
			source.finishedSendingUOMJar(isExt);
			throw e;
		} catch (Error e) {
			source.finishedSendingUOMJar(isExt);
			throw e;
		}
		
		final Runnable r = new Runnable() {

			@Override
			public void run() {
				try {
					if(!bt.send())
						Logger.error(this, "Failed to send "+name+" jar blob to " + source.userToString() + " : " + bt.getCancelReason());
					else
						Logger.normal(this, "Sent "+name+" jar blob to " + source.userToString());
					raf.close();
				} catch (DisconnectedException e) {
					// Not much we can do.
				} finally {
					source.finishedSendingUOMJar(isExt);
					raf.close();
				}
			}
		};

		try {
			source.sendAsync(msg, new AsyncMessageCallback() {

				@Override
				public void acknowledged() {
					if(logMINOR)
						Logger.minor(this, "Sending data...");
					// Send the data

					updateManager.node.executor.execute(r, name+" jar send for " + uid + " to " + source.userToString());
				}

				@Override
				public void disconnected() {
					// Argh
					Logger.error(this, "Peer " + source + " asked us for the blob file for the "+name+" jar, then disconnected when we tried to send the UOMSendingMain");
					source.finishedSendingUOMJar(isExt);
				}

				@Override
				public void fatalError() {
					// Argh
					Logger.error(this, "Peer " + source + " asked us for the blob file for the "+name+" jar, then got a fatal error when we tried to send the UOMSendingMain");
					source.finishedSendingUOMJar(isExt);
				}

				@Override
				public void sent() {
					if(logMINOR)
						Logger.minor(this, "Message sent, data soon");
				}

				@Override
				public String toString() {
					return super.toString() + "(" + uid + ":" + source.getPeer() + ")";
				}
			}, updateManager.ctr);
		} catch(NotConnectedException e) {
			Logger.error(this, "Peer " + source + " asked us for the blob file for the "+name+" jar, then disconnected when we tried to send the UOMSendingExt: " + e, e);
			return;
		} catch (RuntimeException e) {
			source.finishedSendingUOMJar(isExt);
			throw e;
		} catch (Error e) {
			source.finishedSendingUOMJar(isExt);
			throw e;
		}

	}
	
	protected boolean removeOldTempFiles() {
		File oldTempFilesPeerDir = updateManager.node.clientCore.getPersistentTempDir();
		if(!oldTempFilesPeerDir.exists())
			return false;
		if(!oldTempFilesPeerDir.isDirectory()) {
			Logger.error(this, "Persistent temporary files location is not a directory: " + oldTempFilesPeerDir.getPath());
			return false;
		}

		boolean gotError = false;
		File[] oldTempFiles = oldTempFilesPeerDir.listFiles(new FileFilter() {

			private final int lastGoodMainBuildNumber = Version.lastGoodBuild();
			private final int recommendedExtBuildNumber = NodeStarter.RECOMMENDED_EXT_BUILD_NUMBER;

			@Override
			public boolean accept(File file) {
				String fileName = file.getName();

				if(fileName.startsWith("revocation-") && fileName.endsWith(".fblob.tmp"))
					return true;

				String buildNumberStr;
				int buildNumber;
				Matcher extBuildNumberMatcher = extBuildNumberPattern.matcher(fileName);
				Matcher mainBuildNumberMatcher = mainBuildNumberPattern.matcher(fileName);
				Matcher extTempBuildNumberMatcher = extTempBuildNumberPattern.matcher(fileName);
				Matcher mainTempBuildNumberMatcher = mainTempBuildNumberPattern.matcher(fileName);
				Matcher revocationTempBuildNumberMatcher = revocationTempBuildNumberPattern.matcher(fileName);

				if(mainBuildNumberMatcher.matches()) {
					try {
					buildNumberStr = mainBuildNumberMatcher.group(1);
					buildNumber = Integer.parseInt(buildNumberStr);
					if(buildNumber < lastGoodMainBuildNumber)
						return true;
					} catch (NumberFormatException e) {
						Logger.error(this, "Wierd file in persistent temp: "+fileName);
						return false;
					}
				} else if(extBuildNumberMatcher.matches()) {
					try {
					buildNumberStr = extBuildNumberMatcher.group(1);
					buildNumber = Integer.parseInt(buildNumberStr);
					if(buildNumber < recommendedExtBuildNumber)
						return true;
					} catch (NumberFormatException e) {
						Logger.error(this, "Wierd file in persistent temp: "+fileName);
						return false;
					}
				} else if(mainTempBuildNumberMatcher.matches() || extTempBuildNumberMatcher.matches() || revocationTempBuildNumberMatcher.matches()) {
					// Temporary file, can be deleted
					return true;
				}

				return false;
			}
		});

		for(File fileToDelete : oldTempFiles) {
			String fileToDeleteName = fileToDelete.getName();
			if(!fileToDelete.delete()) {
				if(fileToDelete.exists())
					Logger.error(this, "Cannot delete temporary persistent file " + fileToDeleteName + " even though it exists: must be TOO persistent :)");
				else
					Logger.normal(this, "Temporary persistent file does not exist when deleting: " + fileToDeleteName);
				gotError = true;
			}
		}

		return !gotError;
	}

	@Override
	public boolean persistent() {
		return false;
	}

	@Override
	public void removeFrom(ObjectContainer container) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean realTimeFlag() {
		return false;
	}

}