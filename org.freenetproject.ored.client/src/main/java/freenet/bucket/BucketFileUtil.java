package freenet.bucket;

import freenet.support.io.FileUtil;
import freenet.support.io.FilenameGenerator;

import java.io.File;
import java.io.IOException;

public class BucketFileUtil {

	public static boolean copyFile(File copyFrom, File copyTo) {
		copyTo.delete();
		boolean executable = copyFrom.canExecute();
		FileBucket outBucket = new FileBucket(copyTo, false, true, false, false);
		FileBucket inBucket = new FileBucket(copyFrom, true, false, false, false);
		try {
			BucketTools.copy(inBucket, outBucket);
			if (executable) {
				if (!(copyTo.setExecutable(true) || copyTo.canExecute())) {
					System.err.println("Unable to preserve executable bit when copying " + copyFrom + " to " + copyTo
							+ " - you may need to make it executable!");
					// return false; ??? FIXME debatable.
				}
			}
			return true;
		}
		catch (IOException e) {
			System.err.println("Unable to copy from " + copyFrom + " to " + copyTo);
			return false;
		}
	}

	/**
	 * Like renameTo(), but can move across filesystems, by copying the data.
	 * @param orig
	 * @param dest
	 * @param overwrite
	 */
	public static boolean moveTo(File orig, File dest, boolean overwrite) {
		if (orig.equals(dest))
			throw new IllegalArgumentException("Huh? the two file descriptors are the same!");
		if (!orig.exists()) {
			throw new IllegalArgumentException("Original doesn't exist!");
		}
		if (dest.exists()) {
			if (overwrite)
				dest.delete();
			else {
				System.err.println("Not overwriting " + dest + " - already exists moving " + orig);
				return false;
			}
		}
		if (!orig.renameTo(dest))
			return copyFile(orig, dest);
		else
			return true;
	}

}
