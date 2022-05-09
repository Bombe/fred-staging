package freenet.bucket;

import freenet.clientlogger.Logger;
import freenet.support.io.FilenameGenerator;

import java.io.File;
import java.io.IOException;
import java.util.Random;

public class BucketFilenameGenerator extends FilenameGenerator {

	/**
	 * @param random
	 * @param wipeFiles
	 * @param dir if <code>null</code> then use the default temporary directory
	 * @param prefix
	 * @throws IOException
	 */
	public BucketFilenameGenerator(Random random, boolean wipeFiles, File dir, String prefix) throws IOException {
		super(random, wipeFiles, dir, prefix);
	}

	public File maybeMove(File file, long id) {
		if (matches(file))
			return file;
		File newFile = getFilename(id);
		Logger.normal(this, "Moving tempfile " + file + " to " + newFile);
		if (BucketFileUtil.moveTo(file, newFile, false))
			return newFile;
		else {
			Logger.error(this, "Unable to move old temporary file " + file + " to " + newFile);
			return file;
		}
	}

}
