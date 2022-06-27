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

package freenet.client.filter;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;

import freenet.bucket.ArrayBucket;
import freenet.bucket.Bucket;
import freenet.bucket.BucketTools;
import junit.framework.TestCase;

public class M3UFilterTest extends TestCase {

	protected static String[][] testPlaylists = { { "/filter/m3u/safe.m3u", "/filter/m3u/safe_madesafe.m3u" },
			{ "/filter/m3u/unsafe.m3u", "/filter/m3u/unsafe_madesafe.m3u" }, };

	private static final String SCHEME_HOST_PORT = "http://localhost:8888";

	private static final String BASE_KEY = "USK@0I8gctpUE32CM0iQhXaYpCMvtPPGfT4pjXm01oid5Zc,3dAcn4fX2LyxO6uCnWFTx-2HKZ89uruurcKwLSCxbZ4,AQACAAE/FakeM3UHostingFreesite/23/";

	private static final String BASE_URI = '/' + BASE_KEY;

	public void testSuiteTest() throws IOException {
		M3UFilter filter = new M3UFilter();

		for (String[] test : testPlaylists) {
			String original = test[0];
			String correct = test[1];
			Bucket ibo;
			Bucket ibprocessed = new ArrayBucket();
			ArrayBucket ibc;
			ibo = this.resourceToBucket(original);
			ibc = this.resourceToBucket(correct);

			try {
				filter.readFilter(ibo.getInputStream(), ibprocessed.getOutputStream(), "UTF-8", null, SCHEME_HOST_PORT,
						new GenericReadFilterCallback(new URI(BASE_URI), null, null, null));
				String result = ibprocessed.toString();

				// Convert all line breaks to \n

				assertEquals(
						original + " should be filtered as " + correct + " but was filtered as\n" + result
								+ "\ninstead of the correct\n" + this.bucketToString(ibc),
						normalizeEOL(result), normalizeEOL(this.bucketToString(ibc)));
			}
			catch (DataFilterException dfe) {
				fail("Filtering " + original + " failed");
			}
			catch (URISyntaxException use) {
				fail("Creating URI from BASE_URI " + BASE_URI + " failed");
			}
		}
	}

	protected ArrayBucket resourceToBucket(String filename) throws IOException {
		InputStream is = this.getClass().getResourceAsStream(filename);
		if (is == null) {
			throw new java.io.FileNotFoundException(filename);
		}
		ArrayBucket ab = new ArrayBucket();
		BucketTools.copyFrom(ab, is, Long.MAX_VALUE);
		return ab;
	}

	protected String bucketToString(ArrayBucket bucket) throws IOException {
		return new String(bucket.toByteArray());
	}

	private static String normalizeEOL(String content) {
		return content.replaceAll("\\r\\n?", "\n");
	}

}
