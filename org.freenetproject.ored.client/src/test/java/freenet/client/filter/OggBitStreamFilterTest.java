package freenet.client.filter;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

import junit.framework.Assert;
import junit.framework.TestCase;

public class OggBitStreamFilterTest extends TestCase {

	public void testGetVorbisBitstreamFilter() throws IOException {
		DataInputStream input = new DataInputStream(getClass().getResourceAsStream("/filter/ogg/vorbis_header.ogg"));
		OggPage page = OggPage.readPage(input);
		Assert.assertEquals(VorbisBitstreamFilter.class, getFilterClass(page));
		input.close();
	}

	public void testGetTheoraBitStreamFilter() throws IOException {
		DataInputStream input = new DataInputStream(getClass().getResourceAsStream("/filter/ogg/theora_header.ogg"));
		OggPage page = OggPage.readPage(input);
		Assert.assertEquals(TheoraBitstreamFilter.class, getFilterClass(page));
		input.close();
	}

	public void testGetFilterForInvalidFormat() throws IOException {
		InputStream input = getClass().getResourceAsStream("/filter/ogg/invalid_header.ogg");
		DataInputStream dis = new DataInputStream(input);
		OggPage page = OggPage.readPage(dis);
		Assert.assertEquals(null, getFilterClass(page));
		input.close();
	}

	public void testPagesOutOfOrderCausesException() throws IOException {
		DataInputStream input = new DataInputStream(
				getClass().getResourceAsStream("/filter/ogg/pages_out_of_order.ogg"));
		OggPage page = OggPage.readPage(input);
		OggBitstreamFilter filter = new OggBitstreamFilter(page);
		page = OggPage.readPage(input);
		try {
			filter.parse(page);
			fail("Expected exception not caught");
		}
		catch (DataFilterException e) {
		}
		input.close();
	}

	private Class<? extends OggBitstreamFilter> getFilterClass(OggPage page) {
		OggBitstreamFilter filter = OggBitstreamFilter.getBitstreamFilter(page);
		if (filter != null)
			return filter.getClass();
		return null;
	}

}
