package freenet.config;

import freenet.l10n.NodeL10n;
import freenet.support.Fields;

public class ConfigFields extends Fields {

	/*
	 * Removes up to one "(bits) per second" qualifier at the end of the string. If
	 * present such a qualifier will prevent parsing as a size.
	 *
	 * @see freenet.support.Fields#parseInt(String)
	 */
	public static String trimPerSecond(String limit) {
		limit = limit.trim();
		if (limit.isEmpty())
			return "";
		/*
		 * IEC endings are case sensitive, so the input string's case should not be
		 * modified. However, the qualifiers should not be case sensitive.
		 */
		final String lower = limit.toLowerCase();
		for (String ending : new String[] { "/s", "/sec", "/second", "bps",
				NodeL10n.getBase().getString("FirstTimeWizardToadlet.bandwidthPerSecond").toLowerCase() }) {
			if (lower.endsWith(ending)) {
				return limit.substring(0, limit.length() - ending.length());
			}
		}
		return limit;
	}

}
