package freenet.clients.http;

import freenet.l10n.BaseL10n;
import freenet.support.HTMLNode;

public class ToadletL10nAdapter {

	BaseL10n base;

	public ToadletL10nAdapter(BaseL10n base) {
		this.base = base;
	}

	/**
	 * Get a localized string and put it in a HTMLNode for the translation page.
	 * @param key Key to search for.
	 * @return HTMLNode
	 */
	public HTMLNode getHTMLNode(String key) {
		return getHTMLNode(key, null, null);
	}

	/**
	 * Get a localized string and put it in a HTMLNode for the translation page.
	 * @param key Key to search for.
	 * @param patterns Patterns to replace. May be null, if so values must also be null.
	 * @param values Values to replace patterns with.
	 * @return HTMLNode
	 */
	public HTMLNode getHTMLNode(String key, String[] patterns, String[] values) {
		String value = this.base.getString(key, true);
		if (value != null) {
			if (patterns != null)
				return new HTMLNode("#", this.base.getString(key, patterns, values));
			else
				return new HTMLNode("#", value);
		}
		HTMLNode translationField = new HTMLNode("span", "class", "translate_it");
		if (patterns != null)
			translationField.addChild("#", this.base.getDefaultString(key, patterns, values));
		else
			translationField.addChild("#", this.base.getDefaultString(key));
		translationField.addChild("a", "href", TranslationToadlet.TOADLET_URL + "?translate=" + key).addChild("small",
				" (translate it in your native language!)");

		return translationField;
	}

}
