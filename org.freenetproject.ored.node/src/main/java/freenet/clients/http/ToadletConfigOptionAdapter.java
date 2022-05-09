package freenet.clients.http;

import freenet.config.Option;
import freenet.l10n.NodeL10n;
import freenet.pluginmanager.FredPluginConfigurable;
import freenet.support.HTMLNode;

public class ToadletConfigOptionAdapter<T> {

	Option<T> option;

	public ToadletConfigOptionAdapter(Option<T> option) {
		this.option = option;
	}

	/**
	 * Get the localised short description as an HTMLNode, possibly with translation link
	 */
	public HTMLNode getShortDescNode(FredPluginConfigurable plugin) {
		return (plugin == null)
				? new ToadletL10nAdapter(NodeL10n.getBase()).getHTMLNode(this.option.getShortDesc(),
						new String[] { "default" }, new String[] { this.option.getDefault() })
				: new HTMLNode("#", plugin.getString(this.option.getShortDesc()));
	}

	public HTMLNode getShortDescNode() {
		return getShortDescNode(null);
	}

	/**
	 * Get the localised long description as an HTMLNode, possibly with translation link
	 */
	public HTMLNode getLongDescNode(FredPluginConfigurable plugin) {
		return (plugin == null)
				? new ToadletL10nAdapter(NodeL10n.getBase()).getHTMLNode(this.option.getLongDesc(),
						new String[] { "default" }, new String[] { this.option.getDefault() })
				: new HTMLNode("#", plugin.getString(this.option.getLongDesc()));
	}

	public HTMLNode getLongDescNode() {
		return getLongDescNode(null);
	}

}
