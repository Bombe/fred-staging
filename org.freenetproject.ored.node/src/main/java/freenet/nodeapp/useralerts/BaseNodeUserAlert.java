/*
 * freenet - AbstractUserAlert.java Copyright © 2007 David Roden
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307, USA.
 */

package freenet.nodeapp.useralerts;

import freenet.clients.fcp.FCPMessage;
import freenet.clients.fcp.FCPUserAlert;
import freenet.clients.fcp.FeedMessage;
import freenet.support.HTMLNode;
import freenet.support.node.BaseUserAlert;

/**
 * Abstract base implementation of a {@link UserAlert}.
 * 
 * @author David &lsquo;Bombe&rsquo; Roden &lt;bombe@freenetproject.org&gt;
 * @version $Id$
 */
public abstract class BaseNodeUserAlert extends BaseUserAlert implements FCPUserAlert {
	public BaseNodeUserAlert() {
	}

	public BaseNodeUserAlert(boolean userCanDismiss, String title, String text, String shortText, HTMLNode htmlText, short priorityClass, boolean valid, String dismissButtonText, boolean shouldUnregisterOnDismiss, Object userIdentifier) {
		super(userCanDismiss, title, text, shortText, htmlText, priorityClass, valid, dismissButtonText, shouldUnregisterOnDismiss, userIdentifier);
	}

	@Override
	public FCPMessage getFCPMessage() {
		return new FeedMessage(getTitle(), getShortText(), getText(), getPriorityClass(), getUpdatedTime());
	}

}
