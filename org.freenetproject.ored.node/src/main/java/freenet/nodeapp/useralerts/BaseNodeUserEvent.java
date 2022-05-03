package freenet.nodeapp.useralerts;

import freenet.support.HTMLNode;

public abstract class BaseNodeUserEvent extends BaseNodeUserAlert implements UserEvent {

	private Type eventType;

	public BaseNodeUserEvent(Type eventType, boolean userCanDismiss, String title, String text, String shortText, HTMLNode htmlText, short priorityClass, boolean valid, String dismissButtonText, boolean shouldUnregisterOnDismiss, Object userIdentifier) {
		super(userCanDismiss, title, text, shortText, htmlText, priorityClass, valid, dismissButtonText, shouldUnregisterOnDismiss, userIdentifier);
		this.eventType = eventType;
	}

	public BaseNodeUserEvent() {

	}

	@Override
	public Type getEventType() {
		return eventType;
	}

}
