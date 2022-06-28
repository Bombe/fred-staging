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

package freenet.io.comm;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Objects;

import freenet.io.Serializer;
import freenet.nodelogger.Logger;
import freenet.support.ShortBuffer;

public class MessageType {

	public static final String VERSION = "$Id: MessageType.java,v 1.6 2005/08/25 17:28:19 amphibian Exp $";

	private static final HashMap<Integer, MessageType> _specs = new HashMap<>();

	private final String _name;

	private final LinkedList<String> _orderedFields = new LinkedList<>();

	private final HashMap<String, Class<?>> _fields = new HashMap<>();

	private final HashMap<String, Class<?>> _linkedListTypes = new HashMap<>();

	private final boolean internalOnly;

	private final short priority;

	private final boolean isLossyPacketMessage;

	public MessageType(String name, short priority) {
		this(name, priority, false, false);
	}

	public MessageType(String name, short priority, boolean internal, boolean isLossyPacketMessage) {
		this._name = name;
		this.priority = priority;
		this.isLossyPacketMessage = isLossyPacketMessage;
		this.internalOnly = internal;
		// XXX hashCode() is NOT required to be unique!
		Integer id = name.hashCode();
		if (_specs.containsKey(id)) {
			throw new RuntimeException("A message type by the name of " + name + " already exists!");
		}
		_specs.put(id, this);
	}

	public void unregister() {
		_specs.remove(this._name.hashCode());
	}

	public void addLinkedListField(String name, Class<?> parameter) {
		this._linkedListTypes.put(name, parameter);
		this.addField(name, LinkedList.class);
	}

	public void addField(String name, Class<?> type) {
		this._fields.put(name, type);
		this._orderedFields.addLast(name);
	}

	public void addRoutedToNodeMessageFields() {
		this.addField(DMT.UID, Long.class);
		this.addField(DMT.TARGET_LOCATION, Double.class);
		this.addField(DMT.HTL, Short.class);
		this.addField(DMT.NODE_IDENTITY, ShortBuffer.class);
	}

	public boolean checkType(String fieldName, Object fieldValue) {
		if (fieldValue == null) {
			return false;
		}
		Class<?> defClass = this._fields.get(fieldName);
		if (defClass == null) {
			throw new IllegalStateException("Cannot set field \"" + fieldName + "\" which is not defined"
					+ " in the message type \"" + this.getName() + "\".");
		}
		Class<?> valueClass = fieldValue.getClass();
		if (defClass == valueClass) {
			return true;
		}
		return defClass.isAssignableFrom(valueClass);
	}

	public Class<?> typeOf(String field) {
		return this._fields.get(field);
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof MessageType)) {
			return false;
		}
		// We can only register one MessageType for each name.
		// So we can do == here.
		return Objects.equals(((MessageType) o)._name, this._name);
	}

	@Override
	public int hashCode() {
		return this._name.hashCode();
	}

	public static MessageType getSpec(Integer specID, boolean dontLog) {
		MessageType id = _specs.get(specID);
		if (id == null) {
			if (!dontLog) {
				Logger.error(MessageType.class, "Unrecognised message type received (" + specID + ')');
			}
		}
		return id;
	}

	public String getName() {
		return this._name;
	}

	public Map<String, Class<?>> getFields() {
		return this._fields;
	}

	public LinkedList<String> getOrderedFields() {
		return this._orderedFields;
	}

	public Map<String, Class<?>> getLinkedListTypes() {
		return this._linkedListTypes;
	}

	/**
	 * @return True if this message is internal-only. If this is the case, any incoming
	 * messages in UDP form of this spec will be silently discarded.
	 */
	public boolean isInternalOnly() {
		return this.internalOnly;
	}

	/**
	 * @return The default priority for the message type. Messages's don't necessarily use
	 * this: Message.boostPriority() can increase it for a realtime message, for instance.
	 */
	public short getDefaultPriority() {
		return this.priority;
	}

	/** Only works for simple messages!! */
	public int getMaxSize(int maxStringLength) {
		// This method mirrors Message.encodeToPacket.
		int length = 0;
		length += 4; // _spec.getName().hashCode()
		for (Map.Entry<String, Class<?>> entry : this._fields.entrySet()) {
			length += Serializer.length(entry.getValue(), maxStringLength);
		}
		return length;
	}

	public boolean isLossyPacketMessage() {
		return this.isLossyPacketMessage;
	}

}
