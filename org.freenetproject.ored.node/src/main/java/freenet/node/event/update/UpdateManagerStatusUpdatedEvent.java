/*
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

package freenet.node.event.update;

import java.util.EnumMap;

public class UpdateManagerStatusUpdatedEvent {

	public enum StatusType {

		ENABLED, BLOWN, DEPLOYING

	}

	private final EnumMap<StatusType, Boolean> statusMap;

	public UpdateManagerStatusUpdatedEvent(EnumMap<StatusType, Boolean> statusMap) {
		this.statusMap = statusMap;
	}

	public boolean getStatus(StatusType type) {
		return this.statusMap.getOrDefault(type, false);
	}

}
