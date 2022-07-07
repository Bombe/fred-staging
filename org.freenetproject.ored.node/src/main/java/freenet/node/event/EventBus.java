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

package freenet.node.event;

/**
 * Currently it's just a simple wrapper of {@link org.greenrobot.eventbus.EventBus}.
 * However, we can modify configurations of EventBus here.
 */
public final class EventBus {

	private EventBus() {
	}

	public static org.greenrobot.eventbus.EventBus get() {
		return org.greenrobot.eventbus.EventBus.getDefault();
	}

}
