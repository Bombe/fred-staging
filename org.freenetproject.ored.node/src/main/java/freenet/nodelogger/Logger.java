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

package freenet.nodelogger;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

public abstract class Logger extends freenet.support.Logger {

	private static void setLoggerSwitch(Class<?> clazz, SetLogSwitch.Field field, boolean shouldLog)
			throws SecurityException, NoSuchFieldException, IllegalArgumentException, IllegalAccessException {
		Field logMINOR_Field = clazz.getDeclaredField(field.name);
		if ((logMINOR_Field.getModifiers() & Modifier.STATIC) != 0) {
			logMINOR_Field.setAccessible(true);
			logMINOR_Field.set(null, shouldLog);
		}
	}

	public static void registerClass(final Class<?> clazz) {
		freenet.support.Logger.registerClass(clazz, Logger::setLoggerSwitch);
	}

}
