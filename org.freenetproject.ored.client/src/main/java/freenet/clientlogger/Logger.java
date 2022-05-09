package freenet.clientlogger;

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
