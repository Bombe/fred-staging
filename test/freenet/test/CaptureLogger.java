package freenet.test;

import java.util.ArrayList;
import java.util.List;

import freenet.support.Logger;
import freenet.support.LoggerHook;
import org.junit.rules.ExternalResource;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

import static freenet.support.Logger.LogLevel.MINIMAL;

public class CaptureLogger extends ExternalResource {

	public List<String> getLoggedMessages() {
		return loggedMessages;
	}

	@Override
	public Statement apply(Statement base, Description description) {
		return new Statement() {
			@Override
			public void evaluate() throws Throwable {
				Logger.globalAddHook(loggerHook);
				try {
					base.evaluate();
				} finally {
					Logger.globalRemoveHook(loggerHook);
				}
			}
		};
	}

	private final List<String> loggedMessages = new ArrayList<>();
	private final LoggerHook loggerHook = new LoggerHook(MINIMAL) {
		@Override
		public void log(Object o, Class<?> source, String message, Throwable e, LogLevel priority) {
			loggedMessages.add(priority.name() + ": " + message);
		}
	};

}
