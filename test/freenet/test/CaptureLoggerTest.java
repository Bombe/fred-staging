package freenet.test;

import org.junit.Test;
import org.junit.runners.model.Statement;

import static freenet.support.Logger.LogLevel.NORMAL;
import static freenet.support.Logger.logStatic;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.runner.Description.EMPTY;

public class CaptureLoggerTest {

	@Test
	public void captureLoggerCanCaptureMessagesSentToLogger() throws Throwable {
		captureLogger.apply(new Statement() {
			@Override
			public void evaluate() {
				logStatic(this, "Test Message", NORMAL);
			}
		}, EMPTY).evaluate();
		assertThat(captureLogger.getLoggedMessages(), hasItem(equalTo("NORMAL: Test Message")));
	}

	@Test
	public void captureLoggerCanNotCaptureMessagesSentToLoggerAfterTheTest() throws Throwable {
		captureLogger.apply(new Statement() {
			@Override
			public void evaluate() {
			}
		}, EMPTY).evaluate();
		logStatic(this, "Test Message", NORMAL);
		assertThat(captureLogger.getLoggedMessages(), not(hasItem(equalTo("NORMAL: Test Message"))));
	}

	private final CaptureLogger captureLogger = new CaptureLogger();

}
