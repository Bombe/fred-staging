package freenet.test.matcher;

import freenet.node.stats.CompressionStats.CompressionRun;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import static org.hamcrest.Matchers.any;

/**
 * Hamcrest matcher for a {@link CompressionRun}.
 */
public class CompressionRunMatcher extends TypeSafeDiagnosingMatcher<CompressionRun> {

	/**
	 * Returns a matcher that will match a {@link CompressionRun} by algorithm, size before compression, and size after compression.
	 * In other words, this matcher ignores the duration of a compression run.
	 *
	 * @param algorithm The algorithm to match
	 * @param sizeBeforeCompression The size before compression to match
	 * @param sizeAfterCompression The size after compression to match
	 * @return A matcher that matches the given values
	 */
	public static Matcher<CompressionRun> matchesCompressionRun(String algorithm, long sizeBeforeCompression, long sizeAfterCompression) {
		return matchesCompressionRun(algorithm, any(Long.class), sizeBeforeCompression, sizeAfterCompression);
	}

	/**
	 * Returns a matcher that will match a {@link CompressionRun} by algorithm, duration, size before compression, and size after compression.
	 *
	 * @param algorithm The algorithm to match
	 * @param durationMatcher Matcher for the duration
	 * @param sizeBeforeCompression The size before compression to match
	 * @param sizeAfterCompression The size after compression to match
	 * @return A matcher that matches the given values
	 */
	public static Matcher<CompressionRun> matchesCompressionRun(String algorithm, Matcher<Long> durationMatcher, long sizeBeforeCompression, long sizeAfterCompression) {
		return new CompressionRunMatcher(algorithm, durationMatcher, sizeBeforeCompression, sizeAfterCompression);
	}

	@Override
	protected boolean matchesSafely(CompressionRun run, Description mismatchDescription) {
		if (!run.algorithm.equals(algorithm)) {
			mismatchDescription.appendText("algorithm is ").appendValue(run.algorithm);
			return false;
		}
		if (!durationMatcher.matches(run.duration)) {
			mismatchDescription.appendText("duration is ").appendValue(run.duration);
			return false;
		}
		if (run.sizeBeforeCompression != sizeBeforeCompression) {
			mismatchDescription.appendText("sizeBeforeCompression is ").appendValue(run.sizeBeforeCompression);
			return false;
		}
		if (run.sizeAfterCompression != sizeAfterCompression) {
			mismatchDescription.appendText("sizeAfterCompression is ").appendValue(run.sizeAfterCompression);
			return false;
		}
		return true;
	}

	@Override
	public void describeTo(Description description) {
		description.appendText("run with algorithm ").appendValue(algorithm)
				.appendText(", duration ").appendDescriptionOf(durationMatcher)
				.appendText(", sizeBeforeCompression ").appendValue(sizeBeforeCompression)
				.appendText(", sizeAfterCompression ").appendValue(sizeAfterCompression);
	}

	private CompressionRunMatcher(String algorithm, Matcher<Long> durationMatcher, long sizeBeforeCompression, long sizeAfterCompression) {
		this.algorithm = algorithm;
		this.durationMatcher = durationMatcher;
		this.sizeBeforeCompression = sizeBeforeCompression;
		this.sizeAfterCompression = sizeAfterCompression;
	}

	private final String algorithm;
	private final Matcher<Long> durationMatcher;
	private final long sizeBeforeCompression;
	private final long sizeAfterCompression;

}
