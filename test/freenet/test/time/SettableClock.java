package freenet.test.time;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

/**
 * {@link Clock} implementation whose {@link #instant()} can be {@link #setInstant(Instant) set} for usage in tests.
 * <p>
 * Usage:
 * </p>
 * <pre>
 * Instant now = Instant.now();
 * SettableClock testClock = new SettableClock(now);
 * recordCurrentTime1();
 * testClock.setInstant(now.plusMillis(50));
 * recordCurrentTime2();
 * </pre>
 * In {@code recordCurrentTime2()} the instant returned by {@code testClock} will have been advanced by 50 milliseconds.
 */
public class SettableClock extends Clock {

	public SettableClock() {
		this(ZoneId.systemDefault());
	}

	public SettableClock(ZoneId zoneId) {
		this(zoneId, Instant.now());
	}

	public SettableClock(Instant instant) {
		this(ZoneId.systemDefault(), instant);
	}

	public SettableClock(ZoneId zoneId, Instant instant) {
		this.zoneId = zoneId;
		this.instant = instant;
	}

	@Override
	public ZoneId getZone() {
		return zoneId;
	}

	@Override
	public Clock withZone(ZoneId zone) {
		return new SettableClock(zone, instant);
	}

	@Override
	public Instant instant() {
		return instant;
	}

	public void setInstant(Instant instant) {
		this.instant = instant;
	}

	private final ZoneId zoneId;
	private Instant instant;

}
