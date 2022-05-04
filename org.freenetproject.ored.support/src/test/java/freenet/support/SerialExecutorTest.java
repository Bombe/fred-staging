package freenet.support;

import freenet.support.io.NativeThread;
import freenet.support.node.PrioRunnable;
import junit.framework.TestCase;

public class SerialExecutorTest extends TestCase {
	
	public void testBlocking() {
		SerialExecutor exec = new SerialExecutor(NativeThread.NORM_PRIORITY);
		exec.start(new PooledExecutor(), "test");
		final MutableBoolean flag = new MutableBoolean();
		exec.execute(new PrioRunnable() {

			@Override
			public void run() {
				try {
					// Do nothing
				} finally {
					synchronized(flag) {
						flag.value = true;
						flag.notifyAll();
					}
				}
				
			}

			@Override
			public int getPriority() {
				return NativeThread.NORM_PRIORITY;
			}
			
		});
		synchronized(flag) {
			while(!flag.value) {
				try {
					flag.wait();
				} catch (InterruptedException e) {
					// Ignore
				}
			}
		}
	}

}
