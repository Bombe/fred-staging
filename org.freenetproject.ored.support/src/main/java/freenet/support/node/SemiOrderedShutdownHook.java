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

package freenet.support.node;

import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.win32.StdCallLibrary;

public final class SemiOrderedShutdownHook extends Thread {

	private static final long TIMEOUT = TimeUnit.SECONDS.toMillis(100);

	private final ArrayList<Thread> earlyJobs;

	private final ArrayList<Thread> lateJobs;

	public static final SemiOrderedShutdownHook singleton = new SemiOrderedShutdownHook();

	static {
		Runtime.getRuntime().addShutdownHook(singleton);

		if (Platform.isWindows()) {
			var ret = Kernel32Ex.INSTANCE.SetConsoleCtrlHandler((dwCtrlType) -> {
				if (dwCtrlType == 2 || dwCtrlType == 5 || dwCtrlType == 6) {
					try {
						singleton.start();
					}
					catch (IllegalThreadStateException ignored) {
						// Already started. Just join.
					}
					try {
						singleton.join();
					}
					catch (InterruptedException ignored) {
						return false;
					}
					try {
						// Sleep for 1 second for users to see shutdown information
						TimeUnit.SECONDS.sleep(1);
					}
					catch (InterruptedException ignored) {

					}
					return true;
				}
				return false;
			}, true);

			if (ret) {
				System.out.println("SetConsoleCtrlHandler registered");
			}
			else {
				System.out.println("SetConsoleCtrlHandler failed to register");
			}
		}
	}

	public static SemiOrderedShutdownHook get() {
		return singleton;
	}

	private SemiOrderedShutdownHook() {
		this.earlyJobs = new ArrayList<>();
		this.lateJobs = new ArrayList<>();
	}

	public synchronized void addEarlyJob(Thread r) {
		this.earlyJobs.add(r);
	}

	public synchronized void addLateJob(Thread r) {
		this.lateJobs.add(r);
	}

	@Override
	public void run() {
		System.err.println("Shutting down...");
		// First run early jobs, all at once, and wait for them to all complete.

		Thread[] early = this.getEarlyJobs();

		for (Thread r : early) {
			r.start();
		}
		for (Thread r : early) {
			try {
				r.join(TIMEOUT);
			}
			catch (InterruptedException ignored) {
				// :(
				// May as well move on
			}
		}

		Thread[] late = this.getLateJobs();

		// Then run late jobs, all at once, and wait for them to all complete (JVM will
		// exit when we return).
		for (Thread r : late) {
			r.start();
		}
		for (Thread r : late) {
			try {
				r.join(TIMEOUT);
			}
			catch (InterruptedException ignored) {
				// :(
				// May as well move on
			}
		}

	}

	private synchronized Thread[] getEarlyJobs() {
		return this.earlyJobs.toArray(new Thread[0]);
	}

	private synchronized Thread[] getLateJobs() {
		return this.lateJobs.toArray(new Thread[0]);
	}

	interface Kernel32Ex extends StdCallLibrary {

		Kernel32Ex INSTANCE = Native.load("kernel32", Kernel32Ex.class);

		boolean SetConsoleCtrlHandler(HANDLER_ROUTINE handler, boolean add);

		interface HANDLER_ROUTINE extends StdCallLibrary.StdCallCallback {

			boolean callback(int dwCtrlType);

		}

	}

}
