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

package freenet.cli;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.util.Date;
import java.util.concurrent.TimeoutException;

import com.sun.jna.LastErrorException;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.Winsvc;
import com.sun.jna.ptr.IntByReference;

public final class Common {

	private Common() {
	}

	/**
	 * Detect whether a node is running by trying to bind the same port as the node.
	 * @param hostname Hostname or IP address to bind to
	 * @param port Port number to bind to
	 * @return whether the node is running
	 */
	public static boolean detectNodeIsRunning(String hostname, int port) {
		try (var ignored = new DatagramSocket(new InetSocketAddress(hostname, port))) {
			// If not, start Oldenet
			return false;
		}
		catch (IOException ex) {
			// Unable to bind to the port. Node is running.
			return true;
		}

	}

	public enum ServiceOp {

		START, STOP

	}

	/**
	 * Start or stop a service. <a href=
	 * "https://docs.microsoft.com/en-us/windows/win32/services/stopping-a-service">Reference</a>
	 *
	 * TODO: Starting service not implemented
	 *
	 * @param serviceName Service name
	 * @param op START or STOP
	 */
	public static void controlService(String serviceName, ServiceOp op) throws TimeoutException {
		if (Platform.isWindows()) {
			var advapi32 = Advapi32.INSTANCE;
			var dwStartTime = new Date().getTime();
			int dwTimeout = 30000; // 30-second time-out

			var scManager = advapi32.OpenSCManager(null, null, WinNT.GENERIC_READ);
			if (scManager == null) {
				var error = Native.getLastError();
				if (error == WinError.ERROR_ACCESS_DENIED) {
					// TODO: elevate and try again
				}
				else {
					throw new LastErrorException("OpenSCManager() failed");
				}
			}

			var service = advapi32.OpenService(scManager, serviceName,
					Winsvc.SERVICE_STOP | Winsvc.SERVICE_QUERY_STATUS);

			// Make sure the service is not already stopped.
			var serviceStatusProcess = new Winsvc.SERVICE_STATUS_PROCESS();
			var pcbBytesNeeded = new IntByReference();
			var ret = advapi32.QueryServiceStatusEx(service, Winsvc.SC_STATUS_TYPE.SC_STATUS_PROCESS_INFO,
					serviceStatusProcess, serviceStatusProcess.size(), pcbBytesNeeded);
			if (!ret) {
				throw new LastErrorException("QueryServiceStatusEx() failed");
			}

			if (serviceStatusProcess.dwCurrentState == Winsvc.SERVICE_STOPPED) {
				// Service already stopped
				System.out.println("Service already stopped.");
				return;
			}

			while (serviceStatusProcess.dwCurrentState == Winsvc.SERVICE_STOP_PENDING) {
				System.out.println("Service stop pending...");

				// Do not wait longer than the wait hint. A good interval is
				// one-tenth of the wait hint but not less than 1 second
				// and not more than 10 seconds.

				var dwWaitTime = serviceStatusProcess.dwWaitHint / 10;
				if (dwWaitTime < 1000) {
					dwWaitTime = 1000;
				}
				else if (dwWaitTime > 10000) {
					dwWaitTime = 10000;
				}
				try {
					// noinspection BusyWait
					Thread.sleep(dwWaitTime);
				}
				catch (InterruptedException ex) {
					throw new RuntimeException(ex);
				}

				ret = advapi32.QueryServiceStatusEx(service, Winsvc.SC_STATUS_TYPE.SC_STATUS_PROCESS_INFO,
						serviceStatusProcess, serviceStatusProcess.size(), pcbBytesNeeded);
				if (!ret) {
					throw new LastErrorException("QueryServiceStatusEx() failed");
				}

				if (serviceStatusProcess.dwCurrentState == Winsvc.SERVICE_STOPPED) {
					System.out.println("Service stopped successfully.");
					return;
				}

				if (new Date().getTime() - dwStartTime > dwTimeout) {
					System.err.println("Service stop timed out.");
					throw new TimeoutException("Service stop timed out.");
				}
			}

			// As ored doesn't have any dependencies, we don't have code to stop dependent
			// services.

			// Send a stop code to the service.
			var serviceStatus = new Winsvc.SERVICE_STATUS();
			ret = advapi32.ControlService(service, Winsvc.SERVICE_CONTROL_STOP, serviceStatus);

			if (!ret) {
				throw new LastErrorException("QueryServiceStatusEx() failed");
			}

			while (serviceStatus.dwCurrentState != Winsvc.SERVICE_STOPPED) {
				try {
					// noinspection BusyWait
					Thread.sleep(serviceStatus.dwWaitHint);
				}
				catch (InterruptedException ex) {
					throw new RuntimeException(ex);
				}

				ret = advapi32.QueryServiceStatusEx(service, Winsvc.SC_STATUS_TYPE.SC_STATUS_PROCESS_INFO,
						serviceStatusProcess, serviceStatusProcess.size(), pcbBytesNeeded);
				if (!ret) {
					throw new LastErrorException("QueryServiceStatusEx() failed");
				}

				if (serviceStatusProcess.dwCurrentState == Winsvc.SERVICE_STOPPED) {
					System.err.println("Service stopped successfully.");
					return;
				}

				if (new Date().getTime() - dwStartTime > dwTimeout) {
					System.err.println("Service stop timed out.");
					throw new TimeoutException("Service stop timed out.");
				}
			}

		}
	}

}
