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

}
