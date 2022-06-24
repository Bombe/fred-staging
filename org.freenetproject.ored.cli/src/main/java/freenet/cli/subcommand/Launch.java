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

package freenet.cli.subcommand;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.sun.jna.Platform;
import com.sun.jna.platform.win32.W32ServiceManager;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.Winsvc;
import freenet.cli.Common;
import freenet.cli.mixin.IniPathOption;
import freenet.support.SimpleFieldSet;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "launch", description = "Launch Oldenet and browser.")
public class Launch implements Callable<Integer> {

	// Flag to prevent from running node twice
	boolean nodeHasRun = false;

	@CommandLine.Spec
	CommandLine.Model.CommandSpec spec;

	@CommandLine.Mixin
	private IniPathOption iniPathOptionMixin;

	@Option(names = "--ored-path", paramLabel = "PATH",
			description = "Path to ored.bat/ored.sh start script. If not specified, I'll look for it in the same directory I'm in.")
	Path oredPath;

	@Option(names = "--node-may-never-run",
			description = "Set this option if Oldenet may have never run and freenet.ini may haven't been created yet. If this option is set, you need to ensure --ini-path is correct.")
	boolean nodeMayNeverRun;

	@Override
	public Integer call() throws Exception {

		if (this.oredPath != null) {
			if (!Files.exists(this.oredPath)) {
				throw new CommandLine.ParameterException(this.spec.commandLine(),
						"Unable to find ored start script. Check whether --ored-path is correct",
						this.spec.findOption("--ored-path"), this.oredPath.toString());
			}
		}
		else {
			var cwd = System.getProperty("user.dir");
			System.out.println("Working dir: " + cwd);

			if (Platform.isWindows()) {
				this.oredPath = Path.of(cwd + "/ored.bat");
			}
			else {
				this.oredPath = Path.of(cwd + "/ored.sh");
			}

			if (!Files.exists(this.oredPath)) {
				throw new Exception(
						"Unable to find ored start script. Please specify the path with --ored-path option");
			}
		}

		var asyncRun = false;
		if (!Files.exists(this.iniPathOptionMixin.iniPath) && this.nodeMayNeverRun) {
			// Assume that the node has never run and freenet.ini hasn't been created
			// Try to start ored
			System.out.println("Preparing for first run. Please be patient.");

			// Create logs dir in data dir for wrapper.log
			var logdir = this.iniPathOptionMixin.iniPath.getParent().resolve("logs");
			if (!Files.exists(logdir)) {
				Files.createDirectories(logdir);
			}

			asyncRun = this.startNode();
			for (var i = 0; i < 15; i++) {
				TimeUnit.SECONDS.sleep(2);
				if (Files.exists(this.iniPathOptionMixin.iniPath)) {
					break;
				}
			}
		}

		try (var br = Files.newBufferedReader(this.iniPathOptionMixin.iniPath)) {
			var sfs = new SimpleFieldSet(br, true, true);

			// Try to connect to node port
			var listenPort = Integer.parseInt(sfs.get("node.listenPort"));
			var bindTo = sfs.get("node.bindTo");

			var nodeIsRunning = false;
			if (!this.nodeHasRun) {
				// Detect if Oldenet is running
				nodeIsRunning = Common.detectNodeIsRunning(bindTo, listenPort);
				if (!nodeIsRunning) {
					// If not, start Oldenet
					System.out.println("Node is not running. Starting...");
					asyncRun = this.startNode();
					nodeIsRunning = true;
				}
				else {
					System.out.println("Node is running.");
				}
			}

			// Check Oldenet is ready
			if (!sfs.get("fproxy.enabled").equals("true")) {
				this.printAndHold("Fproxy is disabled. Browser won't be launched.");
				return 0;
			}

			// Try to request fproxy

			var httpClientBuilder = HttpClient.newBuilder();

			var protocol = "http";
			if (sfs.get("fproxy.ssl").equals("true")) {
				var trustAllCerts = new TrustManager[] { new X509TrustManager() {
					public java.security.cert.X509Certificate[] getAcceptedIssuers() {
						return null;
					}

					public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
					}

					public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
					}
				} };
				var sslContext = SSLContext.getInstance("TLS");
				sslContext.init(null, trustAllCerts, new SecureRandom());

				httpClientBuilder.sslContext(sslContext);
				protocol = "https";
			}

			var fproxyPort = sfs.get("fproxy.port");

			var fproxyUrl = protocol + "://localhost:" + fproxyPort + "/";

			var req = HttpRequest.newBuilder().uri(new URI(fproxyUrl)).timeout(Duration.ofSeconds(3)).GET().build();

			var httpClient = httpClientBuilder.followRedirects(HttpClient.Redirect.NORMAL)
					.version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(3)).build();

			if (!nodeIsRunning || asyncRun) {
				// Wait for 3 seconds for Node to start
				TimeUnit.SECONDS.sleep(3);
			}

			var tries = 0;

			while (true) {
				try {
					System.out.println("Requesting FProxy (" + tries + ")...");
					httpClient.send(req, HttpResponse.BodyHandlers.ofString());
					break;
				}
				catch (Exception ex) {
					System.out.println("Error to connect to FProxy (" + tries + "): " + ex.getMessage());
					// Try at most 3 times
					if (tries < 3) {
						// Wait for 3 seconds and try again
						TimeUnit.SECONDS.sleep(3);
						tries++;
					}
					else {
						this.printAndHold("Unable to connect to FProxy. Browser won't be launched.");
						return 1;
					}
				}
			}

			// Launch browser
			// Avoid using java.awt.Desktop as it requires the huge "java.desktop" module
			// (which contains swing)
			try {
				var rt = Runtime.getRuntime();

				if (Platform.isWindows()) {
					rt.exec("cmd.exe /c \"start " + fproxyUrl + "\"");
				}
				else if (Platform.isMac()) {
					rt.exec("open " + fproxyUrl);
				}
				else if (Platform.isLinux()) {
					rt.exec("x-www-browser " + fproxyUrl);
				}
				else {
					this.printAndHold("Unsupported system. Please open the following link yourself:\n" + fproxyUrl);
				}
			}
			catch (IOException ignored) {
				this.printAndHold("Unable to launch browser. Please open the following link yourself:\n" + fproxyUrl);
			}
		}
		catch (IOException ex) {
			throw new CommandLine.ParameterException(this.spec.commandLine(),
					"Unable to read freenet.ini file. Check whether --ini-path is correct and freenet.ini has proper permission set.",
					ex, this.spec.findOption("--ini-path"), this.iniPathOptionMixin.iniPath.toString());
		}

		return 0;
	}

	private boolean startNode() throws IOException {

		// whether the node is started asynchronously
		var async = false;

		if (this.nodeHasRun) {
			return false;
		}

		var started = false;
		var rt = Runtime.getRuntime();

		if (Platform.isWindows()) {

			try (var scManager = new W32ServiceManager(WinNT.GENERIC_READ)) {
				try (var service = scManager.openService("ored", Winsvc.SERVICE_START | Winsvc.SERVICE_QUERY_STATUS)) {
					System.out.print("Found Oldenet service. Starting...");
					// All users have permission to start/stop the service. Permission is
					// set by the installer. No need to elevate.
					service.startService();
					started = true;
					System.out.println("Done");
				}
				catch (Win32Exception ex) {
					if (ex.getErrorCode() == WinError.ERROR_SERVICE_DOES_NOT_EXIST) {
						System.out.println("Unable to find Oldenet service.");
					}
					else {
						throw ex;
					}
				}
			}

			if (!started) {
				// Run in command window
				rt.exec("cmd.exe /c start cmd.exe /c \"" + this.oredPath + "\"");
				started = true;
				async = true;
			}

		}
		else {
			// TODO: other OS
		}

		if (started) {
			this.nodeHasRun = true;
		}
		return async;
	}

	private void printAndHold(String msg) throws IOException {
		System.out.println(msg);
		System.out.println("Press any key to continue.");
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		in.readLine();
	}

}
