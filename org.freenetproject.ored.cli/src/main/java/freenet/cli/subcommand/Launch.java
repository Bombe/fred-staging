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
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Scanner;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import freenet.support.SimpleFieldSet;
import net.harawata.appdirs.AppDirs;
import net.harawata.appdirs.AppDirsFactory;
import org.apache.commons.lang3.SystemUtils;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "launch", description = "Launch Oldenet and browser.")
public class Launch implements Callable<Integer> {

	@CommandLine.Spec
	CommandLine.Model.CommandSpec spec;

	@Option(names = "--ini-path", paramLabel = "PATH",
			description = "Path to freenet.ini. If not specified, I'll look for it in default user data directory.")
	Path iniPath;

	@Option(names = "--ored-path", paramLabel = "PATH",
			description = "Path to ored.bat/ored.sh start script. If not specified, I'll look for it in the same directory I'm in.")
	Path oredPath;

	@Override
	public Integer call() throws Exception {
		var rt = Runtime.getRuntime();

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

			if (SystemUtils.IS_OS_WINDOWS) {
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

		if (this.iniPath == null) {
			AppDirs appDirs = AppDirsFactory.getInstance();
			File userDataDir = new File(appDirs.getUserDataDir("ored", "", "Oldenet"));
			this.iniPath = Paths.get(userDataDir.getAbsolutePath(), "freenet.ini");
		}

		try (var br = Files.newBufferedReader(this.iniPath)) {
			var sfs = new SimpleFieldSet(br, true, true);

			// Try to connect to node port
			var listenPort = Integer.parseInt(sfs.get("node.listenPort"));
			var bindTo = sfs.get("node.bindTo");

			// Check if Oldenet is running
			try (var ignored = new DatagramSocket(new InetSocketAddress(bindTo, listenPort))) {
				// If not, start Oldenet
				System.out.println("Node is not running. Starting...");
				if (SystemUtils.IS_OS_WINDOWS) {
					var scProcess = rt.exec("sc query ored");
					Scanner reader = new Scanner(scProcess.getInputStream(), StandardCharsets.UTF_8);
					var serviceInstalled = false;
					while (reader.hasNextLine()) {
						if (reader.nextLine().contains("ored")) {
							serviceInstalled = true;
							System.out.println("Oldenet service detected.");
							break;
						}
					}

					if (serviceInstalled) {
						rt.exec(this.oredPath.getParent() + "\\Elevate.exe net start ored");
					}
					else {
						rt.exec("cmd.exe /c start cmd.exe /c \"" + this.oredPath + "\"");
					}
				}
				else {
					// TODO: other OS
				}
			}
			catch (IOException ex) {
				ex.printStackTrace();
				// Unable to bind to the port. Node is running.
				System.out.println("Node is running.");
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

			// Wait for 3 seconds for Node to start
			TimeUnit.SECONDS.sleep(3);

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
				if (SystemUtils.IS_OS_WINDOWS) {
					rt.exec("cmd.exe /c \"start " + fproxyUrl + "\"");
				}
				else if (SystemUtils.IS_OS_MAC) {
					rt.exec("open " + fproxyUrl);
				}
				else if (SystemUtils.IS_OS_LINUX) {
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
					"Unable to read freenet.ini file. Check whether --ini-path is correct.", ex,
					this.spec.findOption("--ini-path"), this.iniPath.toString());
		}

		return 0;
	}

	private void printAndHold(String msg) throws IOException {
		System.out.println(msg);
		System.out.println("Press any key to continue.");
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		in.readLine();
	}

}
