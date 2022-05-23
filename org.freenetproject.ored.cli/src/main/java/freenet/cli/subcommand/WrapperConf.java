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

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.concurrent.Callable;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "wrapperconf", description = "Create a custom configuration file for Wrapper")
public class WrapperConf implements Callable<Integer> {

	@Option(names = "--ini-path", required = true, paramLabel = "PATH", description = "Path to freenet.ini")
	String iniPath;

	@Parameters(paramLabel = "FILE", description = "File path to save the custom configuration file")
	File customConfFile;

	@Override
	public Integer call() throws Exception {
		try (var writer = new BufferedWriter(new FileWriter(this.customConfFile))) {
			writer.append("wrapper.app.parameter.1=");
			writer.append(this.iniPath);
			writer.append("\n");
		}
		return 0;
	}

}
