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

import freenet.cli.subcommand.WrapperConf;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.UsageMessageSpec;

@Command(name = "oredcli", description = "Command-line utilities and administration tools for Oldenet",
		optionListHeading = "%nOptions:%n", mixinStandardHelpOptions = true,
		versionProvider = JPMSVersionProvider.class, subcommands = { CommandLine.HelpCommand.class, WrapperConf.class })
public class Cli {

	public static void main(String... args) {
		// bootstrap the application
		var commandLine = new CommandLine(new Cli());
		commandLine.getHelpSectionMap().put(UsageMessageSpec.SECTION_KEY_HEADER, (help) -> help
				.createHeading("Oldenet CLI " + "v" + commandLine.getCommandSpec().version()[0] + "%n%n"));
		System.exit(commandLine.execute(args));
	}

}
