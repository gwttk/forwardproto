package com.github.immueggpain.smartproxy;

import java.io.PrintWriter;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;

import com.github.immueggpain.smartproxy.Smartproxy.Settings;

public class Launcher {

	public static void main(String[] args) {
		// in laucher, we dont use log file, just print to console
		// cuz it's all about process input args
		try {
			new Launcher().run(args);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void run(String[] args) {
		// option long names
		String help = "help";
		String log = "log";
		String mode = "mode";
		String password = "password";
		String local_listen_ip = "local_listen_ip";
		String local_listen_port = "local_listen_port";
		String server_ip = "server_ip";
		String server_port = "server_port";

		// define options
		Options options = new Options();
		options.addOption("h", help, false, "print help");
		options.addOption("l", log, true, "log file path");
		options.addOption("m", mode, true, "mode, server or client, default is client");
		options.addOption("w", password, true, "passwords of server & client must be same");
		options.addOption("l", local_listen_ip, true, "local listening ip");
		options.addOption("n", local_listen_port, true, "local listening port");
		options.addOption("s", server_ip, true, "server ip");
		options.addOption("p", server_port, true, "server port");

		// parse from cmd args
		DefaultParser parser = new DefaultParser();
		CommandLine cmd = parser.parse(options, args);
		settings = new Settings();

		// maybe it's server?
		if (cmd.hasOption(mode)) {
			if (cmd.getOptionValue(mode).equals("server")) {
				// run as server
				try {
					settings.password = cmd.getOptionValue(password);
					new SmartproxyServer().run(settings);
				} catch (Exception e) {
					e.printStackTrace();
				}
				return;
			}
		}

		settings.local_listen_ip = cmd.getOptionValue(local_listen_ip, "127.0.0.1");
		settings.local_listen_port = Integer.parseInt(cmd.getOptionValue(local_listen_port, "1083"));
		settings.server_ip = cmd.getOptionValue(server_ip);
		settings.server_port = Integer.parseInt(cmd.getOptionValue(server_port));
		settings.password = cmd.getOptionValue(password);

		if (cmd.hasOption('h')) {
			HelpFormatter formatter = new HelpFormatter();
			formatter.printHelp("smartproxy", options, true);
			return;
		}
	}

}
