/*******************************************************************************
 * MIT License
 *
 * Copyright (c) 2018 Immueggpain
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *******************************************************************************/
package com.github.immueggpain.smartproxy;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

public class Launcher {

	private static final String VERSTR = "1.1.1";

	public static class ClientSettings {
		public String local_listen_ip;
		public int local_listen_port;
		public String server_ip;
		public int server_port;
		public String password;
		public String logfile;
	}

	public static class ServerSettings {
		public String password;
		public int server_port;
		public String cert;
		public String private_key;
	}

	public static void main(String[] args) {
		// in laucher, we dont use log file, just print to console
		// cuz it's all about process input args
		try {
			new Launcher().run(args);
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("use -h to see help");
		}
	}

	private void run(String[] args) throws ParseException {
		// option long names
		String help = "help";
		String mode = "mode";
		String plugin = "plugin";
		String log = "log";
		String password = "password";
		String local_listen_ip = "local_listen_ip";
		String local_listen_port = "local_listen_port";
		String server_ip = "server_ip";
		String server_port = "server_port";
		String cert = "cert";
		String private_key = "private_key";

		// define options
		Options options = new Options();
		options.addOption("h", help, false, "print help then exit");
		options.addOption(Option.builder("m").longOpt(mode).hasArg().desc("mode, server or client, default is client")
				.argName("MODE").build());
		options.addOption("u", plugin, false, "start program as ss plugin");
		options.addOption(Option.builder("l").longOpt(log).hasArg().desc("log file path. default is smartproxy.log")
				.argName("PATH").build());
		options.addOption(Option.builder("w").longOpt(password).hasArg()
				.desc("password of server or client, must be same, recommend 64 bytes").argName("PASSWORD").build());
		options.addOption(
				Option.builder("i").longOpt(local_listen_ip).hasArg().desc("local listening ip").argName("IP").build());
		options.addOption(Option.builder("n").longOpt(local_listen_port).hasArg().desc("local listening port")
				.argName("PORT").build());
		options.addOption(Option.builder("s").longOpt(server_ip).hasArg().desc("server ip").argName("IP").build());
		options.addOption(
				Option.builder("p").longOpt(server_port).hasArg().desc("server port").argName("PORT").build());
		options.addOption(Option.builder("c").longOpt(cert).hasArg()
				.desc("SSL cert chain file path. default is fullchain.pem").argName("PATH").build());
		options.addOption(Option.builder("k").longOpt(private_key).hasArg()
				.desc("SSL private key file path. default is privkey.pem").argName("PATH").build());

		// parse from cmd args
		DefaultParser parser = new DefaultParser();
		CommandLine cmd = parser.parse(options, args);

		// first let's check if it's help
		if (cmd.hasOption(help)) {
			String header = "";
			String footer = "\nPlease report issues at https://github.com/Immueggpain/smartproxy/issues";

			HelpFormatter formatter = new HelpFormatter();
			formatter.printHelp("java -jar smartproxy-" + VERSTR + ".jar", header, options, footer, true);
			return;
		}

		// server or client
		if (cmd.hasOption(mode) && cmd.getOptionValue(mode).equals("server")) {
			// run as server
			ServerSettings settings = new ServerSettings();
			settings.password = cmd.getOptionValue(password);
			settings.server_port = Integer.parseInt(cmd.getOptionValue(server_port));
			settings.cert = cmd.getOptionValue(cert, "fullchain.pem");
			settings.private_key = cmd.getOptionValue(private_key, "privkey.pem");
			try {
				new SmartproxyServer().run(settings);
			} catch (Exception e) {
				e.printStackTrace();
			}
			return;
		} else {
			// run as client
			ClientSettings settings = new ClientSettings();
			settings.local_listen_ip = cmd.getOptionValue(local_listen_ip, "127.0.0.1");
			settings.local_listen_port = Integer.parseInt(cmd.getOptionValue(local_listen_port, "1083"));
			settings.server_ip = cmd.getOptionValue(server_ip);
			settings.server_port = Integer.parseInt(cmd.getOptionValue(server_port));
			settings.password = cmd.getOptionValue(password);
			settings.logfile = cmd.getOptionValue(log, "smartproxy.log");
			try {
				new Smartproxy().run(settings);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

}
