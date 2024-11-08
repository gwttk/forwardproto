package com.github.immueggpain.smartproxy;

import java.util.concurrent.Callable;

import com.github.immueggpain.smartproxytool.DedupUserrule;
import com.github.immueggpain.smartproxytool.ParseGeoDat;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.HelpCommand;

@Command(description = "Please report issues at https://github.com/gwttk/forwardproto/issues",
		name = "smartproxy", mixinStandardHelpOptions = true, version = Launcher.VERSTR, subcommands = {
				HelpCommand.class, Smartproxy.class, SmartproxyServer.class, DedupUserrule.class, ParseGeoDat.class })
public class Launcher implements Callable<Void> {

	public static final String VERSTR = "2.6.0";

	// settings for both client & server
	public static final String[] TLS_CIPHERS = new String[] { "TLS_AES_128_GCM_SHA256" };
	public static final String[] TLS_PROTOCOLS = new String[] { "TLSv1.3" };

	/** basic connect timeout */
	public static final int toBasicConnect = 10 * 1000;
	/** small timeout when server read from client at connection start */
	public static final int toSvrReadFromCltSmall = 10 * 1000;

	/** opcode: tcp forward */
	public static final int OPCODE_TCP = 1;
	/** opcode: udp forward */
	public static final int OPCODE_UDP = 2;
	/** opcode: keep-alive */
	public static final int OPCODE_KEEPALIVE = 3;

	public static void main(String[] args) {
		int exitCode = new CommandLine(new Launcher()).setCaseInsensitiveEnumValuesAllowed(true)
				.setUsageHelpLongOptionsMaxWidth(40).setUsageHelpAutoWidth(true).execute(args);
		System.exit(exitCode);
	}

	@Override
	public Void call() throws Exception {
		CommandLine.usage(this, System.out);
		return null;
	}

}
