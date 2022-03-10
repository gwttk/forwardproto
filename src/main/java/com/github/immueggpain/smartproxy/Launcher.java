package com.github.immueggpain.smartproxy;

import java.util.concurrent.Callable;

import com.github.immueggpain.smartproxytool.DedupUserrule;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.HelpCommand;

@Command(description = "Please report issues at https://github.com/Immueggpain/forwardproto/issues",
		name = "smartproxy", mixinStandardHelpOptions = true, version = Launcher.VERSTR,
		subcommands = { HelpCommand.class, Smartproxy.class, SmartproxyServer.class, DedupUserrule.class })
public class Launcher implements Callable<Void> {

	public static final String VERSTR = "2.0.9";

	// settings for both client & server
	public static final String[] TLS_CIPHERS = new String[] { "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" };
	public static final String[] TLS_PROTOCOLS = new String[] { "TLSv1.2" };

	/** basic connect timeout */
	public static final int toBasicConnect = 10 * 1000;
	/** basic read timeout */
	public static final int toBasicRead = 300 * 1000;
	/** small timeout when server read from client at connection start */
	public static final int toSvrReadFromCltSmall = 10 * 1000;

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
