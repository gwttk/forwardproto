package com.github.immueggpain.smartproxytool;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.github.immueggpain.common.scp;
import com.github.immueggpain.common.scp.ProcessResult;

/**
 * process the log to get all default rules. ping them to check if DIRECT is
 * better than PROXY
 */
class LogProcessor {

	private static final Pattern ping_regex_win = Pattern.compile("time([=<])([0-9]+)ms");
	private static final Pattern default_line = Pattern.compile(".+ socks5 : PROXY  <- default <- (.+)");

	public static void main(String[] args) {
		try {
			new LogProcessor().run(args[0]);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void run(String logFilePath) throws IOException {
		HashSet<String> rules = new HashSet<>();
		HashSet<String> recordedDomains = new HashSet<>();
		HashSet<String> unpingableDomains = new HashSet<>();
		List<String> lines = Files.readAllLines(Paths.get(logFilePath), StandardCharsets.UTF_8);
		for (String line : lines) {
			Matcher m = default_line.matcher(line);
			if (m.find()) {
				String domainName = m.group(1);

				// check if already encountered
				if (recordedDomains.contains(domainName))
					continue;
				recordedDomains.add(domainName);

				// nslookup
				InetAddress addr;
				try {
					addr = InetAddress.getByName(domainName);
				} catch (UnknownHostException e) {
					continue;
				}

				float latency1 = ping_win(addr);
				float latency2 = ping_win(addr);
				if (latency1 < 0 || latency2 < 0) {
					System.out.println("#### can't ping: " + domainName + " " + addr.getHostAddress());
					unpingableDomains.add(domainName);
					
				} else {
					float latency = (latency1 + latency2) / 2;
					System.out.println(domainName + " " + latency + "ms" + " " + addr.getHostAddress());

					if (latency <= 50) {
						rules.add(domainName + " direct");
					} else if (latency > 160) {
						rules.add(domainName + " proxy");
					} else {

					}
				}
			}
		}
		System.out.println("==========rules:");
		for (String rule : rules) {
			System.out.println(rule);
		}
	}

	public static float ping_win(InetAddress ip) throws IOException {
		ProcessResult r = scp.collectResult(Runtime.getRuntime().exec("ping -n 1 " + ip.getHostAddress()));
		Matcher m = ping_regex_win.matcher(r.stdout);
		if (m.find()) {
			if (m.group(1).equals("<"))
				return Float.parseFloat(m.group(2)) - 0.5F;
			else
				return Float.parseFloat(m.group(2));
		} else
			return -1;
	}

}
