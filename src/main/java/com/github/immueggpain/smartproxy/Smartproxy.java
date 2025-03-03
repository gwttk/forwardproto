package com.github.immueggpain.smartproxy;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.PushbackInputStream;
import java.lang.ref.WeakReference;
import java.net.ConnectException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.BOMInputStream;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.RandomUtils;

import com.github.immueggpain.common.sc;
import com.github.immueggpain.common.scmt;
import com.github.immueggpain.common.sct;
import com.github.immueggpain.common.sctp;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Help.Visibility;

@SuppressWarnings("unused")
@Command(description = "Run client", name = "client", mixinStandardHelpOptions = true, version = Launcher.VERSTR)
public class Smartproxy implements Callable<Void> {

	@Option(names = { "-i", "--local_listen_ip" }, description = "local listening ip",
			showDefaultValue = Visibility.ALWAYS)
	public String local_listen_ip = "127.0.0.1";

	@Option(names = { "-n", "--local_listen_port" }, required = true, description = "local listening port",
			showDefaultValue = Visibility.ALWAYS)
	public int local_listen_port;

	@Option(names = { "-s", "--server_ip", "--server_name" }, required = true, description = "server ip or domain name",
			showDefaultValue = Visibility.ALWAYS)
	public String server_ip;

	@Option(names = { "-p", "--server_port" }, required = true, description = "server port",
			showDefaultValue = Visibility.ALWAYS)
	public int server_port;

	@Option(names = { "-w", "--password" }, required = true,
			description = "password must be same between server and client, recommend 64 bytes",
			showDefaultValue = Visibility.ALWAYS)
	public String passwordString;

	@Option(names = { "-l", "--log" }, description = "log file path", showDefaultValue = Visibility.ALWAYS)
	public String logfile = "smartproxy.log";

	@Option(names = { "-r", "--local-rule" }, description = "local user.rule", showDefaultValue = Visibility.ALWAYS)
	public File local_rule;

	@Option(names = { "--debug" }, description = "enable debug code", showDefaultValue = Visibility.ALWAYS)
	public boolean debug = false;

	@Option(names = { "--sndbuf" }, description = "socket send buf size", showDefaultValue = Visibility.ALWAYS)
	public int sndbuf_size = 0;

	@Option(names = { "--rcvbuf" }, description = "socket recv buf size", showDefaultValue = Visibility.ALWAYS)
	public int rcvbuf_size = 1900000;

	@Option(names = { "--halfopen-max" }, description = "how many half-open tunnels can be used",
			showDefaultValue = Visibility.ALWAYS)
	public int hopen_max = 40;

	@Option(names = { "--halfopen-threads" }, description = "how many threads is used to create half-open tunnels",
			showDefaultValue = Visibility.ALWAYS)
	public int hopen_threads = 4;

	@Option(names = { "--halfopen-rest" }, description = "how many seconds a half-open tunnel can wait",
			showDefaultValue = Visibility.ALWAYS)
	public int hopen_rest = 300;

	@Option(names = { "--halfopen-kalive" }, description = "how many seconds before a half-open tunnel send keep-alive",
			showDefaultValue = Visibility.ALWAYS)
	public int hopen_keepalive = 90;

	@Option(names = { "--to-basic" }, description = "basic timeout value in sec", showDefaultValue = Visibility.ALWAYS)
	public int toBasicRead = 300;

	@Option(names = { "--unsafe-cert" }, description = "trust all certs, whether they are safe or not.",
			showDefaultValue = Visibility.ALWAYS)
	public boolean unsafeCert = false;

	// used in android
	public InputStream userRuleStream;

	// timeouts
	/** client incoming socket read/write timeout */
	private int toCltReadFromApp;
	/** client to server socket after rest read/write timeout */
	public int toCltReadFromSvr;
	/** client to server socket before rest read timeout */
	private int toCltReadFromSvrSmall;
	/** client to server socket connect timeout */
	private int toCltConnectToSvr;
	/** client to direct dest socket read/write timeout */
	private int toCltReadFromDirect;
	/** client to direct dest socket connect timeout */
	private int toCltConnectToDirect;
	/** how long half-open tunnel can rest for */
	private int toSvrReadFromCltRest;

	private static final int BUF_SIZE = 1024 * 512;
	private static final int UDP_PKT_SIZE = 1024 * 8;
	private static final SecureRandom rand = new SecureRandom();

	private static final Pattern httpconnect_regex = Pattern.compile("CONNECT (.+):([0-9]+) HTTP/1[.][01]");
	private static final byte[] httpconnect_okresponse = sc.s2b("HTTP/1.1 200 OK\r\n\r\n");
	private static final byte[] httpconnect_500response = sc.s2b("HTTP/1.1 500 Internal Server Error\r\n\r\n");
	private static final Pattern ip_regex = Pattern.compile("\\d+\\.\\d+\\.\\d+\\.\\d+");
	private static final Pattern domain_regex = Pattern.compile("[a-z0-9-_]*(\\.[a-z0-9-_]+)*");

	private static PrintWriter log;

	private SSLSocketFactory ssf;
	private byte[] password = new byte[64];
	private TunnelPool tunnelPool;

	private Proxy next_proxy;
	private NextNode nn_direct;
	private NextNode nn_ban;
	private NextNode nn_proxy;
	private Map<String, NextNode> domain_to_nn;
	private NavigableMap<Long, IpRange> ip_to_nn;
	private SpeedMeter speedMeter;
	private Http2socks http2socks;

	public Void call() throws Exception {
		// from now on, log output to '-l' option or 'smartproxy.log' by default
		log = new PrintWriter(new BufferedWriter(new OutputStreamWriter(new FileOutputStream(logfile), sc.utf8)), true);
		log.println(String.format("running client %s", Launcher.VERSTR));
		log.println(String.format("running on %s %s at %s.", System.getProperty("java.vendor"),
				System.getProperty("java.runtime.version"), System.getProperty("java.home")));
		log.println(String.format("server is %s", server_ip));
		log.println(String.format("--halfopen-max = %d", hopen_max));
		log.println(String.format("--halfopen-threads = %d", hopen_threads));
		log.println(String.format("--halfopen-rest = %d", hopen_rest));
		log.println(String.format("--to-basic = %d", toBasicRead));

		// init timeouts
		toCltReadFromApp = toBasicRead * 1000;
		toCltReadFromSvr = toBasicRead * 1000;
		toCltReadFromSvrSmall = Launcher.toSvrReadFromCltSmall;
		toCltConnectToSvr = Launcher.toBasicConnect;
		toCltReadFromDirect = toBasicRead * 1000;
		toCltConnectToDirect = Launcher.toBasicConnect;
		toSvrReadFromCltRest = hopen_rest * 1000;

		log.println(String.format("small connect timeout to sp server = %d", toCltConnectToSvr));

		byte[] bytes = passwordString.getBytes(StandardCharsets.UTF_8);
		System.arraycopy(bytes, 0, this.password, 0, bytes.length);

		nn_direct = new NextNode(NextNode.Type.DIRECT, Proxy.NO_PROXY);
		nn_ban = new NextNode(NextNode.Type.BAN, null);
		nn_proxy = new NextNode(NextNode.Type.PROXY, next_proxy);
		load_domain_nn_table();

		http2socks = new Http2socks(new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1", local_listen_port)),
				toBasicRead * 1000, log);

		// set SSL
		SSLContext context = SSLContext.getInstance("TLS");
		if (unsafeCert) {
			TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
				@Override
				public X509Certificate[] getAcceptedIssuers() {
					return new X509Certificate[0];
				}

				@Override
				public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
				}

				@Override
				public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
				}
			} };
			context.init(null, trustAllCerts, null);
		} else {
			context.init(null, null, null);
		}
		ssf = context.getSocketFactory();

		tunnelPool = new TunnelPool(server_ip, server_port);

		speedMeter = new SpeedMeter(1000 * 4, tunnelPool.halfTunnels, TunnelContext.allOngoings, this);

		ServerSocket ss = new ServerSocket(local_listen_port, 50, InetAddress.getByName(local_listen_ip));
		try {
			log.println("listened on port " + local_listen_port);
			// for local socket, use auto buf size
			while (true) {
				Socket s;
				try {
					s = ss.accept();
				} catch (SocketException e) {
					// accept will fail sometimes when closing UU
					// wait a moment then recreate serversocket
					e.printStackTrace(log);
					Thread.sleep(1000);
					ss.close();
					ss = new ServerSocket(local_listen_port, 50, InetAddress.getByName(local_listen_ip));
					continue;
				}
				// for local socket, use auto buf size
				// use source port as id
				int id = s.getPort();
				scmt.execAsync("recv_" + id + "_client", () -> recv_client(s));
			}
		} finally {
			ss.close();
		}
	}

	private void recv_client(Socket s) {
		try {
			s.setTcpNoDelay(true);
			s.setSoTimeout(toCltReadFromApp);

			PushbackInputStream is = new PushbackInputStream(s.getInputStream(), 1);
			OutputStream os = s.getOutputStream();

			// read first byte cuz we need to know which protocol the app is using
			int byte1 = is.read();
			if (byte1 == -1) {
//				log.println("error app closed connection without sending any data");
				Util.abortiveCloseSocket(s);
				return;
			}

			byte first_byte = (byte) byte1;
			if (first_byte == 5) {
				// socks5
				socks5(first_byte, is, os, s);
				return;
			} else if (first_byte == 4) {
				// socks4
				socks4(first_byte, is, os, s);
				return;
			} else if (first_byte == 0x43) {
				// 0x43 'C' http connect
				http_connect(first_byte, is, os, s);
				return;
			} else if (first_byte == 0x47 || first_byte == 0x50 || first_byte == 0x48) {
				// 0x47 'G' http get
				// 0x50 'P' http post/put
				// 0x48 'H' http head
				is.unread(first_byte);
				http_other(is, os, s);
				return;
			} else if (first_byte == 1 || first_byte == 3) {
				// ss
				ss_plain(first_byte, is, os, s);
				return;
			} else if (first_byte == 0x16) {
				// possible 0x16 for SSL/TLS
				log.println("error app is talking SSL/TLS, first byte: " + sctp.byte_to_string(first_byte));
				Util.abortiveCloseSocket(s);
				return;
			} else {
				log.println("error app is using unknown protocol, first byte: " + sctp.byte_to_string(first_byte));
				Util.abortiveCloseSocket(s);
				return;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void socks5(byte first_byte, InputStream is1, OutputStream os1, Socket sclient_s) {
		DataInputStream is;
		try {
			is = new DataInputStream(is1);
			int num_authe_methods = is.readUnsignedByte();
			// System.out.println("num_authe_methods " + num_authe_methods);
			ArrayList<Byte> client_methods = new ArrayList<>(num_authe_methods);
			for (int i = 0; i < num_authe_methods; i++) {
				byte authe_method = is.readByte();
				// System.out.println("authe_method " + sctp.byte_to_string(authe_method));
				client_methods.add(authe_method);
			}
			if (client_methods.indexOf((byte) 0) == -1) {
				throw new Exception("error client does not support '0' auth method");
			}
		} catch (Exception e) {
			log.println("error when read socks5 authn");
			e.printStackTrace(log);
			Util.abortiveCloseSocket(sclient_s);
			return;
		}

		// authn
		DataOutputStream os;
		byte[] buf;
		try {
			os = new DataOutputStream(os1);
			buf = new byte[2];
			buf[0] = 5; // reply socks version
			buf[1] = 0; // choose No authentication method
			os.write(buf);
			os.flush();
		} catch (Exception e) {
			log.println("error when write socks5 authn");
			e.printStackTrace(log);
			Util.abortiveCloseSocket(sclient_s);
			return;
		}

		// read client request
		InetSocketAddress dest_sockaddr;
		byte command_code;
		try {
			// socks version
			is.readByte();

			// recv command code
			command_code = is.readByte();

			// reserved byte
			is.readByte();

			// address type
			byte address_type = is.readByte();
			// System.out.println("address_type " + sctp.byte_to_string(address_type));

			InetAddress dest_addr = null;
			String dest_domain = null;

			if (address_type == 1) {
				// ipv4
				buf = new byte[4];
				is.readFully(buf);
				dest_addr = InetAddress.getByAddress(buf);
			} else if (address_type == 3) {
				// domain name
				int domain_length = is.readUnsignedByte();
				buf = new byte[domain_length];
				is.readFully(buf);
				dest_domain = sc.b2s(buf);
			} else if (address_type == 4) {
				// ipv6
				buf = new byte[16];
				is.readFully(buf);
				dest_addr = InetAddress.getByAddress(buf);
				// the reason that we can't do ipv6 is because we don't have ipv6 user.rule
				// things
				throw new Exception("error ipv6 address");
			} else {
				// unknown address_type
				throw new Exception("error unknown address type");
			}

			// port
			int dest_port = is.readUnsignedShort();

			if (dest_addr != null)
				dest_sockaddr = new InetSocketAddress(dest_addr, dest_port);
			else
				dest_sockaddr = InetSocketAddress.createUnresolved(dest_domain, dest_port);
		} catch (Exception e) {
			log.println("error when read socks5 dest addr");
			e.printStackTrace(log);
			Util.abortiveCloseSocket(sclient_s);
			return;
		}

		if (command_code == 1) {
			// if command_code is 0x01, tcp connect

			// now we connect next node
			SocketBundle cserver_sb = null;
			try {
				cserver_sb = create_connect_config_socket(dest_sockaddr, "socks5");
			} catch (Exception e) {
				e.printStackTrace(log);
			}
			if (cserver_sb == null) {
				// can't connect
				// X'04' Host unreachable
				socks5FinalReply(sclient_s, os, (byte) 0x04);
				return;
			}

			// reply ok
			buf = new byte[10];
			// reply socks version again
			buf[0] = 5;
			// reply status
			// X'00' succeeded
			buf[1] = 0;
			// reserved
			buf[2] = 0;
			// bind address data
			buf[3] = 1; // ipv4
			// buf[4~7] is ip 0.0.0.0
			// buf[8~9] is port 0
			try {
				os.write(buf);
				os.flush();
			} catch (Exception e) {
				log.println("error when write socks5 status");
				e.printStackTrace(log);
				Util.abortiveCloseSocket(sclient_s);
				return;
			}

			// transfer data
			handleConnection(cserver_sb.is, cserver_sb.os, is, os, dest_sockaddr.toString(), cserver_sb.socket,
					sclient_s);
			return;
		} else if (command_code == 2) {
			// if command_code is 0x02, tcp port binding
			log.println(String.format("rcv cmd code %d", command_code));
			// 0x07: command not supported / protocol error
			socks5FinalReply(sclient_s, os, (byte) 0x07);
			return;
		} else if (command_code == 3) {
			// if command_code is 0x03, udp associate
			log.println(String.format("rcv cmd code %d, dst addr %s", command_code, dest_sockaddr));

			// create udp socket
			DatagramSocket udpSocket;
			try {
				udpSocket = new DatagramSocket(new InetSocketAddress(InetAddress.getByName(local_listen_ip), 0));
			} catch (Exception e) {
				log.println("error when creating DatagramSocket");
				e.printStackTrace(log);
				Util.abortiveCloseSocket(sclient_s);
				return;
			}
			int udpPort = udpSocket.getLocalPort();

			// reply to client
			buf = new byte[10];
			// reply socks version again
			buf[0] = 5;
			// reply status
			// X'00' succeeded
			buf[1] = 0;
			// reserved
			buf[2] = 0;
			// bind address data
			buf[3] = 1; // ipv4
			// buf[4~7] is ip 0.0.0.0
			// buf[8~9] is port
			buf[8] = (byte) ((udpPort >>> 8) & 0xFF);
			buf[9] = (byte) ((udpPort >>> 0) & 0xFF);
			try {
				os.write(buf);
				os.flush();
			} catch (Exception e) {
				log.println("error when write socks5 status");
				e.printStackTrace(log);
				Util.abortiveCloseSocket(sclient_s);
				return;
			}

			handleConnectionUdp(udpSocket);
			return;
		} else {
			log.println("error command_code " + sctp.byte_to_string(command_code));
			Util.abortiveCloseSocket(sclient_s);
			return;
		}
	}

	/** also close socket */
	private void socks5FinalReply(Socket socket, DataOutputStream os, byte replyStatus) {
		byte[] buf = new byte[10];

		// reply socks version again
		buf[0] = 5;

		// reply status
		buf[1] = replyStatus;

		// reserved
		buf[2] = 0;

		// bind address data
		buf[3] = 1; // ipv4
		// buf[4~7] is ip 0.0.0.0
		// buf[8~9] is port 0

		try {
			os.write(buf);
			os.flush();
		} catch (Exception e) {
			log.println("error when write socks5 status");
			e.printStackTrace(log);
			Util.abortiveCloseSocket(socket);
			return;
		}

		Util.closeQuietly(socket);
	}

	private void http_connect(byte first_byte, InputStream is, OutputStream os, Socket sclient_s) {
		InetSocketAddress dest_sockaddr;
		// connect to nn
		SocketBundle cserver_sb = null;
		try {
			byte[] headers_buf = new byte[1024 * 1024];
			int pos = 0;
			headers_buf[pos++] = first_byte;
			while (true) {
				int b = is.read();
				if (b == -1) {
					throw new Exception("error incomplete http headers");
				}
				headers_buf[pos++] = (byte) b;
				if (pos >= 4 && headers_buf[pos - 4] == '\r' && headers_buf[pos - 3] == '\n'
						&& headers_buf[pos - 2] == '\r' && headers_buf[pos - 1] == '\n') {
					break;
				}
			}
			String headers = sc.b2s(headers_buf, 0, pos);
			String[] header_array = headers.split("\r\n");
			Matcher matcher = httpconnect_regex.matcher(header_array[0]);
			if (!matcher.find()) {
				log.println(headers);
				throw new Exception("error no host or not http connect");
			}
			String dest_host = matcher.group(1);
			int port = Integer.parseInt(matcher.group(2));
			matcher = ip_regex.matcher(dest_host);
			if (matcher.matches()) {
				dest_sockaddr = new InetSocketAddress(InetAddress.getByName(dest_host), port);
			} else {
				dest_sockaddr = InetSocketAddress.createUnresolved(dest_host, port);
			}

			cserver_sb = create_connect_config_socket(dest_sockaddr, "connect");
			if (cserver_sb == null) {
				// reply http 500
				os.write(httpconnect_500response);
				os.flush();
				Util.orderlyCloseSocket(sclient_s);
				return;
			}
			// reply http 200 ok
			os.write(httpconnect_okresponse);
			os.flush();

			// transfer data
			handleConnection(cserver_sb.is, cserver_sb.os, is, os, dest_sockaddr.toString(), cserver_sb.socket,
					sclient_s);
		} catch (Exception e) {
			e.printStackTrace(log);
			Util.abortiveCloseSocket(sclient_s);
			if (cserver_sb != null)
				Util.abortiveCloseSocket(cserver_sb.socket);
		}
	}

	private void ss_plain(byte first_byte, InputStream is1, OutputStream os1, Socket sclient_s) {
		DataInputStream is;
		is = new DataInputStream(is1);
		byte[] buf;

		InetSocketAddress dest_sockaddr;
		try {
			// address type
			byte address_type = first_byte;
			// System.out.println("address_type " + sctp.byte_to_string(address_type));

			InetAddress dest_addr = null;
			String dest_domain = null;

			if (address_type == 1) {
				// ipv4
				buf = new byte[4];
				is.readFully(buf);
				dest_addr = InetAddress.getByAddress(buf);
			} else if (address_type == 3) {
				// domain name
				int domain_length = is.readUnsignedByte();
				buf = new byte[domain_length];
				is.readFully(buf);
				dest_domain = sc.b2s(buf);
			} else if (address_type == 4) {
				// ipv6
				buf = new byte[16];
				is.readFully(buf);
				dest_addr = InetAddress.getByAddress(buf);
				throw new Exception("error ipv6 address");
			} else {
				// unknown address_type
				throw new Exception("error unknown address type");
			}

			// port
			int dest_port = is.readUnsignedShort();

			if (dest_addr != null)
				dest_sockaddr = new InetSocketAddress(dest_addr, dest_port);
			else
				dest_sockaddr = InetSocketAddress.createUnresolved(dest_domain, dest_port);
		} catch (Exception e) {
			log.println("error when read ss dest addr");
			e.printStackTrace(log);
			Util.abortiveCloseSocket(sclient_s);
			return;
		}

		// now we connect next node
		SocketBundle cserver_sb = null;
		try {
			cserver_sb = create_connect_config_socket(dest_sockaddr, "ss");
		} catch (Exception e) {
			e.printStackTrace(log);
		}
		if (cserver_sb == null) {
			// can't connect
			Util.abortiveCloseSocket(sclient_s);
			return;
		}

		// transfer data
		handleConnection(cserver_sb.is, cserver_sb.os, is, os1, dest_sockaddr.toString(), cserver_sb.socket, sclient_s);
	}

	private void socks4(byte first_byte, InputStream is1, OutputStream os1, Socket sclient_s) throws Exception {
		DataInputStream is = new DataInputStream(is1);

		// recv command code
		byte command_code = is.readByte();
		if (command_code != 1)
			log.println("error command_code " + sctp.byte_to_string(command_code));

		// port
		int dest_port = is.readUnsignedShort();

		// ipv4
		InetAddress dest_addr = null;
		byte[] buf = new byte[4];
		is.readFully(buf);
		if (buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] != 0) {

		} else {
			dest_addr = InetAddress.getByAddress(buf);
		}

		buf = new byte[1024 * 8];
		int pos = 0;
		while (true) {
			int b = is.read();
			if (b == 0)
				break;
			else if (b == -1)
				throw new Exception("error incomplete socks4 headers");
			buf[pos++] = (byte) b;
		}
		String userid = sc.b2s(buf, 0, pos);
		log.println("socks4a userid " + userid);

		// domain
		String dest_domain = null;
		if (dest_addr == null) {
			byte[] buf1 = new byte[1024 * 8];
			int pos1 = 0;
			while (true) {
				int b = is.read();
				if (b == -1) {
					throw new Exception("error incomplete socks4 headers 2");
				}
				if (b == 0) {
					break;
				}
				buf1[pos1++] = (byte) b;
			}
			dest_domain = sc.b2s(buf1, 0, pos1);
		}

		InetSocketAddress dest_sockaddr;
		if (dest_addr != null)
			dest_sockaddr = new InetSocketAddress(dest_addr, dest_port);
		else
			dest_sockaddr = InetSocketAddress.createUnresolved(dest_domain, dest_port);

		log.println("socks4 dest_sockaddr " + dest_sockaddr);

		// connect to nn
		/** client socket which connects to server */
		SocketBundle cserver_sb = create_connect_config_socket(dest_sockaddr, "socks4");
		if (cserver_sb == null) {
			buf = new byte[8];
			// reply null byte
			buf[0] = 0;

			// reply status(fail)
			buf[1] = 0x5b;

			// 6 bytes non sense
			buf[3] = 1;
			os1.write(buf);
			os1.flush();
			Util.orderlyCloseSocket(sclient_s);
			return;
		}
		buf = new byte[8];
		// reply null byte
		buf[0] = 0;

		// reply status(ok)
		buf[1] = 0x5a;

		// 6 bytes non sense
		buf[3] = 1;
		os1.write(buf);
		os1.flush();

		// transfer data
		handleConnection(cserver_sb.is, cserver_sb.os, is1, os1, dest_sockaddr.toString(), cserver_sb.socket,
				sclient_s);
	}

	private void handleConnectionUdp(DatagramSocket udpSocket) {
//		Thread handleConn2 = scmt.execAsync("multi-thread-handle-conn-udp2",
//				() -> handleConnectionUdp2(null, null, udpSocket));

		// client to server loop
		byte[] buf = new byte[UDP_PKT_SIZE];
		DatagramPacket p = new DatagramPacket(buf, buf.length);
		while (true) {
			p.setData(buf);
			try {
				udpSocket.receive(p);
			} catch (IOException e) {
				e.printStackTrace(log);
				udpSocket.close();
				return;
			}
			log.println(String.format("udp recv len %d", p.getLength()));

			// buf[0~1] reserved
			// buf[2] fragment number
			if (buf[2] != 0) {
				// not supported, silent drop
				continue;
			}
			// buf[3] address type
			byte address_type = buf[3];
			// parse address
			InetSocketAddress dest_sockaddr;
			int offset = 4;
			try {
				InetAddress dest_addr = null;
				String dest_domain = null;
				if (address_type == 1) {
					// ipv4
					byte[] buf2 = new byte[4];
					System.arraycopy(buf, 4, buf2, 0, 4);
					dest_addr = InetAddress.getByAddress(buf2);
					offset += 4;
				} else if (address_type == 3) {
					// domain name
					int domain_length = buf[4];
					byte[] buf2 = new byte[domain_length];
					System.arraycopy(buf, 5, buf2, 0, domain_length);
					dest_domain = sc.b2s(buf);
					offset += 1 + domain_length;
				} else if (address_type == 4) {
					// ipv6
					byte[] buf2 = new byte[16];
					System.arraycopy(buf, 4, buf2, 0, 16);
					dest_addr = InetAddress.getByAddress(buf);
					offset += 16;
					// the reason that we can't do ipv6 is because we don't have ipv6 user.rule
					// things
					throw new Exception("error ipv6 address");
				} else {
					// unknown address_type
					throw new Exception("error unknown address type");
				}

				int dest_port = sctp.bytes_to_ushort(buf, offset);
				offset += 2;

				if (dest_addr != null)
					dest_sockaddr = new InetSocketAddress(dest_addr, dest_port);
				else
					dest_sockaddr = InetSocketAddress.createUnresolved(dest_domain, dest_port);
			} catch (Exception e) {
				log.println("error when read udp socks5 dest addr");
				e.printStackTrace(log);
				udpSocket.close();
				return;
			}

			//
			log.println(String.format("dst addr %s", dest_sockaddr, p.getLength() - offset));

			// find nextnode
			// if proxy -> poll tunnel -> snd/rcv
			// if direct -> direct socket -> snd/rcv
		}
	}

	private static InetSocketAddress readSocks5Addr(DataInput is) throws Exception {
		byte address_type = is.readByte();
		InetAddress dest_addr = null;
		String dest_domain = null;
		byte[] buf;

		if (address_type == 1) {
			// ipv4
			buf = new byte[4];
			is.readFully(buf);
			dest_addr = InetAddress.getByAddress(buf);
		} else if (address_type == 3) {
			// domain name
			int domain_length = is.readUnsignedByte();
			buf = new byte[domain_length];
			is.readFully(buf);
			dest_domain = sc.b2s(buf);
		} else if (address_type == 4) {
			// ipv6
			buf = new byte[16];
			is.readFully(buf);
			dest_addr = InetAddress.getByAddress(buf);
		} else {
			// unknown address_type
			throw new Exception("error unknown address type");
		}

		// port
		int dest_port = is.readUnsignedShort();

		InetSocketAddress dest_sockaddr;
		if (dest_addr != null)
			dest_sockaddr = new InetSocketAddress(dest_addr, dest_port);
		else
			dest_sockaddr = InetSocketAddress.createUnresolved(dest_domain, dest_port);
		return dest_sockaddr;
	}

	private static int writeSocks5Addr(InetSocketAddress addr, byte[] buf, int offset) {
		return 0;
	}

	/** read from server, write to client */
	private void handleConnectionUdp2(TunnelContext contxt, InputStream cserver_is_, DatagramSocket socks5_udp_socket) {
		DataInputStream cserver_is = new DataInputStream(new BufferedInputStream(cserver_is_, BUF_SIZE));
		InetSocketAddress packetDstAddr;
		byte[] databuf = new byte[UDP_PKT_SIZE];
		int dataLen;
		byte[] socks5udpbuf = new byte[UDP_PKT_SIZE];
		DatagramPacket p = new DatagramPacket(socks5udpbuf, socks5udpbuf.length);

		while (true) {
			// read one packet
			try {
				packetDstAddr = readSocks5Addr(cserver_is);
				dataLen = cserver_is.readInt();
				cserver_is.readFully(databuf, 0, dataLen);
			} catch (SocketTimeoutException e) {
				// timeout cuz read no data
				// if we are writing, then continue
				// if we are not writing, just RST close connection
				if (sct.time_ms() - contxt.lastWriteToServer < toCltReadFromSvr)
					continue;
				else {
					if (contxt.closing) {
					} else {
						// so the keep-alive of app-dest is longer.
						// but there's nothing we can do about it,
						// cuz NAT may timeout.
//						log.println(String.format("%s cserver read timeout %s", sct.datetime(), contxt.toString()));
						contxt.isBroken = true;
					}
					break;
				}
			} catch (Throwable e) {
				if (contxt.closing) {
				} else {
					if (e.getMessage().equals("Connection reset")) {
						// could be many reasons but i don't care
					} else {
						log.println(String.format("%s cserver read exception %s (%s)", sct.datetime(),
								contxt.toString(), e));
					}
					contxt.isBroken = true;
				}
				break;
			}

			int n = 0;
			// normal EOF
			if (n == -1) {
				if (contxt.closing)
					break;
				// normal eof from server, no need to log
//				log.println(String.format("%s cserver read eof %s", sct.datetime(), contxt.toString()));
				break;
			}

			// RSV
			socks5udpbuf[0] = 0;
			socks5udpbuf[1] = 0;
			// FRAG
			socks5udpbuf[2] = 0;
			// socks5addr
			n = 3 + writeSocks5Addr(packetDstAddr, socks5udpbuf, 3);
			// data
			System.arraycopy(databuf, 0, socks5udpbuf, n, dataLen);
			n += dataLen;

			speedMeter.countRecv(n);

			// write some bytes
			try {
				p.setData(socks5udpbuf, 0, n);
				socks5_udp_socket.send(p);
			} catch (Throwable e) {
				if (contxt.closing)
					break;
				log.println(String.format("%s sclient write exception %s", sct.datetime(), contxt.toString()));
				e.printStackTrace(log);
				contxt.isBroken = true;
				break;
			}
			contxt.lastWriteToClient = sct.time_ms();
		}

		// shutdown connections
		synchronized (contxt) {
			if (!contxt.closing) {
				contxt.closing = true;
				if (contxt.isBroken) {
					Util.abortiveCloseSocket(contxt.cserver_s);
					Util.abortiveCloseSocket(contxt.sclient_s);
				} else {
					Util.orderlyCloseSocket(contxt.cserver_s);
					Util.orderlyCloseSocket(contxt.sclient_s);
				}
			}
		}
	}

	// blockingly mutual transfer 2 sockets, make sure closing before return
	private void handleConnection(InputStream cserver_is, OutputStream cserver_os, InputStream sclient_is,
			OutputStream sclient_os, String dest_name, Socket cserver_s, Socket sclient_s) {
		TunnelContext contxt = new TunnelContext(dest_name, cserver_s, sclient_s);

		Thread handleConn2 = scmt.execAsync("multi-thread-handle-conn2",
				() -> handleConnection2(contxt, cserver_is, sclient_os));

		// client to server loop
		byte[] buf = new byte[BUF_SIZE];
		while (true) {
			// read some bytes
			int n;
			try {
				n = sclient_is.read(buf);
			} catch (SocketTimeoutException e) {
				// timeout cuz read no data
				// if we are writing, then continue
				// if we are not writing, tunnel broken
				if (sct.time_ms() - contxt.lastWriteToClient < toCltReadFromApp)
					continue;
				else {
					if (contxt.closing)
						break;
					log.println(String.format("%s sclient read timeout %s", sct.datetime(), contxt.toString()));
					contxt.isBroken = true;
					break;
				}
			} catch (Throwable e) {
				if (contxt.closing) {
				} else {
					if (e instanceof SocketException && e.getMessage().equals("Connection reset")) {
						// it's just client abortively close connection
					} else {
						log.println(String.format("%s sclient read exception %s (%s)", sct.datetime(),
								contxt.toString(), e));
					}
					contxt.isBroken = true;
				}
				break;
			}

			// normal EOF
			if (n == -1) {
				if (contxt.closing)
					break;
				// normal eof from client, no need to log
//				log.println(String.format("%s sclient read eof %s", sct.datetime(), contxt.toString()));
				break;
			}

			// write some bytes
			try {
				cserver_os.write(buf, 0, n);
			} catch (Throwable e) {
				if (contxt.closing) {
				} else {
					log.println(String.format("%s cserver write exception %s", sct.datetime(), contxt.toString()));
					e.printStackTrace(log);
					contxt.isBroken = true;
				}
				break;
			}
			contxt.lastWriteToServer = sct.time_ms();
			speedMeter.countSend(n);
		}

		// shutdown connections
		synchronized (contxt) {
			if (!contxt.closing) {
				contxt.closing = true;
				if (contxt.isBroken) {
					Util.abortiveCloseSocket(contxt.cserver_s);
					Util.abortiveCloseSocket(contxt.sclient_s);
				} else {
					Util.orderlyCloseSocket(contxt.cserver_s);
					Util.orderlyCloseSocket(contxt.sclient_s);
				}
			}
		}

		// make sure another thread is ended
		try {
			handleConn2.join(1000 * 10);
		} catch (InterruptedException e) {
			e.printStackTrace(log);
		}
		if (handleConn2.isAlive()) {
			log.println(handleConn2.getName() + " still alive");
		}
	}

	/** read from server, write to client */
	private void handleConnection2(TunnelContext contxt, InputStream cserver_is, OutputStream sclient_os) {
		byte[] buf = new byte[BUF_SIZE];
		while (true) {
			// read some bytes
			int n;
			try {
				n = cserver_is.read(buf);
			} catch (SocketTimeoutException e) {
				// timeout cuz read no data
				// if we are writing, then continue
				// if we are not writing, just RST close connection
				if (sct.time_ms() - contxt.lastWriteToServer < toCltReadFromSvr)
					continue;
				else {
					if (contxt.closing) {
					} else {
						// so the keep-alive of app-dest is longer.
						// but there's nothing we can do about it,
						// cuz NAT may timeout.
//						log.println(String.format("%s cserver read timeout %s", sct.datetime(), contxt.toString()));
						contxt.isBroken = true;
					}
					break;
				}
			} catch (Throwable e) {
				if (contxt.closing) {
				} else {
					if (e.getMessage().equals("Connection reset")) {
						// could be many reasons but i don't care
					} else {
						log.println(String.format("%s cserver read exception %s (%s)", sct.datetime(),
								contxt.toString(), e));
					}
					contxt.isBroken = true;
				}
				break;
			}

			// normal EOF
			if (n == -1) {
				if (contxt.closing)
					break;
				// normal eof from server, no need to log
//				log.println(String.format("%s cserver read eof %s", sct.datetime(), contxt.toString()));
				break;
			}

			speedMeter.countRecv(n);

			// write some bytes
			try {
				sclient_os.write(buf, 0, n);
			} catch (Throwable e) {
				if (contxt.closing)
					break;
				log.println(String.format("%s sclient write exception %s", sct.datetime(), contxt.toString()));
				e.printStackTrace(log);
				contxt.isBroken = true;
				break;
			}
			contxt.lastWriteToClient = sct.time_ms();

			// debug show socket buf size
			if (debug) {
				try {
					String local = contxt.cserver_s.getLocalSocketAddress().toString();
					int rbufsz = contxt.cserver_s.getReceiveBufferSize();
					int sbufsz = contxt.cserver_s.getSendBufferSize();
					System.out.println(String.format("%s, rbufsz: %d, sbufsz: %d", local, rbufsz, sbufsz));
				} catch (SocketException e) {
					e.printStackTrace();
				}
			}
		}

		// shutdown connections
		synchronized (contxt) {
			if (!contxt.closing) {
				contxt.closing = true;
				if (contxt.isBroken) {
					Util.abortiveCloseSocket(contxt.cserver_s);
					Util.abortiveCloseSocket(contxt.sclient_s);
				} else {
					Util.orderlyCloseSocket(contxt.cserver_s);
					Util.orderlyCloseSocket(contxt.sclient_s);
				}
			}
		}
	}

	public static class TunnelContext {
		public volatile long lastWriteToClient = 0;
		public volatile long lastWriteToServer = 0;
		public final String dest_name;
		/** client - server */
		public Socket cserver_s;
		/** app - client */
		public Socket sclient_s;
		public boolean isBroken = false;
		public boolean closing = false;
		private WeakReference<TunnelContext> weakRef;

		public TunnelContext(String dest_name, Socket cserver_s, Socket sclient_s) {
			this.dest_name = dest_name;
			this.cserver_s = cserver_s;
			this.sclient_s = sclient_s;
			weakRef = new WeakReference<>(this);
			allOngoings.add(weakRef);
		}

		@Override
		public String toString() {
			return String.format("%s", dest_name);
		}

		private static Set<WeakReference<TunnelContext>> allOngoings = ConcurrentHashMap.newKeySet();
	}

	private void http_other(InputStream is, OutputStream os, Socket socket) {
		http2socks.handleConnection(is, os, socket);
	}

	/**
	 * return null means connection refused, or connect timed out, or can't resolve hostname, or it's loopback
	 * 
	 * @param client_protocol
	 */
	private SocketBundle create_connect_config_socket(InetSocketAddress dest_sockaddr, String client_protocol)
			throws Exception {
		int port = dest_sockaddr.getPort();

		NextNode nextNode;
		if (dest_sockaddr.getAddress() != null && dest_sockaddr.getAddress().isLoopbackAddress()) {
			// if it's loopback address.
			// this will only check ip addr(resolved).
			// for unresolved addr, check after resolved.
			// if it's direct, check at direct_create_config_connect_socket().
			// if it's proxy, check at server.
			String hostString = dest_sockaddr.getAddress().getHostAddress();
			nextNode = nn_direct;
			log.println(String.format("%s %-7s: %-6s <- loopback <- %s:%d", sct.datetime(), client_protocol, nextNode,
					hostString, port));
		} else if (dest_sockaddr.isUnresolved()) {
			String hostString = dest_sockaddr.getHostString();
			if (ip_regex.matcher(hostString).matches()) {
				// is an ip string
				long ip = Util.ip2long(hostString);
				IpRange ipRange = ip_to_nn.floorEntry(ip).getValue();
				if (ip > ipRange.end) {
					nextNode = nn_proxy;
					log.println(String.format("%s %-7s: %-6s <- default <- %s:%d", sct.datetime(), client_protocol,
							nextNode, hostString, port));
				} else {
					nextNode = ipRange.nextnode;
					log.println(String.format("%s %-7s: %-6s <- %s ~ %s <- %s:%d", sct.datetime(), client_protocol,
							nextNode, Util.long2ip(ipRange.begin), Util.long2ip(ipRange.end), hostString, port));
				}
			} else {
				// is a domain string
				nextNode = domain_to_nn.get(hostString);
				if (nextNode != null) {
					log.println(String.format("%s %-7s: %-6s <- %s:%d", sct.datetime(), client_protocol, nextNode,
							hostString, port));
				} else {
					String intermediate = "." + hostString;
					while (true) {
						nextNode = domain_to_nn.get(intermediate);
						if (nextNode != null)
							break;
						int indexOf = intermediate.indexOf('.', 1);
						if (indexOf == -1)
							break;
						intermediate = intermediate.substring(indexOf);
					}
					if (nextNode == null) {
						nextNode = nn_proxy;
						log.println(String.format("%s %-7s: %-6s <- default <- %s:%d", sct.datetime(), client_protocol,
								nextNode, hostString, port));
					} else {
						log.println(String.format("%s %-7s: %-6s <- %s <- %s:%d", sct.datetime(), client_protocol,
								nextNode, intermediate, hostString, port));
					}
				}
			}
		} else {
			// is an ip string
			String hostString = dest_sockaddr.getAddress().getHostAddress();
			long ip = Util.ip2long(dest_sockaddr.getAddress());
			IpRange ipRange = ip_to_nn.floorEntry(ip).getValue();
			if (ip > ipRange.end) {
				nextNode = nn_proxy;
				log.println(String.format("%s %-7s: %-6s <- default <- %s:%d", sct.datetime(), client_protocol,
						nextNode, hostString, port));
			} else {
				nextNode = ipRange.nextnode;
				log.println(String.format("%s %-7s: %-6s <- %s ~ %s <- %s:%d", sct.datetime(), client_protocol,
						nextNode, Util.long2ip(ipRange.begin), Util.long2ip(ipRange.end), hostString, port));
			}
		}

		if (nextNode.type == NextNode.Type.BAN) {
			return null;
		} else if (nextNode.type == NextNode.Type.DIRECT) {
			// dns resolve
			InetAddress dest_addr = null;
			try {
				// if it's already resolved, will simply return textual ip
				dest_addr = InetAddress.getByName(dest_sockaddr.getHostString());
			} catch (UnknownHostException e) {
				// can't resolve name
				return null;
			}
			dest_sockaddr = new InetSocketAddress(dest_addr, dest_sockaddr.getPort());
			Socket raw = direct_create_config_connect_socket(dest_sockaddr, client_protocol);
			if (raw == null)
				return null;
			return new SocketBundle(raw, raw.getInputStream(), new DataOutputStream(raw.getOutputStream()));
		} else if (nextNode.type == NextNode.Type.PROXY) {
			// connect through sp server
			SocketBundle tunnel = tunnelPool.pollTunnel(dest_sockaddr.getHostString(), dest_sockaddr.getPort());
			if (tunnel == null) {
				log.println(sct.datetime() + " use tunnel out pool");
				return create_tunnel(server_ip, server_port, ssf, password, dest_sockaddr.getHostString(),
						dest_sockaddr.getPort());
			} else {
				// use tunnel from pool is just normal
				// no need to log it
				// log.println(sct.datetime() + " use tunnel from pool");
				return tunnel;
			}
		} else
			throw new RuntimeException("impossible");
	}

	private SocketBundle create_tunnel(String server_hostname, int server_port, SSLSocketFactory ssf, byte[] password,
			String dest_hostname, int dest_port) {
		SocketBundle half_tunnel = create_half_tunnel(server_hostname, server_port, ssf, password);
		if (half_tunnel == null)
			return null;

		return create_full_tunnel(half_tunnel, dest_hostname, dest_port);
	}

	private SocketBundle create_half_tunnel(String server_hostname, int server_port, SSLSocketFactory ssf,
			byte[] password) {
		try {
			// create sslsocket
			SSLSocket cserver_s = (SSLSocket) ssf.createSocket();

			// config sslsocket
			cserver_s.setEnabledProtocols(Launcher.TLS_PROTOCOLS);
			cserver_s.setEnabledCipherSuites(Launcher.TLS_CIPHERS);
			// use small timeout first
			cserver_s.setSoTimeout(toCltReadFromSvrSmall);
			cserver_s.setTcpNoDelay(true);
			if (rcvbuf_size > 0)
				cserver_s.setReceiveBufferSize(rcvbuf_size);
			if (sndbuf_size > 0)
				cserver_s.setSendBufferSize(sndbuf_size);

			// connect to sp server
			try {
				cserver_s.connect(new InetSocketAddress(server_hostname, server_port), toCltConnectToSvr);
			} catch (Throwable e) {
				log.println(sct.datetime() + " error when connect sp server " + e);
				Util.abortiveCloseSocket(cserver_s);
				return null;
			}

			try {
				cserver_s.startHandshake();
			} catch (IOException e) {
				log.println(sct.datetime() + " error when start tls handshake");
				Util.abortiveCloseSocket(cserver_s);
				return null;
			}

			// log.println(cserver_s.getSession().getCipherSuite());

			InputStream raw_is = cserver_s.getInputStream();
			OutputStream raw_os = cserver_s.getOutputStream();
			DataInputStream is = new DataInputStream(raw_is);
			@SuppressWarnings("resource")
			DataOutputStream os = new DataOutputStream(new BufferedOutputStream(raw_os, 1024 * 2));
			// use 2k buffer so that we only send to network when flush()

			// authn
			try {
				os.write(password);
			} catch (Exception e) {
				log.println(sct.datetime() + " error when send pswd " + e);
				Util.abortiveCloseSocket(cserver_s);
				return null;
			}

			// random stuff hello
			try {
				int len = rand.nextInt(500) + 90;
				String hellostr = RandomStringUtils.randomAlphanumeric(len);
				os.writeUTF(hellostr);
			} catch (Exception e) {
				log.println(sct.datetime() + " error when send hello " + e);
				Util.abortiveCloseSocket(cserver_s);
				return null;
			}

			// send rest timeout
			try {
				os.writeInt(toSvrReadFromCltRest);
				os.flush();
			} catch (Exception e) {
				log.println(sct.datetime() + " error when send timeout " + e);
				Util.abortiveCloseSocket(cserver_s);
				return null;
			}

			// get server error code
			byte ecode;
			try {
				ecode = is.readByte();
			} catch (Exception e) {
				log.println(sct.datetime() + " error when read svr err code " + e);
				Util.abortiveCloseSocket(cserver_s);
				return null;
			}
			if (ecode != 0) {
				log.println(sct.datetime() + " server err code " + ecode);
				Util.orderlyCloseSocket(cserver_s);
				return null;
			}

			SocketBundle sb = new SocketBundle(cserver_s, raw_is, raw_os);
			sb.expireTime = System.currentTimeMillis() + toSvrReadFromCltRest - 10000;
			sb.nextKeepAliveTime = System.currentTimeMillis() + hopen_keepalive * 1000;
			return sb;
		} catch (Throwable e) {
			log.println("there shouldn't be any exception here");
			e.printStackTrace(log);
			return null;
		}
	}

	private SocketBundle create_full_tunnel(SocketBundle sb, String dest_hostname, int dest_port) {
		try {
			Socket cserver_s = sb.socket;
			// DataInputStream is = new DataInputStream(sb.is);
			DataOutputStream os = new DataOutputStream(new BufferedOutputStream(sb.os, 1024));
			// use buffer so that we only send to network when flush()

			// send opcode and dest info
			try {
				os.writeInt(Launcher.OPCODE_TCP);
				os.writeUTF(dest_hostname);
				os.writeShort(dest_port);
				os.flush();
			} catch (Exception e) {
				log.println(sct.datetime() + " error when send dest info " + e);
				Util.abortiveCloseSocket(cserver_s);
				return null;
			}

			// restore to normal timeout
			cserver_s.setSoTimeout(toCltReadFromSvr);

			return sb;
		} catch (Throwable e) {
			log.println("there shouldn't be any exception here");
			e.printStackTrace(log);
			return null;
		}
	}

	private SocketBundle create_full_tunnel_udp(SocketBundle sb, String dest_hostname, int dest_port) {
		try {
			Socket cserver_s = sb.socket;
			// DataInputStream is = new DataInputStream(sb.is);
			DataOutputStream os = new DataOutputStream(new BufferedOutputStream(sb.os, 1024));
			// use buffer so that we only send to network when flush()

			// send opcode and dest info
			try {
				os.writeInt(Launcher.OPCODE_UDP);
				os.flush();
			} catch (Exception e) {
				log.println(sct.datetime() + " error when send opcode " + e);
				Util.abortiveCloseSocket(cserver_s);
				return null;
			}

			// restore to normal timeout
			cserver_s.setSoTimeout(toCltReadFromSvr);

			return sb;
		} catch (Throwable e) {
			log.println("there shouldn't be any exception here");
			e.printStackTrace(log);
			return null;
		}
	}

	private class TunnelPool {

		private BlockingQueue<SocketBundle> halfTunnels = new ArrayBlockingQueue<>(hopen_max * 2);
		private String server_hostname;
		private int server_port;
		private Object queueHeadLock = new Object();

		public TunnelPool(String server_hostname, int server_port) {
			this.server_hostname = server_hostname;
			this.server_port = server_port;
			for (int i = 0; i < hopen_threads; i++) {
				scmt.execAsync("tunnel-pool-connect", this::connect);
			}
			scmt.execAsync("tunnel-pool-cleaner", this::cleaner);
		}

		private void connect() {
			while (true) {
				if (halfTunnels.size() >= hopen_max) {
					try {
						Thread.sleep(RandomUtils.nextInt(1000, 2000));
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
					continue;
				}

				SocketBundle half_tunnel = create_half_tunnel(server_hostname, server_port, ssf, password);
				if (half_tunnel != null) {
					try {
						halfTunnels.put(half_tunnel);
						// log.println(sct.datetime() + " new half tunnel to pool " +
						// halfTunnels.size());
					} catch (InterruptedException e) {
						e.printStackTrace(log);
					}
				} else {
					// can't connect tunnel
					try {
						Thread.sleep(RandomUtils.nextInt(2000, 5000));
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
					continue;
				}
			}
		}

		private void cleaner() {
			while (true) {
				SocketBundle sb;

				synchronized (queueHeadLock) {
					sb = halfTunnels.peek();
					if (sb == null) {
						// empty, do nothing
					} else if (System.currentTimeMillis() > sb.nextKeepAliveTime) {
						// need keep-alive, remove it then keep-alive it then add it back
						halfTunnels.poll();
					} else {
						// queue head is normal, do nothing to it
						sb = null;
					}
				}

				if (sendKeepAlive(sb)) {
					// keep-alive successful
					try {
						halfTunnels.put(sb);
					} catch (InterruptedException e) {
						// should be impossible
						e.printStackTrace(log);
					}
				} else {
					// keep-alive failed
					Util.abortiveCloseSocket(sb.socket);
				}

				try {
					Thread.sleep(1000);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
		}

		/** return true if ok and update expireTime, return false then sb should be considered broken */
		private boolean sendKeepAlive(SocketBundle sb) {
			DataInputStream is = new DataInputStream(sb.is);
			DataOutputStream os = new DataOutputStream(new BufferedOutputStream(sb.os, 1024));

			try {
				os.writeInt(Launcher.OPCODE_KEEPALIVE);
				os.flush();
			} catch (Exception e) {
				log.println(sct.datetime() + " error when send keep-alive");
				return false;
			}

			try {
				if (is.readInt() != Launcher.OPCODE_KEEPALIVE)
					throw new Exception("keep-alive reply is wrong");
			} catch (Exception e) {
				log.println(sct.datetime() + " error when send keep-alive");
				return false;
			}

			sb.expireTime = System.currentTimeMillis() + toSvrReadFromCltRest - 10000;
			sb.nextKeepAliveTime = System.currentTimeMillis() + hopen_keepalive * 1000;
			return true;
		}

		public SocketBundle pollTunnel(String dest_hostname, int dest_port) throws InterruptedException {
			SocketBundle half_tunnel;
			synchronized (queueHeadLock) {
				half_tunnel = halfTunnels.poll();
			}
			if (half_tunnel == null)
				return null;
			return create_full_tunnel(half_tunnel, dest_hostname, dest_port);
		}

		public SocketBundle pollTunnelUdp(String dest_hostname, int dest_port) throws InterruptedException {
			SocketBundle half_tunnel;
			synchronized (queueHeadLock) {
				half_tunnel = halfTunnels.poll();
			}
			if (half_tunnel == null)
				return null;
			return create_full_tunnel_udp(half_tunnel, dest_hostname, dest_port);
		}
	}

	/**
	 * return null means connection refused, or connect timed out
	 */
	private Socket direct_create_config_connect_socket(InetSocketAddress dest_sockaddr, String protocolFromApp)
			throws IOException {
		Socket s = new Socket(Proxy.NO_PROXY);
		s.setTcpNoDelay(true);
		s.setSoTimeout(toCltReadFromDirect);
		if (rcvbuf_size > 0)
			s.setReceiveBufferSize(rcvbuf_size);
		if (sndbuf_size > 0)
			s.setSendBufferSize(sndbuf_size);

		try {
			s.connect(dest_sockaddr, toCltConnectToDirect);
		} catch (ConnectException e) {
			if (e.getMessage().equals("Connection refused: connect")
					|| e.getMessage().equals("Connection timed out: connect"))
				return null;
			else
				throw e;
		} catch (SocketTimeoutException e) {
			if (e.getMessage().equals("connect timed out"))
				return null;
			else
				throw e;
		}
		return s;
	}

	private void load_domain_nn_table() throws Exception {
		domain_to_nn = new HashMap<>();
		ip_to_nn = new TreeMap<>();

		InputStream uris;
		if (userRuleStream == null) {
			uris = new FileInputStream("user.rule");
		} else {
			uris = userRuleStream;
		}

		ArrayList<String> lines = new ArrayList<>();
		try (BOMInputStream is = BOMInputStream.builder().setInputStream(uris).get()) {
			List<String> lines1 = IOUtils.readLines(is, sc.utf8);
			lines.addAll(lines1);
		}
		if (local_rule != null) {
			try (BOMInputStream is = BOMInputStream.builder().setInputStream(new FileInputStream(local_rule)).get()) {
				List<String> lines2 = IOUtils.readLines(is, sc.utf8);
				lines.addAll(lines2);
			}
		}

		for (String line : lines) {
			line = line.trim();
			if (line.isEmpty())
				continue;
			if (line.startsWith("#"))
				continue;
			String[] segments = line.split(" ");
			if (ip_regex.matcher(segments[0]).matches()) {
				// ip
				if (segments.length != 3)
					throw new Exception("nn_table bad line " + line);
				if (!ip_regex.matcher(segments[1]).matches())
					throw new Exception("nn_table bad line " + line);
				NextNode target;
				if (segments[2].equals("direct"))
					target = nn_direct;
				else if (segments[2].equals("reject"))
					target = nn_ban;
				else if (segments[2].equals("proxy"))
					target = nn_proxy;
				else
					throw new Exception("nn_table bad line " + line);
				long begin = Util.ip2long(segments[0]);
				long end = Util.ip2long(segments[1]);
				ip_to_nn.put(begin, new IpRange(begin, end, target));
				continue;
			}
			// domain
			if (segments.length != 2)
				throw new Exception("nn_table bad line: " + line);
			if (!domain_regex.matcher(segments[0]).matches())
				throw new Exception("nn_table bad line: " + line);
			NextNode target;
			if (segments[1].equals("direct"))
				target = nn_direct;
			else if (segments[1].equals("reject"))
				target = nn_ban;
			else if (segments[1].equals("proxy"))
				target = nn_proxy;
			else
				throw new Exception("nn_table bad line " + line);
			domain_to_nn.put(segments[0], target);
		}

	}

	private static class SocketBundle {
		public Socket socket;
		public InputStream is;
		public OutputStream os;
		// optional
		public long expireTime;
		public long nextKeepAliveTime;

		public SocketBundle(Socket socket, InputStream is, OutputStream os) {
			this.socket = socket;
			this.is = is;
			this.os = os;
		}
	}

	private static class NextNode {
		public enum Type {
			DIRECT, PROXY, BAN
		};

		public final Type type;

		public NextNode(Type type, Proxy next_node) {
			this.type = type;
		}

		@Override
		public String toString() {
			return type.toString();
		}

	}

	private static class IpRange {
		public final long begin;
		public final long end;
		private final NextNode nextnode;

		public IpRange(long begin, long end, NextNode target) {
			this.begin = begin;
			this.end = end;
			this.nextnode = target;
		}
	}

}
