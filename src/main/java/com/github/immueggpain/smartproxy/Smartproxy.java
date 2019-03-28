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

import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.apache.commons.collections4.MapIterator;
import org.apache.commons.collections4.multimap.ArrayListValuedHashMap;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.BOMInputStream;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.http.ConnectionClosedException;
import org.apache.http.Header;
import org.apache.http.HeaderIterator;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.HttpVersion;
import org.apache.http.ParseException;
import org.apache.http.ProtocolVersion;
import org.apache.http.RequestLine;
import org.apache.http.TokenIterator;
import org.apache.http.impl.DefaultBHttpClientConnection;
import org.apache.http.impl.DefaultBHttpServerConnection;
import org.apache.http.message.BasicHttpEntityEnclosingRequest;
import org.apache.http.message.BasicHttpRequest;
import org.apache.http.message.BasicHttpResponse;
import org.apache.http.message.BasicTokenIterator;
import org.apache.http.protocol.HTTP;
import org.apache.http.util.EntityUtils;

import com.github.immueggpain.common.sc;
import com.github.immueggpain.common.scmt;
import com.github.immueggpain.common.sct;
import com.github.immueggpain.common.sctp;
import com.github.immueggpain.smartproxy.Launcher.ClientSettings;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WinDef.DWORD;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.win32.StdCallLibrary;

public class Smartproxy {

	private static final int SP_SVR_CONNECT_TIMEOUT = 10 * 1000;
	private static final int SP_SVR_SMALL_TIMEOUT = 15 * 1000;
	private static final int SP_SVR_SO_TIMEOUT = 60 * 1000;
	private static final int SP_SVR_REST_TIMEOUT = 60 * 1000 * 5;
	private static final int BUF_SIZE = 1024 * 16;
	private static final SecureRandom rand = new SecureRandom();

	private static final int HTTP_CONN_BUF_SIZE = 32 * 1024;
	private static final int SOCKET_CONNECT_TIMEOUT = 1000 * 15;
	private static final int SOCKET_SO_TIMEOUT_CLIENT = 0;
	private static final int SOCKET_SO_TIMEOUT_NEXTNODE = 0;
	private static final int HTTP_POOL_TIMEOUT = 120 * 1000;
	private static final Pattern httpconnect_regex = Pattern.compile("CONNECT (.+):([0-9]+) HTTP/1[.][01]");
	private static final byte[] httpconnect_okresponse = sc.s2b("HTTP/1.1 200 OK\r\n\r\n");
	private static final byte[] httpconnect_500response = sc.s2b("HTTP/1.1 500 Internal Server Error\r\n\r\n");
	private static final Pattern ip_regex = Pattern.compile("\\d+\\.\\d+\\.\\d+\\.\\d+");
	private static final Pattern domain_regex = Pattern.compile("[a-z0-9-_]*(\\.[a-z0-9-_]+)*");

	private static PrintWriter log;

	private Set<String> encountered_request_headers = new HashSet<>();
	private Set<String> encountered_response_headers = new HashSet<>();

	private SSLSocketFactory ssf;
	private byte[] password = new byte[64];
	private TunnelPool tunnelPool;

	private ClientSettings settings;
	private Proxy next_proxy;
	private NextNode nn_direct;
	private NextNode nn_ban;
	private NextNode nn_proxy;
	private Map<String, NextNode> domain_to_nn;
	private NavigableMap<Long, IpRange> ip_to_nn;
	private ConnPool socketPool;

	public void run(ClientSettings settings) throws Exception {
		this.settings = settings;
		// from now on, log output to '-l' option or 'smartproxy.log' by default
		log = new PrintWriter(
				new BufferedWriter(new OutputStreamWriter(new FileOutputStream(settings.logfile), sc.utf8)), true);

		byte[] bytes = settings.password.getBytes(StandardCharsets.UTF_8);
		System.arraycopy(bytes, 0, this.password, 0, bytes.length);

		nn_direct = new NextNode(NextNode.Type.DIRECT, Proxy.NO_PROXY);
		nn_ban = new NextNode(NextNode.Type.BAN, null);
		nn_proxy = new NextNode(NextNode.Type.PROXY, next_proxy);
		load_domain_nn_table();
		socketPool = new ConnPool(HTTP_POOL_TIMEOUT);

		// set SSL
		SSLContext context = SSLContext.getInstance("TLSv1.2");
		context.init(null, null, null);
		ssf = context.getSocketFactory();

		tunnelPool = new TunnelPool(settings.server_ip, settings.server_port);

		try (ServerSocket ss = new ServerSocket(settings.local_listen_port, 50,
				InetAddress.getByName(settings.local_listen_ip))) {
			log.println("listened on port " + settings.local_listen_port);
			while (true) {
				Socket s = ss.accept();
				setSocketOptions(s);
				// use source port as id
				int id = s.getPort();
				scmt.execAsync("recv_" + id + "_client", () -> recv_client(s, id));
			}
		}
	}

	private void recv_client(Socket raw, int id) {
		// wrap socket. if failed, just close socket and quit.
		SecTcpSocket s_client = null;
		try {
			s_client = new SecTcpSocket(raw);
		} catch (IOException e) {
			e.printStackTrace(log);
			try {
				raw.close();
			} catch (IOException e1) {
				e1.printStackTrace(log);
			}
			return;
		}

		try {
			raw.setSoTimeout(SOCKET_SO_TIMEOUT_CLIENT);
			BufferedInputStream is = new BufferedInputStream(s_client.is);
			is.mark(1);
			int byte1 = is.read();
			if (byte1 == -1) {
				// client closes without sending any data
				s_client.close();
				return;
			}

			byte first_byte = (byte) byte1;
			if (first_byte == 5) {
				// socks5
				socks5(first_byte, is, s_client.os, s_client);
				return;
			} else if (first_byte == 4) {
				// socks4
				socks4(first_byte, is, s_client.os, raw);
				return;
			} else if (first_byte == 0x43) {
				// 0x43 'C' http connect
				http_connect(first_byte, is, s_client.os, raw);
				return;
			} else if (first_byte == 0x47 || first_byte == 0x50 || first_byte == 0x48) {
				// 0x47 'G' http get
				// 0x50 'P' http post/put
				// 0x48 'H' http head
				is.reset();
				http_other(is, s_client.os, raw);
				return;
			} else {
				s_client.close();
				throw new Exception("error unknown proxy protocol first_byte " + sctp.byte_to_string(first_byte));
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void socks5(byte first_byte, InputStream is1, OutputStream os1, SecTcpSocket s_client) throws Exception {
		@SuppressWarnings("unused")
		byte socks_version = first_byte;
		// System.out.println("socks_version " + sctp.byte_to_string(socks_version));
		DataInputStream is = new DataInputStream(is1);
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

		DataOutputStream os = new DataOutputStream(os1);
		byte[] buf = new byte[2];
		buf[0] = 5; // reply socks version
		buf[1] = 0; // choose No authentication method
		os.write(buf);
		os.flush();

		// recv socks version again
		socks_version = is.readByte();
		// System.out.println("socks_version_2 " + sctp.byte_to_string(socks_version));

		// recv command code
		byte command_code = is.readByte();
		if (command_code != 1)
			log.println("error command_code " + sctp.byte_to_string(command_code));

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
			throw new Exception("error ipv6 address");
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

		// now we connect next node
		SocketBundle cserver_sb = create_connect_config_socket(dest_sockaddr, "socks5");
		if (cserver_sb == null) {
			// can't connect
			buf = new byte[10];

			// reply socks version again
			buf[0] = 5;

			// reply status
			// X'04' Host unreachable
			buf[1] = 4;

			// reserved
			buf[2] = 0;

			// bind address data, not used
			buf[3] = 1;

			// buf[4~7] is ip 0.0.0.0
			// buf[8~9] is port 0

			os.write(buf);
			os.flush();
			s_client.close();
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

		// bind address data, not used
		buf[3] = 1;

		// buf[4~7] is ip 0.0.0.0
		// buf[8~9] is port 0

		os.write(buf);
		os.flush();

		// transfer data
		handleConnection(cserver_sb.is, cserver_sb.os, is, os, dest_sockaddr.toString(), cserver_sb.socket,
				s_client.getRaw());
	}

	private void http_connect(byte first_byte, InputStream is, OutputStream os, Socket sclient_s) throws Exception {
		byte[] headers_buf = new byte[1024 * 1024];
		int pos = 0;
		headers_buf[pos++] = first_byte;
		while (true) {
			int b = is.read();
			if (b == -1) {
				throw new Exception("error incomplete http headers");
			}
			headers_buf[pos++] = (byte) b;
			if (pos >= 4 && headers_buf[pos - 4] == '\r' && headers_buf[pos - 3] == '\n' && headers_buf[pos - 2] == '\r'
					&& headers_buf[pos - 1] == '\n') {
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
		InetSocketAddress dest_sockaddr;
		if (matcher.matches()) {
			dest_sockaddr = new InetSocketAddress(InetAddress.getByName(dest_host), port);
		} else {
			dest_sockaddr = InetSocketAddress.createUnresolved(dest_host, port);
		}

		// connect to nn
		SocketBundle cserver_sb = create_connect_config_socket(dest_sockaddr, "connect");
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
		handleConnection(cserver_sb.is, cserver_sb.os, is, os, dest_sockaddr.toString(), cserver_sb.socket, sclient_s);
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
		log.println("userid " + userid);

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
				if (sct.time_ms() - contxt.lastWriteToClient < SP_SVR_SO_TIMEOUT)
					continue;
				else {
					if (contxt.closing)
						break;
					log.println(String.format("%s sclient read timeout %s", sct.datetime(), contxt.toString()));
					contxt.isBroken = true;
					break;
				}
			} catch (Throwable e) {
				if (contxt.closing)
					break;
				log.println(String.format("%s sclient read exception %s (%s)", sct.datetime(), contxt.toString(), e));
				contxt.isBroken = true;
				break;
			}

			// normal EOF
			if (n == -1) {
				if (contxt.closing)
					break;
				log.println(String.format("%s sclient read eof %s", sct.datetime(), contxt.toString()));
				break;
			}

			// write some bytes
			try {
				cserver_os.write(buf, 0, n);
			} catch (Throwable e) {
				if (contxt.closing)
					break;
				log.println(String.format("%s cserver write exception %s", sct.datetime(), contxt.toString()));
				e.printStackTrace(log);
				contxt.isBroken = true;
				break;
			}
			contxt.lastWriteToServer = sct.time_ms();
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
				if (sct.time_ms() - contxt.lastWriteToServer < SP_SVR_SO_TIMEOUT)
					continue;
				else {
					if (contxt.closing)
						break;
					log.println(String.format("%s cserver read timeout %s", sct.datetime(), contxt.toString()));
					contxt.isBroken = true;
					break;
				}
			} catch (Throwable e) {
				if (contxt.closing)
					break;
				log.println(String.format("%s cserver read exception %s (%s)", sct.datetime(), contxt.toString(), e));
				contxt.isBroken = true;
				break;
			}

			// normal EOF
			if (n == -1) {
				if (contxt.closing)
					break;
				log.println(String.format("%s cserver read eof %s", sct.datetime(), contxt.toString()));
				break;
			}

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

	private static class TunnelContext {
		public volatile long lastWriteToClient = 0;
		public volatile long lastWriteToServer = 0;
		public final String dest_name;
		public Socket cserver_s;
		public Socket sclient_s;
		public boolean isBroken = false;
		public boolean closing = false;

		public TunnelContext(String dest_name, Socket cserver_s, Socket sclient_s) {
			this.dest_name = dest_name;
			this.cserver_s = cserver_s;
			this.sclient_s = sclient_s;
		}

		@Override
		public String toString() {
			return String.format("%s", dest_name);
		}
	}

	private void http_other(InputStream is, OutputStream os, Socket socket) {
		// setup client httpconn
		try (DefaultBHttpServerConnection http_conn = new DefaultBHttpServerConnection(HTTP_CONN_BUF_SIZE) {
			@Override
			protected InputStream getSocketInputStream(Socket socket) throws IOException {
				return is;
			}

			@Override
			protected OutputStream getSocketOutputStream(Socket socket) throws IOException {
				return os;
			}
		}) {
			http_conn.bind(socket);
			Thread.currentThread().setName("http_" + socket.getPort());

			while (true) {
				// parse request+entity of client
				HttpRequest request = null;
				try {
					request = http_conn.receiveRequestHeader();
				} catch (ConnectionClosedException e) {
					// client just closed the socket
					return;
				} catch (SocketException e) {
					if (e.getMessage().equals("Connection reset"))
						return;
					else
						throw e;
				}
				HttpEntity entity = null;
				if (request instanceof HttpEntityEnclosingRequest) {
					HttpEntityEnclosingRequest request_withbody = (HttpEntityEnclosingRequest) request;
					http_conn.receiveRequestEntity(request_withbody);
					entity = request_withbody.getEntity();
				}

				RequestLine requestLine = request.getRequestLine();
				String uri_str = requestLine.getUri();
				// fix because stupid tencent TIM include {} in urls
				uri_str = uri_str.replace("{", "%7B");
				uri_str = uri_str.replace("}", "%7D");
				URI uri = new URI(uri_str);
				int port = uri.getPort() == -1 ? 80 : uri.getPort();
				String host = uri.getHost();

				// respond 400 for bad request
				if (host.equals("canonicalizer.ucsuri.tcs")) {
					log.println("error canonicalizer.ucsuri.tcs");
					if (entity != null)
						EntityUtils.consume(entity);

					BasicHttpResponse response = new BasicHttpResponse(HttpVersion.HTTP_1_1, HttpStatus.SC_BAD_REQUEST,
							"Bad Request");
					http_conn.sendResponseHeader(response);
					http_conn.sendResponseEntity(response);
					http_conn.flush();
					if (keepAlive(request, response))
						continue;
					else {
						return;
					}
				}

				// connect nextnode
				InetSocketAddress dest_sockaddr = InetSocketAddress.createUnresolved(host, port);
				DefaultBHttpClientConnection http_conn_nn = socketPool.get(dest_sockaddr, socket.getPort());
				try {
					// make status line for nextnode
					BasicHttpRequest request_nn = null;
					String newuri = uri.getRawPath();
					if (uri.getRawQuery() != null)
						newuri += "?" + uri.getRawQuery();
					if (entity == null)
						request_nn = new BasicHttpRequest(request.getRequestLine().getMethod(), newuri,
								HttpVersion.HTTP_1_1);
					else
						request_nn = new BasicHttpEntityEnclosingRequest(request.getRequestLine().getMethod(), newuri,
								HttpVersion.HTTP_1_1);

					if (request.getFirstHeader("Keep-Alive") != null)
						log.println(request.getFirstHeader("Keep-Alive"));
					// make headers for nextnode
					request_nn.setHeaders(request.getAllHeaders());
					request_nn.removeHeaders("Host");
					request_nn.removeHeaders("Connection");
					request_nn.removeHeaders("Proxy-Connection");
					request_nn.removeHeaders("Keep-Alive");
					request_nn.removeHeaders("Proxy-Authenticate");
					request_nn.removeHeaders("TE");
					request_nn.removeHeaders("Trailers");
					request_nn.removeHeaders("Upgrade");
					for (Header header : request_nn.getAllHeaders()) {
						if (encountered_request_headers.add(header.getName())) {
							// log.println("request headers add " + header.getName() + ": " +
							// header.getValue());
							// System.out.println("request headers " + encountered_request_headers);
						}
					}
					request_nn.addHeader("Host", uri.getRawAuthority());
					request_nn.addHeader("Connection", "keep-alive");

					// make entity for nextnode
					if (entity != null) {
						HttpEntityEnclosingRequest request_withbody = (HttpEntityEnclosingRequest) request_nn;
						request_withbody.setEntity(entity);
					}

					// send request1+entity to nextnode
					http_conn_nn.sendRequestHeader(request_nn);
					if (request_nn instanceof HttpEntityEnclosingRequest)
						http_conn_nn.sendRequestEntity((HttpEntityEnclosingRequest) request_nn);
					http_conn_nn.flush();
					// make sure request from client is consumed
					EntityUtils.consume(entity);

					HttpResponse response_nn = http_conn_nn.receiveResponseHeader();
					http_conn_nn.receiveResponseEntity(response_nn);

					// make response status line
					BasicHttpResponse response = new BasicHttpResponse(HttpVersion.HTTP_1_1,
							response_nn.getStatusLine().getStatusCode(), response_nn.getStatusLine().getReasonPhrase());

					// make response headers
					response.setHeaders(response_nn.getAllHeaders());
					response.removeHeaders("Connection");
					response.removeHeaders("Proxy-Connection");
					response.removeHeaders("Keep-Alive");
					response.removeHeaders("TE");
					response.removeHeaders("Trailers");
					response.removeHeaders("Upgrade");
					for (Header header : response.getAllHeaders()) {
						if (encountered_response_headers.add(header.getName())) {
							// log.println("response headers add " + header.getName() + ": " +
							// header.getValue());
							// System.out.println("response headers " + encountered_response_headers);
						}
					}
					boolean keepAlive = keepAlive(request, response);
					if (keepAlive)
						response.addHeader("Connection", "keep-alive");
					else
						response.addHeader("Connection", "close");

					// make response1 entity
					response.setEntity(response_nn.getEntity());
					http_conn.sendResponseHeader(response);
					if (canResponseHaveBody(request_nn, response_nn))
						http_conn.sendResponseEntity(response);
					http_conn.flush();

					boolean keepAlive_nn = keepAlive(request_nn, response_nn);
					if (keepAlive_nn) {
						socketPool.giveback(dest_sockaddr, http_conn_nn);
					} else {
						log.println("nc");
						try {
							http_conn_nn.close();
						} catch (IOException e1) {
							e1.printStackTrace(log);
						}
					}

					if (keepAlive) {
					} else {
						log.println("c");
						// return to close http_conn
						return;
					}
				} catch (Exception e) {
					log.println(requestLine);
					e.printStackTrace(log);
					try {
						http_conn_nn.close();
					} catch (IOException e1) {
						e1.printStackTrace(log);
					}
					// return to close http_conn
					return;
				}
			} // end of while, continue next http request
		} catch (Exception e) {
			e.printStackTrace(log);
		}
	}

	/**
	 * return null means connection refused, or connect timed out, or can't resolve
	 * hostname
	 */
	private SocketBundle create_connect_config_socket(InetSocketAddress dest_sockaddr, String client_protocol)
			throws Exception {
		NextNode nextNode;
		if (dest_sockaddr.isUnresolved()) {
			String hostString = dest_sockaddr.getHostString();
			if (ip_regex.matcher(hostString).matches()) {
				// is an ip string
				long ip = ip2long(hostString);
				IpRange ipRange = ip_to_nn.floorEntry(ip).getValue();
				if (ip > ipRange.end) {
					nextNode = nn_proxy;
					log.println(String.format("%s %-7s: %-6s <- default <- %s", sct.datetime(), client_protocol,
							nextNode, hostString));
				} else {
					nextNode = ipRange.nextnode;
					log.println(String.format("%s %-7s: %-6s <- %s ~ %s <- %s", sct.datetime(), client_protocol,
							nextNode, long2ip(ipRange.begin), long2ip(ipRange.end), hostString));
				}
			} else {
				// is a domain string
				nextNode = domain_to_nn.get(hostString);
				if (nextNode != null) {
					log.println(String.format("%s %-7s: %-6s <- %s", sct.datetime(), client_protocol, nextNode,
							hostString));
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
						log.println(String.format("%s %-7s: %-6s <- default <- %s", sct.datetime(), client_protocol,
								nextNode, hostString));
					} else {
						log.println(String.format("%s %-7s: %-6s <- %s <- %s", sct.datetime(), client_protocol,
								nextNode, intermediate, hostString));
					}
				}
			}
		} else {
			String hostString = dest_sockaddr.getAddress().getHostAddress();
			long ip = ip2long(dest_sockaddr.getAddress());
			IpRange ipRange = ip_to_nn.floorEntry(ip).getValue();
			if (ip > ipRange.end) {
				nextNode = nn_proxy;
				log.println(String.format("%s %-7s: %-6s <- default <- %s", sct.datetime(), client_protocol, nextNode,
						hostString));
			} else {
				nextNode = ipRange.nextnode;
				log.println(String.format("%s %-7s: %-6s <- %s ~ %s <- %s", sct.datetime(), client_protocol, nextNode,
						long2ip(ipRange.begin), long2ip(ipRange.end), hostString));
			}
		}

		if (nextNode.type == NextNode.Type.BAN) {
			throw new Exception("this address is banned");
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
			Socket raw = direct_create_config_connect_socket(dest_sockaddr);
			if (raw == null)
				return null;
			return new SocketBundle(raw, raw.getInputStream(), raw.getOutputStream());
		} else if (nextNode.type == NextNode.Type.PROXY) {
			// connect through sp server
			SocketBundle tunnel = tunnelPool.pollTunnel(dest_sockaddr.getHostString(), dest_sockaddr.getPort());
			if (tunnel == null) {
				log.println(sct.datetime() + " use tunnel out pool");
				return create_tunnel(settings.server_ip, settings.server_port, ssf, password,
						dest_sockaddr.getHostString(), dest_sockaddr.getPort());
			} else {
				log.println(sct.datetime() + " use tunnel from pool");
				return tunnel;
			}
		} else
			throw new RuntimeException("impossible");
	}

	private static SocketBundle create_tunnel(String server_hostname, int server_port, SSLSocketFactory ssf,
			byte[] password, String dest_hostname, int dest_port) {
		try {
			// create sslsocket
			SSLSocket cserver_s = (SSLSocket) ssf.createSocket();

			// config sslsocket
			cserver_s.setEnabledCipherSuites(new String[] { "TLS_RSA_WITH_AES_128_GCM_SHA256" });
			// use small timeout first
			cserver_s.setSoTimeout(SP_SVR_SMALL_TIMEOUT);

			// connect to sp server
			try {
				cserver_s.connect(new InetSocketAddress(server_hostname, server_port), SP_SVR_CONNECT_TIMEOUT);
			} catch (Throwable e) {
				log.println(sct.datetime() + " error when connect sp server " + e);
				Util.abortiveCloseSocket(cserver_s);
				return null;
			}

			DataInputStream is = new DataInputStream(cserver_s.getInputStream());
			DataOutputStream os = new DataOutputStream(cserver_s.getOutputStream());

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

			// authn
			try {
				os.write(password);
			} catch (Exception e) {
				log.println(sct.datetime() + " error when send pswd " + e);
				Util.abortiveCloseSocket(cserver_s);
				return null;
			}

			// send rest timeout
			try {
				os.writeInt(SP_SVR_SMALL_TIMEOUT);
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

			// send dest info
			try {
				os.writeUTF(dest_hostname);
				os.writeShort(dest_port);
			} catch (Exception e) {
				log.println(sct.datetime() + " error when send dest info " + e);
				Util.abortiveCloseSocket(cserver_s);
				return null;
			}

			// restore to normal timeout
			cserver_s.setSoTimeout(SP_SVR_SO_TIMEOUT);

			return new SocketBundle(cserver_s, is, os);
		} catch (Throwable e) {
			log.println("there shouldn't be any exception here");
			e.printStackTrace(log);
			return null;
		}
	}

	private static SocketBundle create_half_tunnel(String server_hostname, int server_port, SSLSocketFactory ssf,
			byte[] password) {
		try {
			// create sslsocket
			SSLSocket cserver_s = (SSLSocket) ssf.createSocket();

			// config sslsocket
			cserver_s.setEnabledCipherSuites(new String[] { "TLS_RSA_WITH_AES_128_GCM_SHA256" });
			// use small timeout first
			cserver_s.setSoTimeout(1000 * 15);

			// connect to sp server
			try {
				cserver_s.connect(new InetSocketAddress(server_hostname, server_port), SP_SVR_CONNECT_TIMEOUT);
			} catch (Throwable e) {
				log.println(sct.datetime() + " error when connect sp server " + e);
				Util.abortiveCloseSocket(cserver_s);
				return null;
			}

			DataInputStream is = new DataInputStream(cserver_s.getInputStream());
			DataOutputStream os = new DataOutputStream(cserver_s.getOutputStream());

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

			// authn
			try {
				os.write(password);
			} catch (Exception e) {
				log.println(sct.datetime() + " error when send pswd " + e);
				Util.abortiveCloseSocket(cserver_s);
				return null;
			}

			// send rest timeout
			try {
				os.writeInt(SP_SVR_REST_TIMEOUT);
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

			SocketBundle sb = new SocketBundle(cserver_s, is, os);
			sb.expireTime = System.currentTimeMillis() + SP_SVR_REST_TIMEOUT - 1000;
			return sb;
		} catch (Throwable e) {
			log.println("there shouldn't be any exception here");
			e.printStackTrace(log);
			return null;
		}
	}

	private static SocketBundle create_full_tunnel(SocketBundle sb, String dest_hostname, int dest_port) {
		try {
			// DataInputStream is = new DataInputStream(sb.is);
			DataOutputStream os = new DataOutputStream(sb.os);
			Socket cserver_s = sb.socket;

			// send dest info
			try {
				os.writeUTF(dest_hostname);
				os.writeShort(dest_port);
			} catch (Exception e) {
				log.println(sct.datetime() + " error when send dest info " + e);
				Util.abortiveCloseSocket(cserver_s);
				return null;
			}

			// restore to normal timeout
			cserver_s.setSoTimeout(SP_SVR_SO_TIMEOUT);

			return sb;
		} catch (Throwable e) {
			log.println("there shouldn't be any exception here");
			e.printStackTrace(log);
			return null;
		}
	}

	private class TunnelPool {

		private BlockingQueue<SocketBundle> halfTunnels = new ArrayBlockingQueue<>(40);
		private String server_hostname;
		private int server_port;

		public TunnelPool(String server_hostname, int server_port) {
			this.server_hostname = server_hostname;
			this.server_port = server_port;
			scmt.execAsync("tunnel-pool-connect1", this::connect);
			scmt.execAsync("tunnel-pool-connect2", this::connect);
			scmt.execAsync("tunnel-pool-connect3", this::connect);
			scmt.execAsync("tunnel-pool-connect4", this::connect);
			scmt.execAsync("tunnel-pool-cleaner", this::cleaner);
		}

		private void connect() {
			while (true) {
				SocketBundle half_tunnel = create_half_tunnel(server_hostname, server_port, ssf, password);
				if (half_tunnel != null)
					try {
						halfTunnels.put(half_tunnel);
						log.println(sct.datetime() + " new half tunnel to pool " + halfTunnels.size());
					} catch (InterruptedException e) {
						e.printStackTrace(log);
					}
			}
		}

		private void cleaner() {
			while (true) {
				SocketBundle sb = halfTunnels.peek();
				if (sb != null && sb.expireTime < System.currentTimeMillis()) {
					if (halfTunnels.remove(sb)) {
						Util.abortiveCloseSocket(sb.socket);
						log.println(sct.datetime() + " half tunnel expires");
					}
				}
				try {
					Thread.sleep(1000);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
		}

		public SocketBundle pollTunnel(String dest_hostname, int dest_port) throws InterruptedException {
			SocketBundle half_tunnel = halfTunnels.poll();
			if (half_tunnel == null)
				return null;
			return create_full_tunnel(half_tunnel, dest_hostname, dest_port);
		}
	}

	/** return null means connection refused, or connect timed out */
	private Socket direct_create_config_connect_socket(SocketAddress dest_sockaddr) throws IOException {
		Socket s = new Socket(Proxy.NO_PROXY);
		setSocketOptions(s);
		try {
			s.connect(dest_sockaddr, SOCKET_CONNECT_TIMEOUT);
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
		Path path = Paths.get("user.rule");
		try (BOMInputStream is = new BOMInputStream(new FileInputStream(path.toFile()))) {
			for (String line : IOUtils.readLines(is, sc.utf8)) {
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
					long begin = ip2long(segments[0]);
					long end = ip2long(segments[1]);
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
	}

	private static class SocketBundle {
		public Socket socket;
		public InputStream is;
		public OutputStream os;
		// optional
		public long expireTime;

		public SocketBundle(Socket socket, InputStream is, OutputStream os) {
			this.socket = socket;
			this.is = is;
			this.os = os;
		}
	}

	public static interface Iphlpapi extends StdCallLibrary {
		int GetExtendedTcpTable(MIB_TCPTABLE_OWNER_PID pTcpTable, IntByReference pdwSize, boolean bOrder, long ulAf,
				int table, long reserved);

		Iphlpapi INSTANCE = com.sun.jna.Native.loadLibrary("iphlpapi", Iphlpapi.class);
	}

	public static class MIB_TCPROW_OWNER_PID extends Structure {
		public DWORD dwState;
		public DWORD dwLocalAddr;
		public DWORD dwLocalPort;
		public DWORD dwRemoteAddr;
		public DWORD dwRemotePort;
		public DWORD dwOwningPid;

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList(new String[] { "dwState", "dwLocalAddr", "dwLocalPort", "dwRemoteAddr", "dwRemotePort",
					"dwOwningPid" });
		}

	}

	public static class MIB_TCPTABLE_OWNER_PID extends Structure {
		public DWORD dwNumEntries;
		public MIB_TCPROW_OWNER_PID[] table = new MIB_TCPROW_OWNER_PID[1];

		public MIB_TCPTABLE_OWNER_PID() {
		}

		public MIB_TCPTABLE_OWNER_PID(int size) {
			this.dwNumEntries = new DWORD(size);
			this.table = (MIB_TCPROW_OWNER_PID[]) new MIB_TCPROW_OWNER_PID().toArray(size);
		}

		@Override
		protected List<String> getFieldOrder() {
			return Arrays.asList(new String[] { "dwNumEntries", "table" });
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

	private class ConnPool {

		private ArrayListValuedHashMap<InetSocketAddress, UnusedConn> unused = new ArrayListValuedHashMap<>();
		private int timeout_ms;

		public ConnPool(int timeout_ms) {
			this.timeout_ms = timeout_ms;
			scmt.execAsync("pool_monitor", this::job_pool_monitor);
		}

		private void job_pool_monitor() {
			while (true) {
				scmt.sleep(1000 * 30);
				synchronized (unused) {
					MapIterator<InetSocketAddress, UnusedConn> iterator = unused.mapIterator();
					while (iterator.hasNext()) {
						iterator.next();
						UnusedConn value = iterator.getValue();
						if (sct.time_ms() - value.lastUsedTime > timeout_ms) {
							log.println(sct.datetime() + " socketPool " + iterator.getKey() + " expired");
							iterator.remove();
							try {
								value.conn.close();
							} catch (IOException e) {
								e.printStackTrace(log);
							}
						}
					}
				}
			}
		}

		public DefaultBHttpClientConnection get(InetSocketAddress dest_sockaddr, int client_remote_port)
				throws Exception {
			synchronized (unused) {
				List<UnusedConn> list = unused.get(dest_sockaddr);
				if (!list.isEmpty()) {
					log.println(sct.datetime() + " socketPool " + dest_sockaddr + " reused");
					return list.remove(list.size() - 1).conn;
				}
			}
			SocketBundle new_socketb = create_connect_config_socket(dest_sockaddr, "http");
			DefaultBHttpClientConnection conn = new DefaultBHttpClientConnection(HTTP_CONN_BUF_SIZE) {
				protected InputStream getSocketInputStream(final Socket socket) throws IOException {
					return new_socketb.is;
				}

				protected OutputStream getSocketOutputStream(final Socket socket) throws IOException {
					return new_socketb.os;
				}
			};
			conn.bind(new_socketb.socket);
			log.println(sct.datetime() + " socketPool " + dest_sockaddr + " created");
			return conn;
		}

		public void giveback(InetSocketAddress dest_sockaddr, DefaultBHttpClientConnection conn) {
			synchronized (unused) {
				unused.put(dest_sockaddr, new UnusedConn(conn, sct.time_ms()));
				log.println(sct.datetime() + " socketPool " + dest_sockaddr + " givenback");
			}
		}
	}

	private static class UnusedConn {
		public DefaultBHttpClientConnection conn;
		public long lastUsedTime;

		public UnusedConn(DefaultBHttpClientConnection conn, long lastUsedTime) {
			this.conn = conn;
			this.lastUsedTime = lastUsedTime;
		}
	}

	private static long ip2long(String ip) {
		String[] parts = ip.split("\\.");
		long ipLong = 0;
		for (int i = 0; i < 4; i++)
			ipLong += Integer.parseInt(parts[i]) << (24 - (8 * i));
		return ipLong;
	}

	private static long ip2long(InetAddress ip) {
		byte[] parts = ip.getAddress();
		long ipLong = 0;
		for (int i = 0; i < 4; i++)
			ipLong += (parts[i] & 0xff) << (24 - (8 * i));
		return ipLong;
	}

	private static String long2ip(long l) {
		String ip = (l >> 24 & 0xff) + "." + (l >> 16 & 0xff) + "." + (l >> 8 & 0xff) + "." + (l & 0xff);
		return ip;
	}

	private static void setSocketOptions(Socket s) throws SocketException {
		s.setTcpNoDelay(true);
		s.setSoTimeout(SOCKET_SO_TIMEOUT_NEXTNODE);
	}

	private static boolean keepAlive(final HttpRequest request, final HttpResponse response) {
		if (request != null) {
			try {
				final TokenIterator ti = new BasicTokenIterator(request.headerIterator(HttpHeaders.CONNECTION));
				while (ti.hasNext()) {
					final String token = ti.nextToken();
					if (HTTP.CONN_CLOSE.equalsIgnoreCase(token)) {
						return false;
					}
				}
			} catch (final ParseException px) {
				// invalid connection header. do not re-use
				return false;
			}
		}

		// Check for a self-terminating entity. If the end of the entity will
		// be indicated by closing the connection, there is no keep-alive.
		final ProtocolVersion ver = response.getStatusLine().getProtocolVersion();
		final Header teh = response.getFirstHeader(HTTP.TRANSFER_ENCODING);
		if (teh != null) {
			if (!HTTP.CHUNK_CODING.equalsIgnoreCase(teh.getValue())) {
				return false;
			}
		} else {
			if (canResponseHaveBody(request, response)) {
				final Header[] clhs = response.getHeaders(HTTP.CONTENT_LEN);
				// Do not reuse if not properly content-length delimited
				if (clhs.length == 1) {
					final Header clh = clhs[0];
					try {
						final int contentLen = Integer.parseInt(clh.getValue());
						if (contentLen < 0) {
							return false;
						}
					} catch (final NumberFormatException ex) {
						return false;
					}
				} else {
					return false;
				}
			}
		}

		// Check for the "Connection" header. If that is absent, check for
		// the "Proxy-Connection" header. The latter is an unspecified and
		// broken but unfortunately common extension of HTTP.
		HeaderIterator headerIterator = response.headerIterator(HTTP.CONN_DIRECTIVE);
		if (!headerIterator.hasNext()) {
			headerIterator = response.headerIterator("Proxy-Connection");
		}

		// Experimental usage of the "Connection" header in HTTP/1.0 is
		// documented in RFC 2068, section 19.7.1. A token "keep-alive" is
		// used to indicate that the connection should be persistent.
		// Note that the final specification of HTTP/1.1 in RFC 2616 does not
		// include this information. Neither is the "Connection" header
		// mentioned in RFC 1945, which informally describes HTTP/1.0.
		//
		// RFC 2616 specifies "close" as the only connection token with a
		// specific meaning: it disables persistent connections.
		//
		// The "Proxy-Connection" header is not formally specified anywhere,
		// but is commonly used to carry one token, "close" or "keep-alive".
		// The "Connection" header, on the other hand, is defined as a
		// sequence of tokens, where each token is a header name, and the
		// token "close" has the above-mentioned additional meaning.
		//
		// To get through this mess, we treat the "Proxy-Connection" header
		// in exactly the same way as the "Connection" header, but only if
		// the latter is missing. We scan the sequence of tokens for both
		// "close" and "keep-alive". As "close" is specified by RFC 2068,
		// it takes precedence and indicates a non-persistent connection.
		// If there is no "close" but a "keep-alive", we take the hint.

		if (headerIterator.hasNext()) {
			try {
				final TokenIterator ti = new BasicTokenIterator(headerIterator);
				boolean keepalive = false;
				while (ti.hasNext()) {
					final String token = ti.nextToken();
					if (HTTP.CONN_CLOSE.equalsIgnoreCase(token)) {
						return false;
					} else if (HTTP.CONN_KEEP_ALIVE.equalsIgnoreCase(token)) {
						// continue the loop, there may be a "close" afterwards
						keepalive = true;
					}
				}
				if (keepalive) {
					return true;
					// neither "close" nor "keep-alive", use default policy
				}

			} catch (final ParseException px) {
				// invalid connection header. do not re-use
				return false;
			}
		}

		// default since HTTP/1.1 is persistent, before it was non-persistent
		return !ver.lessEquals(HttpVersion.HTTP_1_0);
	}

	private static boolean canResponseHaveBody(final HttpRequest request, final HttpResponse response) {
		if (request != null && request.getRequestLine().getMethod().equalsIgnoreCase("HEAD")) {
			return false;
		}
		final int status = response.getStatusLine().getStatusCode();
		return status >= HttpStatus.SC_OK && status != HttpStatus.SC_NO_CONTENT && status != HttpStatus.SC_NOT_MODIFIED
				&& status != HttpStatus.SC_RESET_CONTENT;
	}

}
