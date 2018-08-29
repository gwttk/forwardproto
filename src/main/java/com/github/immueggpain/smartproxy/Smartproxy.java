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
import java.io.File;
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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.net.Proxy.Type;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.collections4.MapIterator;
import org.apache.commons.collections4.multimap.ArrayListValuedHashMap;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.BOMInputStream;
import org.apache.http.ConnectionClosedException;
import org.apache.http.Header;
import org.apache.http.HeaderIterator;
import org.apache.http.HttpClientConnection;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpHost;
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
import org.apache.http.impl.pool.BasicConnPool;
import org.apache.http.impl.pool.BasicPoolEntry;
import org.apache.http.message.BasicHttpEntityEnclosingRequest;
import org.apache.http.message.BasicHttpRequest;
import org.apache.http.message.BasicHttpResponse;
import org.apache.http.message.BasicTokenIterator;
import org.apache.http.pool.ConnFactory;
import org.apache.http.protocol.HTTP;
import org.apache.http.util.EntityUtils;

import com.github.immueggpain.common.sc;
import com.github.immueggpain.common.scmt;
import com.github.immueggpain.common.sct;
import com.github.immueggpain.common.sctp;
import com.google.gson.Gson;

public class Smartproxy {

	private static final int HTTP_CONN_BUF_SIZE = 8 * 1024;
	private static final int SOCKET_CONNECT_TIMEOUT = 1000 * 30;
	private static final int SOCKET_SO_TIMEOUT_CLIENT = 0;
	private static final int SOCKET_SO_TIMEOUT_NEXTPROXY = 0;
	private static final int CONNECTION_POOL_TIMEOUT = 120 * 1000;
	private static final Pattern httpconnect_regex = Pattern.compile("CONNECT (.+):([0-9]+) HTTP/1[.][01]");
	private static final byte[] httpconnect_okresponse = sc.s2b("HTTP/1.1 200 OK\r\n\r\n");
	private static final Pattern ip_regex = Pattern.compile("\\d+\\.\\d+\\.\\d+\\.\\d+");
	private static final Pattern domain_regex = Pattern.compile("[a-z0-9-]*(\\.[a-z0-9-]+)+");

	private static PrintWriter log;

	private Set<String> encountered_request_headers = new HashSet<>();
	private Set<String> encountered_response_headers = new HashSet<>();

	private Settings settings;
	private SocketAddress nextproxy_addr;
	private Proxy next_proxy;
	private BasicConnPool connpool;
	private NextNode nn_direct;
	private NextNode nn_ban;
	private NextNode nn_proxy;
	private Map<String, NextNode> domain_to_nn;
	private NavigableMap<Long, IpRange> ip_to_nn;

	public static void main(String[] args) {
		try {
			new Smartproxy().run(args);
		} catch (Exception e) {
			e.printStackTrace(log);
		}
	}

	private void run(String[] args) throws Exception {
		log = new PrintWriter(System.err, true);

		// option long names
		String backend_proxy_port = "backend_proxy_port";
		String local_listen_port = "local_listen_port";

		// define options
		Options options = new Options();
		options.addOption("h", "help", false, "print help");
		options.addOption("p", backend_proxy_port, true, "backend proxy port");
		options.addOption("n", local_listen_port, true, "local listening port");
		options.addOption("l", "log", true, "log file path");

		// parse from cmd args
		DefaultParser parser = new DefaultParser();
		CommandLine cmd = parser.parse(options, args);

		// parse from settings.json file
		settings = new Gson().fromJson(FileUtils.readFileToString(new File("settings.json"), sc.utf8), Settings.class);

		if (cmd.hasOption('h')) {
			HelpFormatter formatter = new HelpFormatter();
			formatter.printHelp("smartproxy", options, true);
			return;
		}
		if (cmd.hasOption(backend_proxy_port)) {
			settings.backend_proxy_port = Integer.parseInt(cmd.getOptionValue(backend_proxy_port));
		}
		if (cmd.hasOption(local_listen_port)) {
			settings.local_listen_port = Integer.parseInt(cmd.getOptionValue(local_listen_port));
		}
		// set log output to '-l' option or 'smartproxy.log' by default
		log = new PrintWriter(new BufferedWriter(
				new OutputStreamWriter(new FileOutputStream(cmd.getOptionValue('l', "smartproxy.log")), sc.utf8)),
				true);

		nextproxy_addr = new InetSocketAddress(InetAddress.getByName(settings.backend_proxy_ip),
				settings.backend_proxy_port);
		next_proxy = new Proxy(Type.SOCKS, nextproxy_addr);
		nn_direct = new NextNode(NextNode.Type.DIRECT, Proxy.NO_PROXY);
		nn_ban = new NextNode(NextNode.Type.BAN, null);
		nn_proxy = new NextNode(NextNode.Type.PROXY, next_proxy);
		load_domain_nn_table();
		connpool = new BasicConnPool(new ConnFactory<HttpHost, HttpClientConnection>() {
			@Override
			public HttpClientConnection create(HttpHost route) throws IOException {
				InetSocketAddress dest_sockaddr = InetSocketAddress.createUnresolved(route.getHostName(),
						route.getPort());
				Socket socket_nn = null;
				try {
					socket_nn = create_connect_config_socket(dest_sockaddr, "http");
				} catch (Exception e) {
					e.printStackTrace(log);
				}
				DefaultBHttpClientConnection http_conn_nn = new DefaultBHttpClientConnection(HTTP_CONN_BUF_SIZE);
				http_conn_nn.bind(socket_nn);
				return http_conn_nn;
			}
		});
		connpool.setMaxTotal(200);
		connpool.setDefaultMaxPerRoute(10);

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

	@SuppressWarnings("deprecation")
	private void recv_client(Socket raw, int id) {
		// wrap socket. if failed, just close socket and quit.
		SecTcpSocket s_client = null;
		try {
			s_client = new SecTcpSocket(raw);
		} catch (IOException e) {
			e.printStackTrace(log);
			IOUtils.closeQuietly(raw);
			return;
		}

		Socket raw_to_nn = null;
		InetSocketAddress dest_sockaddr = null;
		ConnectionContext cc = new ConnectionContext();
		OutputStream os_nn = null;
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

			String client_protocol = null;
			byte first_byte = (byte) byte1;
			if (first_byte == 5) {
				// socks5
				client_protocol = "socks5";
				dest_sockaddr = socks5(first_byte, is, s_client.os);
			} else if (first_byte == 4) {
				// socks4
				client_protocol = "socks4";
				dest_sockaddr = socks4(first_byte, is, s_client.os);
			} else if (first_byte == 0x43) {
				// 0x43 'C' http connect
				client_protocol = "connect";
				dest_sockaddr = http_connect(first_byte, is, s_client.os);
			} else if (first_byte == 0x47 || first_byte == 0x50 || first_byte == 0x48) {
				// 0x47 'G' http get
				// 0x50 'P' http post/put
				// 0x48 'H' http head
				client_protocol = "http";
				is.reset();
				http_other(is, s_client.os, raw);
				// cuz http proxy does not forward connection
				return;
			} else {
				s_client.close();
				throw new Exception("error unknown proxy protocol first_byte " + sctp.byte_to_string(first_byte));
			}

			raw_to_nn = create_connect_config_socket(dest_sockaddr, client_protocol);
			if (raw_to_nn == null) {
				// can't connect
				s_client.close();
				return;
			}

			// transfer data
			cc.dest = dest_sockaddr.toString();
			SecTcpSocket copy_of_s = s_client;
			Socket copy_of_raw_to_nn = raw_to_nn;
			scmt.execAsync("recv_" + id + "_nextnode", () -> recv_nextnode(copy_of_raw_to_nn, copy_of_s, cc));
			os_nn = raw_to_nn.getOutputStream();
			IOUtils.copy(is, os_nn, 32 * 1024);
		} catch (Exception e) {
			int cc_shutdown_sum;
			synchronized (cc) {
				cc_shutdown_sum = cc.shutdown_sum;
			}
			if (cc_shutdown_sum > 0) {
			} else if (e instanceof SocketTimeoutException) {
			} else if (e instanceof SocketException && (e.getMessage().equals("Connection reset")
					|| e.getMessage().equals("Software caused connection abort: socket write error")
					|| e.getMessage().equals("Software caused connection abort: recv failed")
					|| e.getMessage().equals("Connection reset by peer: socket write error"))) {
			} else {
				log.println("@" + dest_sockaddr + ", " + cc.shutdown_sum);
				e.printStackTrace(log);
			}
		} finally {
			if (os_nn != null)
				try {
					os_nn.flush();
				} catch (IOException e) {
				}
			if (raw_to_nn != null)
				try {
					raw_to_nn.shutdownOutput();
				} catch (IOException e) {
				}
			synchronized (cc) {
				s_client.close();
				IOUtils.closeQuietly(raw_to_nn);
				cc.shutdown_sum += 1;
			}
		}
	}

	@SuppressWarnings("deprecation")
	private void recv_nextnode(Socket raw_to_nn, SecTcpSocket s_client, ConnectionContext cc) {
		try {
			InputStream is_nn = raw_to_nn.getInputStream();
			IOUtils.copy(is_nn, s_client.os, 32 * 1024);
		} catch (Exception e) {
			int cc_shutdown_sum;
			synchronized (cc) {
				cc_shutdown_sum = cc.shutdown_sum;
			}
			if (cc_shutdown_sum > 0) {
			} else if (e instanceof SocketTimeoutException) {
			} else if (e instanceof SocketException && (e.getMessage().equals("Connection reset")
					|| e.getMessage().equals("Software caused connection abort: socket write error")
					|| e.getMessage().equals("Software caused connection abort: recv failed")
					|| e.getMessage().equals("Connection reset by peer: socket write error"))) {
			} else {
				log.println("@" + cc.dest + ", " + cc.shutdown_sum);
				e.printStackTrace(log);
			}
		} finally {
			try {
				s_client.os.flush();
			} catch (IOException e) {
			}
			try {
				s_client.getRaw().shutdownOutput();
			} catch (IOException e) {
			}
			synchronized (cc) {
				s_client.close();
				IOUtils.closeQuietly(raw_to_nn);
				cc.shutdown_sum += 2;
			}
		}
	}

	private InetSocketAddress socks5(byte first_byte, InputStream is1, OutputStream os1) throws Exception {
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

		// System.out.println("socks5 dest_sockaddr " + dest_sockaddr);

		buf = new byte[10];
		// reply socks version again
		buf[0] = 5;

		// reply status
		buf[1] = 0;

		// reserved
		buf[2] = 0;

		// bind address data, not used
		buf[3] = 1;
		os.write(buf);
		os.flush();

		return dest_sockaddr;
	}

	private InetSocketAddress socks4(byte first_byte, InputStream is1, OutputStream os1) throws Exception {
		@SuppressWarnings("unused")
		byte socks_version = first_byte;
		// System.out.println("socks_version " + sctp.byte_to_string(socks_version));
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

		buf = new byte[8];
		// reply null byte
		buf[0] = 0;

		// reply status
		buf[1] = 90;

		// 6 bytes non sense
		buf[3] = 1;
		os1.write(buf);
		os1.flush();

		InetSocketAddress dest_sockaddr;
		if (dest_addr != null)
			dest_sockaddr = new InetSocketAddress(dest_addr, dest_port);
		else
			dest_sockaddr = InetSocketAddress.createUnresolved(dest_domain, dest_port);

		log.println("socks4 dest_sockaddr " + dest_sockaddr);

		if (dest_sockaddr.isUnresolved())
			return dest_sockaddr;
		else
			throw new Exception("warning socks4 with ip destination is not allowed");
	}

	private InetSocketAddress http_connect(byte first_byte, InputStream is1, OutputStream os1) throws Exception {
		byte[] headers_buf = new byte[1024 * 1024];
		int pos = 0;
		headers_buf[pos++] = first_byte;
		while (true) {
			int b = is1.read();
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
		if (matcher.find()) {
			String dest_host = matcher.group(1);
			int port = Integer.parseInt(matcher.group(2));
			matcher = ip_regex.matcher(dest_host);
			InetSocketAddress dest_sockaddr;
			if (matcher.matches()) {
				dest_sockaddr = new InetSocketAddress(InetAddress.getByName(dest_host), port);
			} else {
				dest_sockaddr = InetSocketAddress.createUnresolved(dest_host, port);
			}

			// reply http 200 ok
			os1.write(httpconnect_okresponse);
			os1.flush();

			return dest_sockaddr;
		}
		log.println(headers);
		throw new Exception("error no host or not http connect");
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
					log.println("error http_conn.receiveRequestHeader " + e.getMessage());
					return;
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
				HttpHost target = new HttpHost(host, port, uri.getScheme());
				Future<BasicPoolEntry> future = connpool.lease(target, null);
				BasicPoolEntry poolEntry = future.get();
				poolEntry.updateExpiry(CONNECTION_POOL_TIMEOUT, TimeUnit.MILLISECONDS);
				try {
					HttpClientConnection http_conn_nn = poolEntry.getConnection();

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
					} else
						log.println("nc");

					if (keepAlive) {
					} else {
						log.println("c");
						connpool.release(poolEntry, keepAlive_nn);
						// return to close http_conn
						return;
					}
					connpool.release(poolEntry, keepAlive_nn);
				} catch (Exception e) {
					log.println(requestLine);
					e.printStackTrace(log);
					connpool.release(poolEntry, false);
					// return to close http_conn
					return;
				} finally {
					connpool.closeExpired();
				}
			} // end of while
		} catch (Exception e) {
			e.printStackTrace(log);
		}
	}

	/**
	 * return null means connection refused, or connect timed out, or can't resolve
	 * hostname
	 * 
	 * @param client_protocol
	 */
	private Socket create_connect_config_socket(InetSocketAddress dest_sockaddr, String client_protocol)
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
			log.println("connect with ip that resolved locally is dangerous for the server");
			throw new Exception("don't connect with ip");
		}

		if (nextNode.type == NextNode.Type.BAN) {
			throw new Exception("this address is banned");
		}
		if (nextNode.type == NextNode.Type.DIRECT) {
			// dns resolve
			InetAddress dest_addr = null;
			try {
				dest_addr = InetAddress.getByName(dest_sockaddr.getHostString());
			} catch (UnknownHostException e) {
				return null;
			}
			dest_sockaddr = new InetSocketAddress(dest_addr, dest_sockaddr.getPort());
		}
		Socket raw_to_nn = new Socket(nextNode.next_node);
		setSocketOptions(raw_to_nn);
		try {
			raw_to_nn.connect(dest_sockaddr, SOCKET_CONNECT_TIMEOUT);
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
		raw_to_nn.setSoTimeout(SOCKET_SO_TIMEOUT_NEXTPROXY);
		return raw_to_nn;
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
					throw new Exception("nn_table bad line " + line);
				if (!domain_regex.matcher(segments[0]).matches())
					throw new Exception("nn_table bad line " + line);
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

	private static class ConnectionContext {
		private int shutdown_sum;
		private String dest;
	}

	private static class NextNode {
		public enum Type {
			DIRECT, PROXY, BAN
		};

		public Type type;
		public Proxy next_node;

		public NextNode(Type type, Proxy next_node) {
			this.type = type;
			this.next_node = next_node;
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

	@SuppressWarnings("unused")
	private class SocketPool {

		private ArrayListValuedHashMap<InetSocketAddress, UnusedSocket> unused = new ArrayListValuedHashMap<>();
		private int timeout_ms;

		public SocketPool(int timeout_ms) {
			this.timeout_ms = timeout_ms;
			scmt.execAsync("pool_monitor", this::job_pool_monitor);
		}

		private void job_pool_monitor() {
			while (true) {
				scmt.sleep(1000 * 30);
				MapIterator<InetSocketAddress, UnusedSocket> iterator = unused.mapIterator();
				while (iterator.hasNext()) {
					iterator.next();
					UnusedSocket value = iterator.getValue();
					if (sct.time_ms() - value.lastUsedTime > timeout_ms)
						iterator.remove();
				}
			}
		}

		public Socket get(InetSocketAddress dest_sockaddr) throws Exception {
			synchronized (unused) {
				List<UnusedSocket> list = unused.get(dest_sockaddr);
				if (!list.isEmpty())
					return list.remove(list.size() - 1).s;
			}
			Socket new_socket = create_connect_config_socket(dest_sockaddr, "http");
			return new_socket;
		}

		public void giveback(InetSocketAddress dest_sockaddr, Socket s) {
			synchronized (unused) {
				unused.put(dest_sockaddr, new UnusedSocket(s, sct.time_ms()));
			}
		}
	}

	private static class UnusedSocket {
		public Socket s;
		public long lastUsedTime;

		public UnusedSocket(Socket s, long lastUsedTime) {
			this.s = s;
			this.lastUsedTime = lastUsedTime;
		}
	}

	private static class Settings {
		public String local_listen_ip;
		public int local_listen_port;
		public String backend_proxy_ip;
		public int backend_proxy_port;
	}

	private static long ip2long(String ip) {
		String[] parts = ip.split("\\.");
		long ipLong = 0;
		for (int i = 0; i < 4; i++)
			ipLong += Integer.parseInt(parts[i]) << (24 - (8 * i));
		return ipLong;
	}

	private static String long2ip(long l) {
		String ip = (l >> 24 & 0xff) + "." + (l >> 16 & 0xff) + "." + (l >> 8 & 0xff) + "." + (l & 0xff);
		return ip;
	}

	private static void setSocketOptions(Socket s) throws SocketException {
		s.setTcpNoDelay(true);
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
