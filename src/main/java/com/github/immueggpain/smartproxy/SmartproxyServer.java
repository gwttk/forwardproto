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

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import org.apache.commons.io.IOUtils;

import com.github.immueggpain.common.scmt;
import com.github.immueggpain.common.sct;
import com.github.immueggpain.smartproxy.Launcher.ServerSettings;

public class SmartproxyServer {

	public static final int SVRERRCODE_OK = 0x00; // request granted
	public static final int SVRERRCODE_FAIL = 0x01; // general failure
	public static final int SVRERRCODE_NOTALLOW = 0x02; // connection not allowed by ruleset
	public static final int SVRERRCODE_NETWORK = 0x03; // network unreachable
	public static final int SVRERRCODE_HOST = 0x04; // host unreachable
	public static final int SVRERRCODE_REFUSED = 0x05; // connection refused by destination host
	public static final int SVRERRCODE_TTL = 0x06; // TTL expired
	public static final int SVRERRCODE_COMMAND = 0x07; // command not supported / protocol error
	public static final int SVRERRCODE_ADDR = 0x08; // address type not supported

	private static final int CLIENT_SO_TIMEOUT = 1000 * 60;
	private static final int DEST_SO_TIMEOUT = 1000 * 60;
	private static final int CONNECT_TIMEOUT = 1000 * 10;
	private static final int BUF_SIZE = 1024 * 16;

	private byte[] realpswd = new byte[64];

	public void run(ServerSettings settings) throws Exception {
		byte[] bytes = settings.password.getBytes(StandardCharsets.UTF_8);
		System.arraycopy(bytes, 0, realpswd, 0, bytes.length);

		// init SSL
		InputStream certFile = Files.newInputStream(Paths.get(settings.cert));
		InputStream privateKeyFile = Files.newInputStream(Paths.get(settings.private_key));

		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		Collection<? extends Certificate> certificates = cf.generateCertificates(certFile);

		String privateKeyPEM = IOUtils.toString(privateKeyFile, StandardCharsets.UTF_8);
		String privateKeyBase64 = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----", "")
				.replace("-----END PRIVATE KEY-----", "").replaceAll("\\s+", "");
		byte[] privateKeyPKCS8 = Base64.getDecoder().decode(privateKeyBase64);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyPKCS8));

		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(null);
		ks.setKeyEntry("nonce", privateKey, "123456".toCharArray(), certificates.toArray(new Certificate[0]));

		KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
		kmf.init(ks, "123456".toCharArray());
		KeyManager[] keyManagers = kmf.getKeyManagers();

		SSLContext context = SSLContext.getInstance("TLSv1.2");
		context.init(keyManagers, null, null);

		SSLServerSocketFactory ssf = context.getServerSocketFactory();

		try (SSLServerSocket ss = (SSLServerSocket) ssf.createServerSocket()) {

			// config ss here
			ss.setEnabledCipherSuites(new String[] { "TLS_RSA_WITH_AES_128_GCM_SHA256" });
			ss.setPerformancePreferences(0, 0, 1);

			ss.bind(new InetSocketAddress(settings.server_port));

			while (true) {
				SSLSocket sclient_s = (SSLSocket) ss.accept();

				try {
					// config s here
					sclient_s.setSoTimeout(CLIENT_SO_TIMEOUT);
				} catch (Exception e) {
					// you know, socket is already in error, we don't care if it makes more errors
					Util.abortiveCloseSocket(sclient_s);
					throw e;
				}

				scmt.execAsync("multi-thread-handle-conn", () -> handleConnection(sclient_s));
			}
		}
	}

	private void handleConnection(Socket sclient_s) {
		try {
			DataInputStream is = new DataInputStream(sclient_s.getInputStream());
			DataOutputStream os = new DataOutputStream(sclient_s.getOutputStream());

			// authn this connection
			{
				byte[] pswd = new byte[64];
				try {
					is.readFully(pswd);
				} catch (Exception e) {
					System.out.println("someone is scanning you, do something!");
					Util.abortiveCloseSocket(sclient_s);
					return;
				}
				if (!Arrays.equals(pswd, realpswd)) {
					System.out.println("someone is scanning you, do something!!");
					Util.abortiveCloseSocket(sclient_s);
					return;
				}
			}

			String dest_hostname = is.readUTF();
			int dest_port = is.readUnsignedShort();
			System.out.println("client request connect " + dest_hostname + ":" + dest_port);

			// do dns
			InetAddress dest_addr;
			try {
				dest_addr = InetAddress.getByName(dest_hostname);
			} catch (UnknownHostException e) {
				System.err.println("unknown host " + dest_hostname);
				// send error code & orderly release connection
				os.writeByte(SVRERRCODE_HOST);
				Util.orderlyCloseSocket(sclient_s);
				return;
			}

			// validate dest_addr & dest_port
			InetSocketAddress dest_sockaddr;
			try {
				dest_sockaddr = new InetSocketAddress(dest_addr, dest_port);
			} catch (Exception e) {
				e.printStackTrace();
				// send error code & orderly release connection
				os.writeByte(SVRERRCODE_HOST);
				Util.orderlyCloseSocket(sclient_s);
				return;
			}

			// create cdest(client to destination) socket
			Socket cdest_s = new Socket();

			// connect cdest
			try {
				cdest_s.connect(dest_sockaddr, CONNECT_TIMEOUT);
			} catch (SocketTimeoutException e) {
				// send error code & orderly release connection
				os.writeByte(SVRERRCODE_HOST);
				Util.orderlyCloseSocket(sclient_s);
				Util.abortiveCloseSocket(cdest_s);
				return;
			} catch (Exception e) {
				e.printStackTrace();
				// send error code & orderly release connection
				os.writeByte(SVRERRCODE_FAIL);
				Util.orderlyCloseSocket(sclient_s);
				Util.abortiveCloseSocket(cdest_s);
				return;
			}

			cdest_s.setSoTimeout(DEST_SO_TIMEOUT);
			InputStream cdest_is = cdest_s.getInputStream();
			OutputStream cdest_os = cdest_s.getOutputStream();
			TunnelContext contxt = new TunnelContext(dest_sockaddr.toString(), cdest_s, sclient_s);

			// everything seems ok, will tunnel data
			os.writeByte(SVRERRCODE_OK);

			Thread handleConn2 = scmt.execAsync("multi-thread-handle-conn2",
					() -> handleConnection2(contxt, cdest_is, os));

			// this try makes sure that thread is joined
			try {
				byte[] buf = new byte[BUF_SIZE];
				while (true) {
					int n;
					try {
						n = is.read(buf);
					} catch (SocketTimeoutException e) {
						// timeout cuz read no data
						// if we are writing, then continue
						// if we are not writing, just RST close connection
						if (sct.time_ms() - contxt.lastWriteToClient < CLIENT_SO_TIMEOUT)
							continue;
						else {
							// prepare RST close
							// break transfering loop, close() is at finally block
							cdest_s.setSoLinger(true, 0);
							sclient_s.setSoLinger(true, 0);
							break;
						}
					}
					if (n == -1)
						break;
					cdest_os.write(buf, 0, n);
					contxt.lastWriteToDest = sct.time_ms();
				}
			} finally {
				handleConn2.join();
			}
		} catch (Throwable e) {
			System.err.println("there shouldn't be any exception here");
			e.printStackTrace();
		}
	}

	private void handleConnection2(TunnelContext contxt, InputStream cdest_is, OutputStream sclient_os) {
		try {
			byte[] buf = new byte[BUF_SIZE];
			while (true) {
				int n;
				try {
					n = cdest_is.read(buf);
				} catch (SocketTimeoutException e) {
					// timeout cuz read no data
					// if we are writing, then continue
					// if we are not writing, just RST close connection
					if (sct.time_ms() - contxt.lastWriteToDest < DEST_SO_TIMEOUT)
						continue;
					else {
						// prepare RST close
						// break transfering loop, close() is at parent thread
						// there is a chance that setSoLinger will throw java.net.SocketException:
						// Socket Closed. I guess it means the remote peer has closed the connection?
						// cuz we are sure that we only close socket on this side after thread join
						Util.cullException(() -> contxt.cdest_s.setSoLinger(true, 0), SocketException.class, "");
						if (!contxt.sclient_s.isClosed())
							contxt.sclient_s.setSoLinger(true, 0);
						break;
					}
				}
				if (n == -1)
					break;
				sclient_os.write(buf, 0, n);
				contxt.lastWriteToClient = sct.time_ms();
			}
		} catch (Exception e) {
			System.err.println("@" + contxt.dest_name);
			e.printStackTrace();
			// if there is exception, use RST close
			try {
				contxt.cdest_s.setSoLinger(true, 0);
			} catch (SocketException e1) {
				e1.printStackTrace();
			}
			try {
				contxt.sclient_s.setSoLinger(true, 0);
			} catch (SocketException e1) {
				e1.printStackTrace();
			}
		}
	}

	private static class TunnelContext {
		public volatile long lastWriteToClient = 0;
		public volatile long lastWriteToDest = 0;
		public final String dest_name;
		public Socket cdest_s;
		public Socket sclient_s;

		public TunnelContext(String dest_name, Socket cdest_s, Socket sclient_s) {
			this.dest_name = dest_name;
			this.cdest_s = cdest_s;
			this.sclient_s = sclient_s;
		}
	}

	@SuppressWarnings("unused")
	private static class Connection {

		private Socket s;
		private boolean closed1 = false;
		private boolean closed2 = false;

		public Connection(Socket s) {
			this.s = s;

		}

		public synchronized void close1() throws IOException {
			if (closed1 && closed2)
				return;
			closed1 = true;
			if (closed1 && closed2)
				close();
		}

		public synchronized void close2() throws IOException {
			if (closed1 && closed2)
				return;
			closed2 = true;
			if (closed1 && closed2)
				close();
		}

		private void close() throws IOException {
			s.close();
		}
	}

}
