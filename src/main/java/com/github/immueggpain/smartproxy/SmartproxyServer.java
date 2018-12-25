package com.github.immueggpain.smartproxy;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
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
import org.apache.commons.io.IOUtils;

import com.github.immueggpain.common.scmt;
import com.github.immueggpain.common.sct;
import com.github.immueggpain.smartproxy.Launcher.ServerSettings;

public class SmartproxyServer {

	private static final int PORT = 9039;
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

			ss.bind(new InetSocketAddress(PORT));

			while (true) {
				Socket sclient_s = ss.accept();

				try {
					// config s here
					sclient_s.setSoTimeout(CLIENT_SO_TIMEOUT);
				} catch (Exception e) {
					try {
						sclient_s.close();
					} catch (Exception ignore) {
						// you know, s is already in error, we don't care if it makes more errors
					}
					throw e;
				}

				scmt.execAsync("multi-thread-handle-conn", () -> handleConnection(sclient_s));
			}
		}
	}

	private void handleConnection(Socket sclient_s) {
		try {
			// authn this connection
			DataInputStream is = new DataInputStream(sclient_s.getInputStream());
			DataOutputStream os = new DataOutputStream(sclient_s.getOutputStream());
			byte[] pswd = new byte[64];
			is.readFully(pswd);
			if (!Arrays.equals(pswd, realpswd)) {
				// abortive close socket, close() is at finally block
				sclient_s.setSoLinger(true, 0);
				System.out.println("someone is scanning you, do something!");
			}

			String dest_hostname = is.readUTF();
			int dest_port = is.readUnsignedShort();
			System.out.println("client request connect " + dest_hostname + ":" + dest_port);

			// do dns
			InetAddress dest_addr;
			try {
				dest_addr = InetAddress.getByName(dest_hostname);
			} catch (UnknownHostException e) {
				e.printStackTrace();
				// send error code & orderly release connection
				os.writeByte(1);
				os.close();
				return;
			}

			// validate dest_addr & dest_port
			InetSocketAddress dest_sockaddr;
			try {
				dest_sockaddr = new InetSocketAddress(dest_addr, dest_port);
			} catch (Exception e) {
				e.printStackTrace();
				// send error code & orderly release connection
				os.writeByte(2);
				os.close();
				return;
			}

			try (Socket cdest_s = new Socket()) { // I'll just take that new Socket() won't throw
				// connect cdest(client to destination) socket
				try {
					cdest_s.connect(dest_sockaddr, CONNECT_TIMEOUT);
				} catch (SocketTimeoutException e) {
					// send error code & orderly release connection
					os.writeByte(3);
					os.close();
					return;
				} catch (Exception e) {
					e.printStackTrace();
					// send error code & orderly release connection
					os.writeByte(4);
					os.close();
					return;
				}

				cdest_s.setSoTimeout(DEST_SO_TIMEOUT);
				InputStream cdest_is = cdest_s.getInputStream();
				OutputStream cdest_os = cdest_s.getOutputStream();
				TunnelContext contxt = new TunnelContext(dest_sockaddr.toString());

				// everything seems ok, will tunnel data
				os.writeByte(0);

				Thread handleConn2 = scmt.execAsync("multi-thread-handle-conn2",
						() -> handleConnection2(contxt, cdest_is, os));

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
							sclient_s.setSoLinger(true, 0);
							break;
						}
					}
					if (n == -1)
						break;
					try {
						cdest_os.write(buf, 0, n);
					} catch (Exception e) {
						e.printStackTrace();
					}
				}

				handleConn2.join();
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				sclient_s.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private void handleConnection2(TunnelContext contxt, InputStream cdest_is, OutputStream sclient_os) {
		try {
			byte[] buf = new byte[BUF_SIZE];
			while (true) {
				int n = cdest_is.read(buf);
				if (n == -1)
					break;
				sclient_os.write(buf, 0, n);
				contxt.lastWriteToClient = sct.time_ms();
			}
		} catch (Exception e) {
			System.err.println("@" + contxt.dest_name);
			e.printStackTrace();
		}
	}

	private static class TunnelContext {
		public volatile long lastWriteToClient = 0;
		public final String dest_name;

		public TunnelContext(String dest_name) {
			this.dest_name = dest_name;
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
