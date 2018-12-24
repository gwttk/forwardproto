package com.github.immueggpain.smartproxy;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
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
import com.github.immueggpain.smartproxy.Launcher.Settings;

public class SmartproxyServer {

	private static final int PORT = 9039;
	private static final int SO_TIMEOUT = 1000 * 60;
	private static final int CONNECT_TIMEOUT = 1000 * 10;
	private static final int BUF_SIZE = 1024 * 16;

	private byte[] realpswd = new byte[64];

	public void run(Settings settings) throws Exception {
		byte[] bytes = settings.password.getBytes(StandardCharsets.UTF_8);
		System.arraycopy(bytes, 0, realpswd, 0, bytes.length);

		InputStream certFile = Files.newInputStream(Paths.get("fullchain.pem"));
		InputStream privateKeyFile = Files.newInputStream(Paths.get("privkey.pem"));

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

		SSLServerSocket ss = (SSLServerSocket) ssf.createServerSocket();

		// config ss here
		ss.setEnabledCipherSuites(new String[] { "TLS_RSA_WITH_AES_128_GCM_SHA256" });
		ss.setPerformancePreferences(0, 0, 1);

		ss.bind(new InetSocketAddress(PORT));

		while (true) {
			Socket s = ss.accept();

			// config s here
			s.setSoTimeout(SO_TIMEOUT);

			scmt.execAsync("multi-thread-handle-conn", () -> handleConnection(s));
		}
	}

	private void handleConnection(Socket s) {
		try {
			DataInputStream is = new DataInputStream(s.getInputStream());
			DataOutputStream os = new DataOutputStream(s.getOutputStream());
			byte[] pswd = new byte[64];
			is.readFully(pswd);
			if (!Arrays.equals(pswd, realpswd)) {
				// abortive close socket
				s.setSoLinger(true, 0);
				s.close();
				System.out.println("someone is scanning you, do something!");
			}

			String dest_hostname = is.readUTF();
			int dest_port = is.readUnsignedShort();
			System.out.println("client request connect " + dest_hostname + ":" + dest_port);
			try {
				InetAddress.getByName(dest_hostname);
			} catch (UnknownHostException e) {
				os.writeByte(1);
				os.close();
				return;
			}
			InetSocketAddress dest_sockaddr = new InetSocketAddress(dest_hostname, dest_port);

			Socket cdest_s = new Socket();
			cdest_s.connect(dest_sockaddr, CONNECT_TIMEOUT);
			os.writeByte(0);

			InputStream cdest_is = cdest_s.getInputStream();
			OutputStream cdest_os = cdest_s.getOutputStream();

			scmt.execAsync("multi-thread-handle-conn2", () -> handleConnection2(cdest_is, os));

			byte[] buf = new byte[BUF_SIZE];
			while (true) {
				int n = is.read(buf);
				if (n == -1)
					break;
				cdest_os.write(buf, 0, n);
			}

			cdest_s.close();
			s.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void handleConnection2(InputStream is, OutputStream os) {
		try {
			byte[] buf = new byte[BUF_SIZE];
			while (true) {
				int n = is.read(buf);
				if (n == -1)
					break;
				os.write(buf, 0, n);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
