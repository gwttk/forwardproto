package com.github.immueggpain.smartproxy;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collection;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import org.apache.commons.io.IOUtils;

public class SmartproxyServer {

	public static void main(String[] args) {
		try {
			System.out.println("server test run");
			new SmartproxyServer().run();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void run() throws Exception {
		InputStream certFile = Files.newInputStream(Paths.get("cert.pem"));
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
	}

}
