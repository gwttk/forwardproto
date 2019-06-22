package com.github.immueggpain.smartproxy;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import org.apache.http.HttpClientConnection;
import org.apache.http.HttpConnectionFactory;
import org.apache.http.HttpHost;
import org.apache.http.annotation.Contract;
import org.apache.http.annotation.ThreadingBehavior;
import org.apache.http.config.ConnectionConfig;
import org.apache.http.config.SocketConfig;
import org.apache.http.impl.DefaultBHttpClientConnectionFactory;
import org.apache.http.impl.pool.BasicConnFactory;
import org.apache.http.pool.ConnFactory;

/**
 * modified version of {@link BasicConnFactory}. Modify BasicConnFactory cuz it
 * resolves hostname, we don't want that.
 */
@Contract(threading = ThreadingBehavior.IMMUTABLE_CONDITIONAL)
public class ModifiedConnFactory implements ConnFactory<HttpHost, HttpClientConnection> {

	private final SocketFactory plainfactory;
	private final SSLSocketFactory sslfactory;
	private final int connectTimeout;
	private final SocketConfig sconfig;
	private final HttpConnectionFactory<? extends HttpClientConnection> connFactory;

	/**
	 * @since 4.3
	 */
	public ModifiedConnFactory(final SocketFactory plainfactory, final SSLSocketFactory sslfactory,
			final int connectTimeout, final SocketConfig sconfig, final ConnectionConfig cconfig) {
		super();
		this.plainfactory = plainfactory;
		this.sslfactory = sslfactory;
		this.connectTimeout = connectTimeout;
		this.sconfig = sconfig != null ? sconfig : SocketConfig.DEFAULT;
		this.connFactory = new DefaultBHttpClientConnectionFactory(
				cconfig != null ? cconfig : ConnectionConfig.DEFAULT);
	}

	/**
	 * @since 4.3
	 */
	public ModifiedConnFactory(final int connectTimeout, final SocketConfig sconfig, final ConnectionConfig cconfig) {
		this(null, null, connectTimeout, sconfig, cconfig);
	}

	/**
	 * @since 4.3
	 */
	public ModifiedConnFactory(final SocketConfig sconfig, final ConnectionConfig cconfig) {
		this(null, null, 0, sconfig, cconfig);
	}

	/**
	 * @since 4.3
	 */
	public ModifiedConnFactory() {
		this(null, null, 0, SocketConfig.DEFAULT, ConnectionConfig.DEFAULT);
	}

	@Override
	public HttpClientConnection create(final HttpHost host) throws IOException {
		final String scheme = host.getSchemeName();
		Socket socket = null;
		if ("http".equalsIgnoreCase(scheme)) {
			socket = this.plainfactory != null ? this.plainfactory.createSocket() : new Socket();
		}
		if ("https".equalsIgnoreCase(scheme)) {
			socket = (this.sslfactory != null ? this.sslfactory : SSLSocketFactory.getDefault()).createSocket();
		}
		if (socket == null) {
			throw new IOException(scheme + " scheme is not supported");
		}
		final String hostname = host.getHostName();
		int port = host.getPort();
		if (port == -1) {
			if (host.getSchemeName().equalsIgnoreCase("http")) {
				port = 80;
			} else if (host.getSchemeName().equalsIgnoreCase("https")) {
				port = 443;
			}
		}
		socket.setSoTimeout(this.sconfig.getSoTimeout());
		if (this.sconfig.getSndBufSize() > 0) {
			socket.setSendBufferSize(this.sconfig.getSndBufSize());
		}
		if (this.sconfig.getRcvBufSize() > 0) {
			socket.setReceiveBufferSize(this.sconfig.getRcvBufSize());
		}
		socket.setTcpNoDelay(this.sconfig.isTcpNoDelay());
		final int linger = this.sconfig.getSoLinger();
		if (linger >= 0) {
			socket.setSoLinger(true, linger);
		}
		socket.setKeepAlive(this.sconfig.isSoKeepAlive());
		socket.connect(InetSocketAddress.createUnresolved(hostname, port), this.connectTimeout);
		return this.connFactory.createConnection(socket);
	}

}
