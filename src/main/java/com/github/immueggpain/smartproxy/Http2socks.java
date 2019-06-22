package com.github.immueggpain.smartproxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import javax.net.SocketFactory;

import org.apache.http.ConnectionReuseStrategy;
import org.apache.http.HttpClientConnection;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.HttpVersion;
import org.apache.http.RequestLine;
import org.apache.http.StatusLine;
import org.apache.http.config.ConnectionConfig;
import org.apache.http.config.MessageConstraints;
import org.apache.http.config.SocketConfig;
import org.apache.http.impl.DefaultBHttpServerConnection;
import org.apache.http.impl.DefaultConnectionReuseStrategy;
import org.apache.http.impl.DefaultHttpResponseFactory;
import org.apache.http.impl.entity.StrictContentLengthStrategy;
import org.apache.http.impl.pool.BasicConnFactory;
import org.apache.http.impl.pool.BasicConnPool;
import org.apache.http.impl.pool.BasicPoolEntry;
import org.apache.http.message.BasicHttpEntityEnclosingRequest;
import org.apache.http.message.BasicHttpRequest;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpCoreContext;
import org.apache.http.protocol.HttpProcessor;
import org.apache.http.protocol.HttpProcessorBuilder;
import org.apache.http.protocol.HttpRequestExecutor;
import org.apache.http.protocol.HttpRequestHandler;
import org.apache.http.protocol.HttpRequestHandlerMapper;
import org.apache.http.protocol.HttpService;
import org.apache.http.protocol.RequestConnControl;
import org.apache.http.protocol.RequestContent;
import org.apache.http.protocol.RequestExpectContinue;
import org.apache.http.protocol.ResponseConnControl;
import org.apache.http.protocol.ResponseContent;

public class Http2socks {

	private static final int bufferSize = 32 * 1024;
	private static final int fragmentSizeHint = 32 * 1024;

	private PrintWriter log;
	private final HttpRequestHandlerMapper singleHandlerMapper = new HttpRequestHandlerMapper() {
		@Override
		public HttpRequestHandler lookup(HttpRequest request) {
			return Http2socks.this::handleHttpReq;
		}
	};
	private SocketFactory socketFactoryToSocks;

	public Http2socks(Proxy socksProxy, PrintWriter log) {
		this.log = log;
		this.socketFactoryToSocks = new SocketFactory() {
			@Override
			public Socket createSocket() throws IOException {
				return new Socket(socksProxy);
			}

			@Override
			public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
					throws IOException {
				Socket socket = new Socket(socksProxy);
				socket.bind(new InetSocketAddress(localAddress, localPort));
				socket.connect(new InetSocketAddress(address, port));
				return socket;
			}

			@Override
			public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
					throws IOException, UnknownHostException {
				Socket socket = new Socket(socksProxy);
				socket.bind(new InetSocketAddress(localHost, localPort));
				socket.connect(InetSocketAddress.createUnresolved(host, port));
				return socket;
			}

			@Override
			public Socket createSocket(InetAddress host, int port) throws IOException {
				Socket socket = new Socket(socksProxy);
				socket.connect(new InetSocketAddress(host, port));
				return socket;
			}

			@Override
			public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
				Socket socket = new Socket(socksProxy);
				socket.connect(InetSocketAddress.createUnresolved(host, port));
				return socket;
			}
		};
	}

	public void handleConnection(InputStream is, OutputStream os, Socket socket) {
		DefaultBHttpServerConnection connFromApp = new DefaultBHttpServerConnection(bufferSize, fragmentSizeHint, null,
				null, MessageConstraints.DEFAULT, StrictContentLengthStrategy.INSTANCE,
				StrictContentLengthStrategy.INSTANCE, null, null) {
			@Override
			protected InputStream getSocketInputStream(Socket socket) {
				return is;
			}

			@Override
			protected OutputStream getSocketOutputStream(Socket socket) {
				return os;
			}
		};

		try {
			connFromApp.bind(socket);
		} catch (IOException e) {
			throw new RuntimeException("this should be impossible", e);
		}

		HttpProcessor httpprocForApp = HttpProcessorBuilder.create().add(new ResponseContent())
				.add(new ResponseConnControl()).build();

		HttpContext context = HttpCoreContext.create();

		HttpService service = new HttpService(httpprocForApp, DefaultConnectionReuseStrategy.INSTANCE,
				DefaultHttpResponseFactory.INSTANCE, singleHandlerMapper, null);

		do {
			try {
				service.handleRequest(connFromApp, context);
			} catch (IOException | HttpException e) {
				log.println("error connection from app broken, shutdown");
				e.printStackTrace(log);
				try {
					connFromApp.shutdown(); // this will also close socket
				} catch (IOException ignore) {
				}
			}
		} while (connFromApp.isOpen());
	}

	private void handleHttpReq(HttpRequest requestFromApp, HttpResponse responseToApp, HttpContext contextFromApp)
			throws HttpException, IOException {
		final HttpProcessor httpprocForDest = HttpProcessorBuilder.create().add(new RequestContent())
				.add(new RequestConnControl()).add(new RequestExpectContinue(true)).build();

		final HttpRequestExecutor httpexecutor = new HttpRequestExecutor();

		final BasicConnPool pool = new BasicConnPool(
				new BasicConnFactory(socketFactoryToSocks, null, 0, SocketConfig.DEFAULT, ConnectionConfig.DEFAULT));
		pool.setDefaultMaxPerRoute(5);
		pool.setMaxTotal(50);

		RequestLine requestLine = requestFromApp.getRequestLine();
		log.println("http2socks " + requestLine);
		String uri_str = requestLine.getUri();
		URI uri;
		try {
			uri = new URI(uri_str);
		} catch (URISyntaxException e) {
			log.println("error parse URI from app broken, return http 400");
			e.printStackTrace(log);
			responseToApp.setStatusCode(HttpStatus.SC_BAD_REQUEST);
			return;
		}
		int port = uri.getPort() == -1 ? 80 : uri.getPort();
		String host = uri.getHost();
		String newuri = uri.getRawPath();
		if (uri.getRawQuery() != null)
			newuri += "?" + uri.getRawQuery();

		HttpHost destination = new HttpHost(host, port);

		ConnectionReuseStrategy connStrategy = DefaultConnectionReuseStrategy.INSTANCE;
		Future<BasicPoolEntry> future = pool.lease(destination, null);
		boolean reusable = false;
		BasicPoolEntry entry;
		try {
			entry = future.get();
		} catch (InterruptedException | ExecutionException e) {
			log.println(String.format("error can't get conn of %s from http client conn pool, return http 502",
					destination));
			e.printStackTrace(log);
			responseToApp.setStatusCode(HttpStatus.SC_BAD_GATEWAY);
			return;
		}
		try {
			HttpClientConnection conn = entry.getConnection();
			HttpCoreContext contextToDest = HttpCoreContext.create();
			contextToDest.setTargetHost(destination);

			// create requestToDest based on requestFromApp
			BasicHttpRequest requestToDest;
			if (requestFromApp instanceof HttpEntityEnclosingRequest) {
				BasicHttpEntityEnclosingRequest requestToDest_ = new BasicHttpEntityEnclosingRequest(
						requestLine.getMethod(), newuri, HttpVersion.HTTP_1_1);
				requestToDest_.setEntity(((HttpEntityEnclosingRequest) requestFromApp).getEntity());
				requestToDest = requestToDest_;
			} else {
				requestToDest = new BasicHttpRequest(requestLine.getMethod(), newuri, HttpVersion.HTTP_1_1);
			}
			requestToDest.setHeaders(requestFromApp.getAllHeaders());

			httpexecutor.preProcess(requestToDest, httpprocForDest, contextToDest);
			HttpResponse responseFromDest = httpexecutor.execute(requestToDest, conn, contextToDest);
			httpexecutor.postProcess(responseFromDest, httpprocForDest, contextToDest);

			reusable = connStrategy.keepAlive(responseFromDest, contextToDest);

			StatusLine statusLine = responseFromDest.getStatusLine();
			responseToApp.setStatusLine(requestFromApp.getProtocolVersion(), statusLine.getStatusCode(),
					statusLine.getReasonPhrase());
			responseToApp.setHeaders(responseFromDest.getAllHeaders());
			responseToApp.setEntity(responseFromDest.getEntity());
		} finally {
			if (reusable) {
				log.println("Connection kept alive...");
			}
			pool.release(entry, reusable);
		}
	}
}
