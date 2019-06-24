package com.github.immueggpain.smartproxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import javax.net.SocketFactory;
import org.apache.http.ConnectionClosedException;
import org.apache.http.ConnectionReuseStrategy;
import org.apache.http.Header;
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
import org.apache.http.impl.pool.BasicConnPool;
import org.apache.http.impl.pool.BasicPoolEntry;
import org.apache.http.message.BasicHttpEntityEnclosingRequest;
import org.apache.http.message.BasicHttpRequest;
import org.apache.http.protocol.HTTP;
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

	// timeouts
	public static final int toHttpWithDest = 60 * 1000;
	public static final int toH2sReadFromSocks = toHttpWithDest + 10 * 1000;
	private static final int toH2sConnectThruSocks = 20 * 1000;

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
	private ModifiedConnFactory connFactory;
	private BasicConnPool pool;

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
		SocketConfig socketConfig = SocketConfig.custom().setTcpNoDelay(true).setSoTimeout(toH2sReadFromSocks).build();
		// modify BasicConnFactory cuz it resolves hostname, we don't want that
		connFactory = new ModifiedConnFactory(socketFactoryToSocks, null, toH2sConnectThruSocks, socketConfig,
				ConnectionConfig.DEFAULT);

		pool = new BasicConnPool(connFactory);
		pool.setDefaultMaxPerRoute(6);
		pool.setMaxTotal(60);
		new Thread(this::connPoolCleaner, "h2s-connPoolCleaner").start();
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

		// ResponseContent needs to overwrite Content-Length and Transfer-Encoding,
		// cuz response from dest may not be ok with app,
		// e.g. different http version, different keep-alive etc.
		HttpProcessor httpprocForApp = HttpProcessorBuilder.create().add(new ResponseContent(true))
				.add(new ResponseConnControl()).build();

		HttpContext contextFromAppPerConn = HttpCoreContext.create();

		HttpService service = new HttpService(httpprocForApp, DefaultConnectionReuseStrategy.INSTANCE,
				DefaultHttpResponseFactory.INSTANCE, singleHandlerMapper, null);

		do {
			try {
				service.handleRequest(connFromApp, contextFromAppPerConn);
			} catch (IOException | HttpException e) {
				// since we don't throw anything in handleHttpReq(),
				// exceptions here can only be related to conn from app!

				if (e instanceof ConnectionClosedException && e.getMessage().equals("Client closed connection")) {
					// this is normal, client is just closing conn without sending next request.
					// this is when remote tcp peer properly closed conn.
					try {
						connFromApp.close(); // this will also close socket
					} catch (IOException ignore) {
					}
				} else if (e instanceof SocketTimeoutException && e.getMessage().equals("Read timed out")) {
					// socket timed out, close conn from app
					try {
						connFromApp.close(); // this will also close socket
					} catch (IOException ignore) {
					}
				} else if (e instanceof SocketException && e.getMessage().equals("Connection reset")
						&& excpWhenParsHead(e)) {
					// this is normal, client is just closing conn without sending next request.
					try {
						connFromApp.shutdown(); // this will also close socket
					} catch (IOException ignore) {
					}
				} else if (e instanceof SocketException
						&& e.getMessage().equals("Software caused connection abort: recv failed")
						&& excpWhenParsHead(e)) {
					// this is normal, client is just closing conn without sending next request.
					// this is when remote tcp peer abortively closed conn.
					try {
						connFromApp.shutdown(); // this will also close socket
					} catch (IOException ignore) {
					}
				} else {
					log.println("error connection from app broken, shutdown");
					e.printStackTrace(log);
					try {
						connFromApp.shutdown(); // this will also close socket
					} catch (IOException ignore) {
					}
				}
			} finally {
				// release conn to dest after conn from app has finished reading
				BasicPoolEntry entry = (BasicPoolEntry) contextFromAppPerConn.getAttribute("pool.entry");
				Boolean reusable = (Boolean) contextFromAppPerConn.getAttribute("pool.reusable");
				if (entry != null && reusable != null) {
					entry.updateExpiry(toHttpWithDest, TimeUnit.MILLISECONDS);
					pool.release(entry, reusable);
				}
			}
		} while (connFromApp.isOpen());
	}

	private void handleHttpReq(HttpRequest requestFromApp, HttpResponse responseToApp,
			HttpContext contextFromAppPerConn) throws HttpException, IOException {
		// RequestContent needs to overwrite Content-Length and Transfer-Encoding,
		// cuz request from app may not be ok with dest,
		// e.g. different http version, different keep-alive etc.
		final HttpProcessor httpprocForDest = HttpProcessorBuilder.create().add(new RequestContent(true))
				.add(new RequestConnControl()).add(new RequestExpectContinue(true)).build();

		final HttpRequestExecutor httpexecutor = new HttpRequestExecutor();

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
		String rawAuthority = uri.getRawAuthority();
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

		// used to release entry after responseToApp finishes
		contextFromAppPerConn.setAttribute("pool.entry", entry);
		contextFromAppPerConn.setAttribute("pool.reusable", reusable);

		HttpClientConnection conn = entry.getConnection();
		HttpCoreContext contextToDestPerMsg = HttpCoreContext.create();
		contextToDestPerMsg.setTargetHost(destination);

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
		requestToDest.setHeader(HTTP.TARGET_HOST, rawAuthority);

		HttpResponse responseFromDest;
		try {
			httpexecutor.preProcess(requestToDest, httpprocForDest, contextToDestPerMsg);
			responseFromDest = httpexecutor.execute(requestToDest, conn, contextToDestPerMsg);
			httpexecutor.postProcess(responseFromDest, httpprocForDest, contextToDestPerMsg);
		} catch (Exception e) {
			log.println(String.format("error when execute request to dest, return http 502"));
			log.println("error request host: " + destination);
			printHttpRequest(log, requestFromApp, "request from app");
			printHttpRequest(log, requestToDest, "request to dest");
			e.printStackTrace(log);
			responseToApp.setStatusCode(HttpStatus.SC_BAD_GATEWAY);
			return;
		}

		reusable = connStrategy.keepAlive(responseFromDest, contextToDestPerMsg);
		contextFromAppPerConn.setAttribute("pool.reusable", reusable);

		StatusLine statusLine = responseFromDest.getStatusLine();
		responseToApp.setStatusLine(requestFromApp.getProtocolVersion(), statusLine.getStatusCode(),
				statusLine.getReasonPhrase());
		responseToApp.setHeaders(responseFromDest.getAllHeaders());
		responseToApp.setEntity(responseFromDest.getEntity());
	}

	private void connPoolCleaner() {
		while (true) {
			try {
				Thread.sleep(10 * 1000);
			} catch (InterruptedException e) {
				log.println("error conn pool cleaner thread interrupted");
				e.printStackTrace(log);
			}
			pool.closeExpired();
		}
	}

	private static void printHttpRequest(PrintWriter log, HttpRequest request, String prefix) {
		log.println("error " + prefix + " line is: " + request.getRequestLine());
		log.println("error " + prefix + " request headers: ");
		for (Header header : request.getAllHeaders()) {
			log.println("        " + header);
		}
	}

	private static boolean excpWhenParsHead(Throwable e) {
		StackTraceElement ste = e.getStackTrace()[10];
		if (ste.getFileName().equals("DefaultBHttpServerConnection.java") && ste.getLineNumber() == 129) {
			return true;
		} else
			return false;
	}
}
