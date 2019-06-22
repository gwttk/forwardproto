package com.github.immueggpain.smartproxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.concurrent.Future;

import org.apache.http.ConnectionReuseStrategy;
import org.apache.http.HttpClientConnection;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.RequestLine;
import org.apache.http.config.MessageConstraints;
import org.apache.http.impl.DefaultBHttpClientConnection;
import org.apache.http.impl.DefaultBHttpServerConnection;
import org.apache.http.impl.DefaultConnectionReuseStrategy;
import org.apache.http.impl.DefaultHttpResponseFactory;
import org.apache.http.impl.entity.StrictContentLengthStrategy;
import org.apache.http.impl.pool.BasicConnFactory;
import org.apache.http.impl.pool.BasicConnPool;
import org.apache.http.impl.pool.BasicPoolEntry;
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
import org.apache.http.protocol.RequestTargetHost;
import org.apache.http.protocol.RequestUserAgent;
import org.apache.http.protocol.ResponseConnControl;
import org.apache.http.protocol.ResponseContent;
import org.apache.http.protocol.ResponseDate;
import org.apache.http.protocol.ResponseServer;
import org.apache.http.util.EntityUtils;

public class Http2socks {

	private static final int bufferSize = 0;
	private static final int fragmentSizeHint = 0;

	private final HttpRequestHandlerMapper singleHandlerMapper = new HttpRequestHandlerMapper() {
		@Override
		public HttpRequestHandler lookup(HttpRequest request) {
			return Http2socks.this::handleHttpReq;
		}
	};

	public Http2socks() {
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

		HttpProcessor httpproc = HttpProcessorBuilder.create().add(new ResponseDate())
				.add(new ResponseServer("MyServer-HTTP/1.1")).add(new ResponseContent()).add(new ResponseConnControl())
				.build();

		HttpContext context = HttpCoreContext.create();

		HttpService service = new HttpService(httpproc, DefaultConnectionReuseStrategy.INSTANCE,
				DefaultHttpResponseFactory.INSTANCE, singleHandlerMapper, null);

		do {
			try {
				service.handleRequest(connFromApp, context);
			} catch (IOException | HttpException e) {
				System.err.println("error connection from app broken, shutdown");
				try {
					connFromApp.shutdown(); // this will also close socket
				} catch (IOException ignore) {
				}
				e.printStackTrace();
			}
		} while (connFromApp.isOpen());
	}

	public void handleHttpReq(HttpRequest requestFromApp, HttpResponse responseToApp, HttpContext contextFromApp)
			throws HttpException, IOException {
		DefaultBHttpClientConnection connToDest = new DefaultBHttpClientConnection(bufferSize, fragmentSizeHint, null,
				null, MessageConstraints.DEFAULT, StrictContentLengthStrategy.INSTANCE,
				StrictContentLengthStrategy.INSTANCE, null, null);
		final HttpProcessor httpproc = HttpProcessorBuilder.create().add(new RequestContent())
				.add(new RequestTargetHost()).add(new RequestConnControl()).add(new RequestUserAgent("Test/1.1"))
				.add(new RequestExpectContinue(true)).build();

		final HttpRequestExecutor httpexecutor = new HttpRequestExecutor();

		final BasicConnPool pool = new BasicConnPool(new BasicConnFactory());
		pool.setDefaultMaxPerRoute(2);
		pool.setMaxTotal(2);

		RequestLine requestLine = requestFromApp.getRequestLine();
		String uri_str = requestLine.getUri();
		// fix because stupid tencent TIM include {} in urls
		uri_str = uri_str.replace("{", "%7B");
		uri_str = uri_str.replace("}", "%7D");
		URI uri;
		try {
			uri = new URI(uri_str);
		} catch (URISyntaxException e) {
			e.printStackTrace();
			return;
		}
		int port = uri.getPort() == -1 ? 80 : uri.getPort();
		String host = uri.getHost();

		HttpHost destination = new HttpHost(host, port);

		ConnectionReuseStrategy connStrategy = DefaultConnectionReuseStrategy.INSTANCE;
		try {
			Future<BasicPoolEntry> future = pool.lease(destination, null);

			boolean reusable = false;
			BasicPoolEntry entry = future.get();
			try {
				HttpClientConnection conn = entry.getConnection();
				HttpCoreContext contextToDest = HttpCoreContext.create();
				contextToDest.setTargetHost(destination);

				BasicHttpRequest request1 = new BasicHttpRequest("GET", "/");
				System.out.println(">> Request URI: " + request1.getRequestLine().getUri());

				httpexecutor.preProcess(request1, httpproc, contextToDest);
				HttpResponse response1 = httpexecutor.execute(request1, conn, contextToDest);
				httpexecutor.postProcess(response1, httpproc, contextToDest);

				System.out.println("<< Response: " + response1.getStatusLine());
				System.out.println(EntityUtils.toString(response1.getEntity()));

				reusable = connStrategy.keepAlive(response1, contextToDest);
			} finally {
				if (reusable) {
					System.out.println("Connection kept alive...");
				}
				pool.release(entry, reusable);
			}
		} catch (Exception ex) {
			System.out.println("Request to " + destination + " failed: " + ex.getMessage());
		}
	}
}
