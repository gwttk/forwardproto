package com.github.immueggpain.smartproxy;

import java.io.IOException;
import java.net.URI;
import java.util.Locale;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.MethodNotSupportedException;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpRequestHandler;

public class BaseHandler implements HttpRequestHandler {

	@Override
	public void handle(HttpRequest request, HttpResponse response, HttpContext context)
			throws HttpException, IOException {
		String method = request.getRequestLine().getMethod().toUpperCase(Locale.ROOT);
		String uriStr = request.getRequestLine().getUri();
		URI uri = URI.create(uriStr);
		String webPath = uri.getPath();

		System.out.println(String.format("==> http request: %s %s", method, webPath));

		try {
			if (method.equals("GET"))
				handleGet(request, response, context, webPath);
			else if (method.equals("POST"))
				handlePost(request, response, context, webPath);
			else if (method.equals("HEAD"))
				handleHead(request, response, context, webPath);
			else if (method.equals("OPTIONS"))
				handleOptions(request, response, context, webPath);
			else
				handleOtherMethod(request, response, context, webPath, method);
		} catch (Throwable e) {
			// if there is an exception, return http 500 with stack trace as content
			String bodyString = ExceptionUtils.getStackTrace(e);
			StringEntity entity = new StringEntity(bodyString, ContentType.create("text/plain", "UTF-8"));
			response.setStatusCode(HttpStatus.SC_INTERNAL_SERVER_ERROR);
			response.setEntity(entity);
		}

		System.out.println(String.format("<== http %s", response.getStatusLine()));
	}

	public void handleGet(HttpRequest request, HttpResponse response, HttpContext context, String webPath)
			throws Exception {
		throw new MethodNotSupportedException("GET method not supported");
	}

	public void handlePost(HttpRequest request, HttpResponse response, HttpContext context, String webPath)
			throws Exception {
		throw new MethodNotSupportedException("POST method not supported");
	}

	public void handleHead(HttpRequest request, HttpResponse response, HttpContext context, String webPath)
			throws Exception {
		throw new MethodNotSupportedException("HEAD method not supported");
	}

	public void handleOptions(HttpRequest request, HttpResponse response, HttpContext context, String webPath)
			throws Exception {
		throw new MethodNotSupportedException("OPTIONS method not supported");
	}

	public void handleOtherMethod(HttpRequest request, HttpResponse response, HttpContext context, String webPath,
			String method) throws Exception {
		throw new MethodNotSupportedException(method + " method not supported");
	}

}
