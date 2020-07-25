package com.github.immueggpain.smartproxy;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.function.Consumer;

public class MutualTransit {

	private long expiry;
	private int busy = 0;

	public MutualTransit() {

	}

	@Override
	public String toString() {
		return String.format("%s", "");
	}

	public static void doIt(int bufSize, InputStream inA, OutputStream outA, InputStream inB, OutputStream outB,
			int timeout, ExecutorService exs) {
		MutualTransit contxt = new MutualTransit();
		Future<?> a2b = exs.submit(() -> contxt.oneWayTrans(bufSize, inA, outB, timeout, null));
		Future<?> b2a = exs.submit(() -> contxt.oneWayTrans(bufSize, inB, outA, timeout, null));

		// just wait ANY of 2 returns
		// then close abortively.
		// unless reason is EOF. like a.read() EOF.
		// then we do b.shutdownOutput(), then wait b.read, then also must be EOF, then
		// b.close(), then a close().
		// if so , no data lost
		// using close() directly may lose data, meaning orderly close from user results
		// in data loss, which is no good!

		try {
			a2b.get();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ExecutionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			b2a.get();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ExecutionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void oneWayTrans(int bufSize, InputStream in, OutputStream out, int timeout,
			Consumer<Object> notifyEndTrans) {
		byte[] buf = new byte[bufSize];
		Object reason = null;
		while (true) {
			int n;
			try {
				n = in.read(buf);
			} catch (SocketTimeoutException e) {
				if (isExpired(System.currentTimeMillis())) {
					reason = "timeout";
					break;
				} else {
					continue;
				}
			} catch (Throwable e) {
				reason = e;
				break;
			}

			// we just finished reading, update expiry
			justUpdateExpiry(System.currentTimeMillis() + timeout);

			// normal EOF
			if (n == -1) {
				reason = "EOF";
				break;
			}

			// begin to write, we'll update expiry when write is done. but during write, it
			// should not expire
			prepareUpdateExpiry();
			try {
				out.write(buf, 0, n);
			} catch (Throwable e) {
				reason = e;
				break;
			} finally {
				endUpdateExpiry(System.currentTimeMillis() + timeout);
			}
		}

		// the loop ended
		notifyEndTrans.accept(reason);
	}

	private synchronized boolean isExpired(final long now) {
		if (busy > 0)
			return false;
		else
			return now > expiry;
	}

	private synchronized void prepareUpdateExpiry() {
		busy++;
	}

	private synchronized void endUpdateExpiry(long newExpiry) {
		busy--;
		expiry = newExpiry;
	}

	private synchronized void justUpdateExpiry(long newExpiry) {
		expiry = newExpiry;
	}

}
