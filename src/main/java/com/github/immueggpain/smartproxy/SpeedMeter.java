package com.github.immueggpain.smartproxy;

import java.lang.ref.WeakReference;
import java.util.Collection;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicLong;

import com.github.immueggpain.smartproxy.Smartproxy.TunnelContext;

public class SpeedMeter {

	private AtomicLong atomRecv = new AtomicLong();
	private AtomicLong atomSend = new AtomicLong();
	private int reportInterval;
	private Collection<?> halfOpenPool;
	private Collection<WeakReference<TunnelContext>> onGoings;
	private long lastReportTime;
	private Smartproxy instance;

	public SpeedMeter(int reportInterval, Collection<?> halfOpenPool, Collection<WeakReference<TunnelContext>> onGoings,
			Smartproxy instance) {
		this.reportInterval = reportInterval;
		this.halfOpenPool = halfOpenPool;
		this.onGoings = onGoings;
		this.instance = instance;
		new Thread(this::run, "SpeedMeter").start();
	}

	/** call this everytime we receive data from server */
	public void countRecv(long n) {
		atomRecv.addAndGet(n);
	}

	/** call this everytime we send data from server */
	public void countSend(long n) {
		atomSend.addAndGet(n);
	}

	private void run() {
		try {
			while (true) {
				Thread.sleep(reportInterval);

				long now = System.currentTimeMillis();
				long duration = now - lastReportTime;
				double speedRecv = (double) atomRecv.getAndSet(0) / ((double) duration / 1000) / 1024;
				double speedSend = (double) atomSend.getAndSet(0) / ((double) duration / 1000) / 1024;
				lastReportTime = now;
				System.out.println(String.format(Locale.ROOT,
						"half-open: %2d, ongoing: %2d, upload: %6.1f KB/s, download: %7.1f KB/s", halfOpenPool.size(),
						onGoings.size(), speedSend, speedRecv));

				// print ongoings infos
				for (WeakReference<TunnelContext> weakReference : onGoings) {
					TunnelContext tc = weakReference.get();
					if (tc == null) {
						onGoings.remove(weakReference);
						continue;
					}
					if (!tc.isBroken && !tc.closing) {
						int receiveBufferSize = tc.cserver_s.getReceiveBufferSize();
						int sendBufferSize = tc.cserver_s.getSendBufferSize();
						// print if not match option values
						if ((instance.sndbuf_size != 0 && sendBufferSize != instance.sndbuf_size)
								|| (instance.rcvbuf_size != 0 && receiveBufferSize != instance.rcvbuf_size)) {
							String str = String.format("    %s %d/%d", tc.cserver_s.getInetAddress(), sendBufferSize,
									receiveBufferSize);
							System.out.println(str);
						}
					} else {
						onGoings.remove(weakReference);
					}
				}
			}
		} catch (Throwable e) {
			e.printStackTrace();
		}
	}

}
