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

	public SpeedMeter(int reportInterval, Collection<?> halfOpenPool,
			Collection<WeakReference<TunnelContext>> onGoings) {
		this.reportInterval = reportInterval;
		this.halfOpenPool = halfOpenPool;
		this.onGoings = onGoings;
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
				System.out.println(
						String.format(Locale.ROOT, "download: %.2f KB/s, upload: %.2f KB/s, half-open: %d, ongoing: %d",
								speedRecv, speedSend, halfOpenPool.size(), onGoings.size()));

				// print ongoings infos
				for (WeakReference<TunnelContext> weakReference : onGoings) {
					TunnelContext tc = weakReference.get();
					if (tc == null) {
						onGoings.remove(weakReference);
						continue;
					}
					if (!tc.isBroken && !tc.closing) {
						int receiveBufferSize = tc.cserver_s.getReceiveBufferSize();
						String str = String.format("    %s %d", tc.cserver_s.getInetAddress(), receiveBufferSize);
						System.out.println(str);
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
