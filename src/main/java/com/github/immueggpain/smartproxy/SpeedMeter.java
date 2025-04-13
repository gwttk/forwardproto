package com.github.immueggpain.smartproxy;

import java.lang.ref.WeakReference;
import java.util.Collection;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicLong;

import com.github.immueggpain.smartproxy.Smartproxy.TunnelContext;
import com.github.immueggpain.smartproxy.Smartproxy.TunnelPool;

public class SpeedMeter {

	private AtomicLong atomRecv = new AtomicLong();
	private AtomicLong atomSend = new AtomicLong();
	private int reportInterval;
	private TunnelPool halfOpenPool;
	private Collection<WeakReference<TunnelContext>> onGoings;
	private long lastReportTime;

	public SpeedMeter(int reportInterval, TunnelPool halfOpenPool, Collection<WeakReference<TunnelContext>> onGoings,
			Smartproxy instance) {
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
				System.out.println(String.format(Locale.ROOT,
						"half-open: %2d, ongoing: %2d, upload: %6.1f KB/s, download: %7.1f KB/s, latency: %3d",
						halfOpenPool.getCurrentSize(), onGoings.size(), speedSend, speedRecv,
						halfOpenPool.getCurrentLatency()));

				// print ongoings infos
				for (WeakReference<TunnelContext> weakReference : onGoings) {
					TunnelContext tc = weakReference.get();
					if (tc == null) {
						onGoings.remove(weakReference);
						continue;
					}
					if (tc.isBroken || tc.closing)
						onGoings.remove(weakReference);
				}
			}
		} catch (Throwable e) {
			e.printStackTrace();
		}
	}

}
