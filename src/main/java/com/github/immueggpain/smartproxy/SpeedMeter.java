package com.github.immueggpain.smartproxy;

import java.util.Collection;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicLong;

public class SpeedMeter {

	private AtomicLong atomRecv = new AtomicLong();
	private AtomicLong atomSend = new AtomicLong();
	private int reportInterval;
	private Collection<?> halfOpenPool;
	private long lastReportTime;

	public SpeedMeter(int reportInterval, Collection<?> halfOpenPool) {
		this.reportInterval = reportInterval;
		this.halfOpenPool = halfOpenPool;
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
				System.out.println(String.format(Locale.ROOT, "download: %.2f KB/s, upload: %.2f KB/s, half-open: %d",
						speedRecv, speedSend, halfOpenPool.size()));
			}
		} catch (Throwable e) {
			e.printStackTrace();
		}
	}

}
