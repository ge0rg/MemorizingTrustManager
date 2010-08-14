/* MemorizingTrustManager - a TrustManager which asks the user about invalid
 *  certificates and memorizes their decision.
 *
 * Copyright (c) 2010 Georg Lukas <georg@op-co.de>
 *
 * MemorizingTrustManager.java contains the actual trust manager and interface
 * code to create a MemorizingActivity and obtain the results.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package de.duenndns.ssl;

import android.app.Activity;
import android.app.Application;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.Service;
import android.app.AlertDialog;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.Uri;
import android.util.Log;
import android.os.Handler;

import java.io.File;
import java.security.cert.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.HashMap;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * A X509 trust manager implementation which asks the user about invalid
 * certificates and memorizes their decision.
 * <p>
 * The certificate validity is checked using the system default X509
 * TrustManager, creating a query Dialog if the check fails.
 * <p>
 * <b>WARNING:</b> This only works if a dedicated thread is used for
 * opening sockets!
 */
public class MemorizingTrustManager implements X509TrustManager {
	final static String TAG = "MemorizingTrustManager";
	final static String DECISION_INTENT = "de.duenndns.ssl.DECISION";
	final static String DECISION_INTENT_ID     = DECISION_INTENT + ".decisionId";
	final static String DECISION_INTENT_CERT   = DECISION_INTENT + ".cert";
	final static String DECISION_INTENT_CHOICE = DECISION_INTENT + ".decisionChoice";
	private final static int NOTIFICATION_ID = 100509;

	static String KEYSTORE_DIR = "KeyStore";
	static String KEYSTORE_FILE = "KeyStore.bks";

	Context master;
	NotificationManager notificationManager;
	private static int decisionId = 0;
	private static HashMap<Integer,MTMDecision> openDecisions = new HashMap();
	private static BroadcastReceiver decisionReceiver;

	Handler masterHandler;
	private File keyStoreFile;
	private KeyStore appKeyStore;
	private X509TrustManager defaultTrustManager;
	private X509TrustManager appTrustManager;

	/** Creates an instance of the MemorizingTrustManager class.
	 *
	 * @param m the Activity to be used for displaying Dialogs.
	 */
	private MemorizingTrustManager(Application app, Context m) {
		master = m;
		masterHandler = new Handler();
		notificationManager = (NotificationManager)master.getSystemService(Context.NOTIFICATION_SERVICE);

		File dir = app.getDir(KEYSTORE_DIR, Context.MODE_PRIVATE);
		keyStoreFile = new File(dir + File.separator + KEYSTORE_FILE);

		appKeyStore = loadAppKeyStore();
		defaultTrustManager = getTrustManager(null);
		appTrustManager = getTrustManager(appKeyStore);

		if (decisionReceiver == null) {
			decisionReceiver = new BroadcastReceiver() {
				public void onReceive(Context ctx, Intent i) { interactResult(i); }
			};
			master.registerReceiver(decisionReceiver, new IntentFilter(DECISION_INTENT));
		}
	}

	/** Creates an instance of the MemorizingTrustManager class.
	 *
	 * @param m the Activity to be used for displaying Dialogs.
	 */
	private MemorizingTrustManager(Activity m) {
		this(m.getApplication(), m);
	}


	/** Creates an instance of the MemorizingTrustManager class.
	 *
	 * @param m the Service to be used for displaying Dialogs.
	 */
	private MemorizingTrustManager(Service m) {
		this(m.getApplication(), m);
	}

	/**
	 * Returns a X509TrustManager list containing a new instance of
	 * TrustManagerFactory.
	 *
	 * This function is meant for convenience only. You can use it
	 * as follows to integrate TrustManagerFactory for HTTPS sockets:
	 *
	 * <pre>
	 *     SSLContext sc = SSLContext.getInstance("TLS");
	 *     sc.init(null, MemorizingTrustManager.getInstanceList(this),
	 *         new java.security.SecureRandom());
	 *     HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
	 * </pre>
	 * @param c the Activity to be used for displaying Dialogs.
	 */
	public static X509TrustManager[] getInstanceList(Activity c) {
		return new X509TrustManager[] { new MemorizingTrustManager(c) };
	}

	/**
	 * Returns a X509TrustManager list containing a new instance of
	 * TrustManagerFactory.
	 *
	 * This is equivalent to getInstanceList(Activity), but for Services.
	 */
	public static X509TrustManager[] getInstanceList(Service s) {
		return new X509TrustManager[] { new MemorizingTrustManager(s) };
	}

	/**
	 * Changes the path for the KeyStore file.
	 *
	 * The actual filename relative to the app's directory will be
	 * <code>app_<i>dirname</i>/<i>filename</i></code>.
	 *
	 * @param dirname directory to store the KeyStore.
	 * @param filename file name for the KeyStore.
	 */
	public static void setKeyStoreFile(String dirname, String filename) {
		KEYSTORE_DIR = dirname;
		KEYSTORE_FILE = filename;
	}

	X509TrustManager getTrustManager(KeyStore ks) {
		try {
			TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509");
			tmf.init(ks);
			for (TrustManager t : tmf.getTrustManagers()) {
				if (t instanceof X509TrustManager) {
					return (X509TrustManager)t;
				}
			}
		} catch (Exception e) {
			// Here, we are covering up errors. It might be more useful
			// however to throw them out of the constructor so the
			// embedding app knows something went wrong.
			Log.e(TAG, "getTrustManager(" + ks + ")", e);
		}
		return null;
	}

	KeyStore loadAppKeyStore() {
		KeyStore ks;
		try {
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
		} catch (KeyStoreException e) {
			Log.e(TAG, "getAppKeyStore()", e);
			return null;
		}
		try {
			ks.load(null, null);
			ks.load(new java.io.FileInputStream(keyStoreFile), "MTM".toCharArray());
		} catch (java.io.FileNotFoundException e) {
			Log.i(TAG, "getAppKeyStore(" + keyStoreFile + ") - file does not exist");
		} catch (Exception e) {
			Log.e(TAG, "getAppKeyStore(" + keyStoreFile + ")", e);
		}
		return ks;
	}

	void storeCert(X509Certificate[] chain) {
		// add all certs from chain to appKeyStore
		try {
			for (X509Certificate c : chain)
				appKeyStore.setCertificateEntry(c.getSubjectDN().toString(), c);
		} catch (KeyStoreException e) {
			Log.e(TAG, "storeCert(" + chain + ")", e);
			return;
		}
		
		// reload appTrustManager
		appTrustManager = getTrustManager(appKeyStore);

		// store KeyStore to file
		try {
			java.io.FileOutputStream fos = new java.io.FileOutputStream(keyStoreFile);
			appKeyStore.store(fos, "MTM".toCharArray());
			fos.close();
		} catch (Exception e) {
			Log.e(TAG, "storeCert(" + keyStoreFile + ")", e);
		}
	}

	public void checkClientTrusted(X509Certificate[] chain, String authType)
		throws CertificateException
	{
		Log.d(TAG, "checkClientTrusted(" + chain + ", " + authType + ")");
		try {
			appTrustManager.checkClientTrusted(chain, authType);
		} catch (CertificateException _) {
			try {
				defaultTrustManager.checkClientTrusted(chain, authType);
			} catch (CertificateException e) {
				interact(chain, authType, e);
			}
		}
	}

	public void checkServerTrusted(X509Certificate[] chain, String authType)
		throws CertificateException
	{
		Log.d(TAG, "checkServerTrusted(" + chain + ", " + authType + ")");
		try {
			appTrustManager.checkServerTrusted(chain, authType);
		} catch (CertificateException _) {
			try {
				defaultTrustManager.checkServerTrusted(chain, authType);
			} catch (CertificateException e) {
				interact(chain, authType, e);
			}
		}
	}

	public X509Certificate[] getAcceptedIssuers()
	{
		Log.d(TAG, "getAcceptedIssuers()");
		return defaultTrustManager.getAcceptedIssuers();
	}

	private int createDecisionId(MTMDecision d) {
		int myId;
		synchronized(openDecisions) {
			myId = decisionId;
			openDecisions.put(myId, d);
			decisionId += 1;
		}
		return myId;
	}

	private String certChainMessage(final X509Certificate[] chain, CertificateException cause) {
		Throwable e = cause;
		Log.d(TAG, "certChainMessage for " + e);
		while (e.getCause() != null)
			e = e.getCause();
		StringBuffer si = new StringBuffer(e.getLocalizedMessage());
		for (X509Certificate c : chain) {
			si.append("\n\n");
			si.append(c.getSubjectDN().toString());
			si.append(" (");
			si.append(c.getIssuerDN().toString());
			si.append(")");
		}
		return si.toString();
	}

	void startActivityNotification(Intent intent) {
		Notification n = new Notification(android.R.drawable.ic_lock_lock, "SSL Certificate", System.currentTimeMillis());
		PendingIntent call = PendingIntent.getActivity(master, 0, intent, 0);
		n.setLatestEventInfo(master.getApplicationContext(), "Title", "Text", call);
		n.flags |= Notification.FLAG_AUTO_CANCEL;

		notificationManager.notify(NOTIFICATION_ID, n);
	}

	void interact(final X509Certificate[] chain, String authType, CertificateException cause)
		throws CertificateException
	{
		/* prepare the MTMDecision blocker object */
		MTMDecision choice = new MTMDecision();
		final int myId = createDecisionId(choice);
		final String certMessage = certChainMessage(chain, cause);

		masterHandler.post(new Runnable() {
			public void run() {
				Intent ni = new Intent(master, MemorizingActivity.class);
				ni.setData(Uri.parse(MemorizingTrustManager.class.getName() + "/" + myId));
				ni.putExtra(DECISION_INTENT_ID, myId);
				ni.putExtra(DECISION_INTENT_CERT, certMessage);

				try {
					master.startActivity(ni);
				} catch (Exception e) {
					Log.e(TAG, "startActivity: " + e);
					startActivityNotification(ni);
				}
			}
		});

		Log.d(TAG, "openDecisions: " + openDecisions);
		Log.d(TAG, "waiting on " + myId);
		try {
			synchronized(choice) { choice.wait(); }
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		Log.d(TAG, "finished wait on " + myId + ": " + choice.state);
		switch (choice.state) {
		case MTMDecision.DECISION_ALWAYS:
			storeCert(chain);
		case MTMDecision.DECISION_ONCE:
			break;
		default:
			throw (cause);
		}
	}

	public static void interactResult(Intent i) {
		int decisionId = i.getIntExtra(DECISION_INTENT_ID, MTMDecision.DECISION_INVALID);
		int choice = i.getIntExtra(DECISION_INTENT_CHOICE, MTMDecision.DECISION_INVALID);
		Log.d(TAG, "interactResult: " + decisionId + " chose " + choice);
		Log.d(TAG, "openDecisions: " + openDecisions);

		MTMDecision d;
		synchronized(openDecisions) {
			 d = openDecisions.get(decisionId);
			 openDecisions.remove(decisionId);
		}
		synchronized(d) {
			d.state = choice;
			d.notify();
		}
	}

}
