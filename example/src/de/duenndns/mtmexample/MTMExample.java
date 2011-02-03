package de.duenndns.mtmexample;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.Window;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.TextView;

import java.net.URL;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.HttpsURLConnection;

import de.duenndns.ssl.MemorizingTrustManager;

/**
 * Example to demonstrate the use of MemorizingTrustManager on HTTPS
 * sockets.
 */
public class MTMExample extends Activity implements OnClickListener
{
	TextView content;
	CheckBox verifyhost;
	HostnameVerifier defaultverifier;
	EditText urlinput;
	String text;
	Handler hdlr;

	/** Creates the Activity and registers a MemorizingTrustManager. */
	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);
		setContentView(R.layout.mtmexample);


		// set up gui elements
		findViewById(R.id.connect).setOnClickListener(this);
		content = (TextView)findViewById(R.id.content);
		urlinput = (EditText)findViewById(R.id.url);
		verifyhost = (CheckBox)findViewById(R.id.verifyhost);

		// register handler for background thread
		hdlr = new Handler();

		// Here, the MemorizingTrustManager is activated for HTTPS
		try {
			// set location of the keystore
			MemorizingTrustManager.setKeyStoreFile("private", "sslkeys.bks");

			// register MemorizingTrustManager for HTTPS
			SSLContext sc = SSLContext.getInstance("TLS");
			sc.init(null, MemorizingTrustManager.getInstanceList(this),
					new java.security.SecureRandom());
			HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
			defaultverifier = HttpsURLConnection.getDefaultHostnameVerifier();

			// disable redirects to reduce possible confusion
			HttpsURLConnection.setFollowRedirects(false);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/** Updates the screen content from a background thread. */
	void setText(final String s, final boolean progress) {
		text = s;
		hdlr.post(new Runnable() {
			public void run() {
				content.setText(s);
				setProgressBarIndeterminateVisibility(progress);
			}
		});
	}

	/** Spawns a new thread connecting to the specified URL.
	 * The result of the request is displayed on the screen.
	 * @param urlString a HTTPS URL to connect to.
	 */
	void connect(final String urlString) {
		// register the right hostname verifier
		if (verifyhost.isChecked()) {
			HttpsURLConnection.setDefaultHostnameVerifier(defaultverifier);
		} else {
			HttpsURLConnection.setDefaultHostnameVerifier(new org.apache.http.conn.ssl.AllowAllHostnameVerifier());
		}
		new Thread() {
			public void run() {
				try {
					URL u = new URL(urlString);
					HttpsURLConnection c = (HttpsURLConnection)u.openConnection();
					c.connect();
					setText("" + c.getResponseCode() + " "
							+ c.getResponseMessage(), false);
					c.disconnect();
				} catch (Exception e) {
					setText(e.toString(), false);
					e.printStackTrace();
				}
			}
		}.start();
	}

	/** Reacts on the connect Button press. */
	@Override
	public void onClick(View view) {
		String url = urlinput.getText().toString();
		setText("Loading " + url, true);
		setProgressBarIndeterminateVisibility(true);
		connect(url);
	}
}
