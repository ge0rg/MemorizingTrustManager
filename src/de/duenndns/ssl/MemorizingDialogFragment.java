package de.duenndns.ssl;

/* MemorizingTrustManager - a TrustManager which asks the user about invalid
 *  certificates and memorizes their decision.
 *
 * Copyright (c) 2010 Georg Lukas <georg@op-co.de>
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


import android.app.AlertDialog;
import android.app.Dialog;
import android.content.DialogInterface;
import android.content.DialogInterface.OnCancelListener;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.os.Bundle;
import android.support.v4.app.DialogFragment;
import android.util.Log;

import de.duenndns.ssl.R;


public class MemorizingDialogFragment extends DialogFragment
		implements OnClickListener,OnCancelListener {
	final static String TAG = "MemorizingDialogFragment";

	int decisionId;
	String app;
	String cert;

	public static MemorizingDialogFragment getInstance(Intent i) {
		MemorizingDialogFragment f = new MemorizingDialogFragment();

		Bundle args = new Bundle();
		args.putString(MemorizingTrustManager.DECISION_INTENT_APP, i.getStringExtra(MemorizingTrustManager.DECISION_INTENT_APP));
		args.putInt(MemorizingTrustManager.DECISION_INTENT_ID, i.getIntExtra(MemorizingTrustManager.DECISION_INTENT_ID, MTMDecision.DECISION_INVALID));
		args.putString(MemorizingTrustManager.DECISION_INTENT_CERT, i.getStringExtra(MemorizingTrustManager.DECISION_INTENT_CERT));
		f.setArguments(args);
		return f;
	}

	@Override
	public Dialog onCreateDialog(Bundle savedInstanceState){
		Bundle args = getArguments();
		app = args.getString(MemorizingTrustManager.DECISION_INTENT_APP);
		decisionId = args.getInt(MemorizingTrustManager.DECISION_INTENT_ID);
		cert = args.getString(MemorizingTrustManager.DECISION_INTENT_CERT);

		return new AlertDialog.Builder(getActivity()).setTitle(R.string.mtm_accept_cert)
				.setMessage(cert)
				.setPositiveButton(R.string.mtm_decision_always, this)
				//.setNeutralButton(R.string.mtm_decision_once, this)
				.setNegativeButton(R.string.mtm_decision_abort, this)
				.setOnCancelListener(this)
				.create();
	}

	void sendDecision(int decision) {
		if(getActivity() == null)
			return;
		Log.d(TAG, "Sending decision to " + app + ": " + decision);
		Intent i = new Intent(MemorizingTrustManager.DECISION_INTENT + "/" + app);
		i.putExtra(MemorizingTrustManager.DECISION_INTENT_ID, decisionId);
		i.putExtra(MemorizingTrustManager.DECISION_INTENT_CHOICE, decision);
		getActivity().sendBroadcast(i);
		getDialog().dismiss();
	}

	// react on AlertDialog button press
	public void onClick(DialogInterface dialog, int btnId) {
		int decision;
		dialog.dismiss();
		switch (btnId) {
		case DialogInterface.BUTTON_POSITIVE:
			decision = MTMDecision.DECISION_ALWAYS;
			break;
		case DialogInterface.BUTTON_NEUTRAL:
			decision = MTMDecision.DECISION_ONCE;
			break;
		default:
			decision = MTMDecision.DECISION_ABORT;
		}
		sendDecision(decision);
	}

	public void onCancel(DialogInterface dialog) {
		sendDecision(MTMDecision.DECISION_ABORT);
	}
}
