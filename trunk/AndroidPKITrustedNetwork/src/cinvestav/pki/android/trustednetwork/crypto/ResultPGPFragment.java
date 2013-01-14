/**
 *  Created on  : 25/10/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Fragment that shows the verification result using the PGP+ method
 */
package cinvestav.pki.android.trustednetwork.crypto;

import java.text.DecimalFormat;

import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.SeekBar;
import android.widget.TextView;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

import com.actionbarsherlock.app.SherlockFragment;

/**
 * Fragment that shows the verification result using the PGP+ method
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 25/10/2012
 * @version 1.0
 */
public class ResultPGPFragment extends SherlockFragment {

	private Double trustLevel;
	private DecimalFormat decimalFormat;
	TextView txtTrustLevel;
	SeekBar seekCertificateTrustLevel;

	public ResultPGPFragment() {
		super();
	}

	/**
	 * @return the trustLevel
	 */
	public Double getTrustLevel() {
		return trustLevel;
	}

	/**
	 * @param trustLevel
	 *            the trustLevel to set between [-100,100]
	 */
	public void setTrustLevel(Double trustLevel) {
		this.trustLevel = trustLevel;
	}

	/**
	 * Create a new instance with empty values for the view
	 * 
	 * @return a new instance for this class filled out with empty values
	 */
	public static ResultPGPFragment newInstance() {
		ResultPGPFragment f = new ResultPGPFragment();
		f.setTrustLevel(0.0);
		return f;
	}

	/**
	 * Create a new instance with trust level values for the view
	 * 
	 * @param trustLevel
	 *            Trust level to be shown in the view, the value must be between [-100,100]
	 * @return a new instance for this class filled out with initial values
	 */
	public static ResultPGPFragment newInstance(Double trustLevel) {
		ResultPGPFragment f = new ResultPGPFragment();
		f.setTrustLevel(trustLevel);
		return f;
	}
	
	public void updateTrustLevel(Double trustLevel){
		Log.i(PKITrustNetworkActivity.TAG, "TrustLevel Seek: "+trustLevel.intValue());
		Double trustLvl = trustLevel / 10.0;
		txtTrustLevel.setText(decimalFormat.format(trustLvl));
		seekCertificateTrustLevel.setProgress(trustLevel.intValue()+100);
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		setRetainInstance(true);
		decimalFormat = new DecimalFormat("#.##");

		Log.i(PKITrustNetworkActivity.TAG, "TrustLevel: "+trustLevel);
		
		View rootView = inflater.inflate(R.layout.result_pgp, container, false);

		txtTrustLevel = (TextView) rootView
				.findViewById(R.id.txtTrustLevel);
		Double trustLvl = trustLevel / 10.0;
		txtTrustLevel.setText(decimalFormat.format(trustLvl));

		seekCertificateTrustLevel = (SeekBar) rootView
				.findViewById(R.id.seekCertificateTrustLevel);
		Log.i(PKITrustNetworkActivity.TAG, "TrustLevel Seek: "+trustLevel.intValue());
		
		seekCertificateTrustLevel.setProgress(0);
		seekCertificateTrustLevel.setMax(200);
		seekCertificateTrustLevel.setProgress(trustLevel.intValue()+100);	
		//seekCertificateTrustLevel.setProgress(trustLevel.intValue()+100);		
		seekCertificateTrustLevel.setEnabled(Boolean.FALSE);

		return rootView;
	}

}
