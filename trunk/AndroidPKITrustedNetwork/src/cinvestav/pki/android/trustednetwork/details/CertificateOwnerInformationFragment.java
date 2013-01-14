/**
 *  Created on  : 20/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	A fragment representing a section of the app, in this fragment the decoded
 * certificate owner  is shown
 */
package cinvestav.pki.android.trustednetwork.details;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map.Entry;

import org.spongycastle.util.encoders.Hex;

import android.graphics.Typeface;
import android.os.Bundle;
import android.text.format.DateFormat;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.RelativeLayout;
import android.widget.TextView;
import cinvestav.android.pki.cryptography.cert.CertificateInformationKeys;
import cinvestav.android.pki.cryptography.utils.X509Utils;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.details.CertificateDecodedInformationFragment.OnClickCertificateDecodeListener;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

import com.actionbarsherlock.app.SherlockFragment;

/**
 * A fragment representing a section of the app, in this fragment the decoded
 * certificate owner information is shown
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 20/09/2012
 * @version 1.0
 */
public class CertificateOwnerInformationFragment extends SherlockFragment {

	/**
	 * Certificate position in the certificate view pager, to be used as
	 * reference when hide details is selected
	 */
	Integer certificatePosition;

	private java.text.DateFormat df;
	
	private static final String CERTIFICATE_POSITION = "CERTIFICATE_POSITION";

	public CertificateOwnerInformationFragment() {
		super();
		certificatePosition = 0;
	}

	public static CertificateOwnerInformationFragment newInstance(
			Integer certificatePosition) {
		CertificateOwnerInformationFragment f = new CertificateOwnerInformationFragment();
		f.setCertificatePosition(certificatePosition);
		return f;
	}

	/**
	 * @return the certificatePosition
	 */
	public Integer getCertificatePosition() {
		return certificatePosition;
	}

	/**
	 * @param certificatePosition
	 *            the certificatePosition to set
	 */
	public void setCertificatePosition(Integer certificatePosition) {
		this.certificatePosition = certificatePosition;
	}

	/**
	 * @return the df
	 */
	public java.text.DateFormat getDf() {
		return df;
	}

	/**
	 * @param df
	 *            the df to set
	 */
	public void setDf(java.text.DateFormat df) {
		this.df = df;
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		df = DateFormat.getDateFormat(getActivity().getApplicationContext());
		View rootView = inflater.inflate(
				R.layout.detail_certificate_fragment_decoded_owner, container,
				false);

		setRetainInstance(true);
		
		if (savedInstanceState != null) {
			certificatePosition = savedInstanceState
					.getInt(CERTIFICATE_POSITION);
		}

		X509Certificate certificate = ((CertificateDetailsActivity) getActivity())
				.getSelectedCertificate();
		
		X509Utils x509Utils = ((CertificateDetailsActivity) getActivity())
				.getX509Utils();

		TextView txtCertificateSubjectKeyId = ((TextView) rootView
				.findViewById(R.id.txtCertificateSubjectKeyId));
		txtCertificateSubjectKeyId.setText(new String(Hex.encode(x509Utils
				.getSubjectKeyIdentifier(certificate))).toUpperCase());

		RelativeLayout layout = (RelativeLayout) rootView
				.findViewById(R.id.layoutDetailCertificateOwnerInformation);

		// Get the certificateInformationMap from the certificate, and add each
		// element to the view
		HashMap<String, String> certificateInformationMap = x509Utils
				.getCertificateInformationMap(certificate);

		// Create the layout parameters object to be used for adding the
		// elements of the map

		Iterator<Entry<String, String>> it = certificateInformationMap
				.entrySet().iterator();
		int lastId = txtCertificateSubjectKeyId.getId();
		while (it.hasNext()) {
			Entry<String, String> pair = it.next();
			try {
				RelativeLayout.LayoutParams lpLbl = new RelativeLayout.LayoutParams(
						RelativeLayout.LayoutParams.WRAP_CONTENT,
						RelativeLayout.LayoutParams.WRAP_CONTENT);
				lpLbl.addRule(RelativeLayout.BELOW, lastId);// important
				lpLbl.setMargins(15, 0, 0, 0);

				TextView newLblTextView = new TextView(getActivity());
				newLblTextView.setLayoutParams(lpLbl);
				newLblTextView.setId(lastId + 1);
				newLblTextView.setText(CertificateInformationKeys
						.getKeyNameStr(pair.getKey(),
								PKITrustNetworkActivity.LAN));
				newLblTextView.setTextSize(15);
				layout.addView(newLblTextView);
				lastId = newLblTextView.getId();

				RelativeLayout.LayoutParams lpTxt = new RelativeLayout.LayoutParams(
						RelativeLayout.LayoutParams.WRAP_CONTENT,
						RelativeLayout.LayoutParams.WRAP_CONTENT);
				lpTxt.addRule(RelativeLayout.BELOW, lastId);
				lpTxt.setMargins(25, 0, 0, 0);

				TextView newTextView = new TextView(getActivity());
				newTextView.setLayoutParams(lpTxt);
				newTextView.setId(lastId + 1);
				newTextView.setText(pair.getValue());
				newTextView.setTextSize(15);
				newTextView.setTypeface(null, Typeface.BOLD);
				layout.addView(newTextView);
				lastId = newTextView.getId();

			} catch (IllegalArgumentException ex) {
				// If the key hasn't been found in the lookup table
			}
		}

		TextView lblImgSeeMoreDetails = ((TextView) rootView
				.findViewById(R.id.lblImgSeeMoreDetails));
		lblImgSeeMoreDetails.setOnClickListener(new View.OnClickListener() {

			@Override
			public void onClick(View v) {

				((OnClickCertificateDecodeListener) getActivity())
						.onSeeExtention(certificatePosition);
			}
		});
		RelativeLayout.LayoutParams lp = (RelativeLayout.LayoutParams) lblImgSeeMoreDetails
				.getLayoutParams();
		lp.addRule(RelativeLayout.BELOW, lastId);

		((TextView) rootView.findViewById(R.id.lblImgHideDetails))
				.setOnClickListener(new View.OnClickListener() {

					@Override
					public void onClick(View v) {

						((OnClickCertificateDecodeListener) getActivity())
								.onHideDetails(certificatePosition);
					}
				});

		return rootView;
	}
	
	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * android.support.v4.app.Fragment#onSaveInstanceState(android.os.Bundle)
	 */
	@Override
	public void onSaveInstanceState(Bundle outState) {
		super.onSaveInstanceState(outState);
		outState.putInt(CERTIFICATE_POSITION, certificatePosition);
	}
}
