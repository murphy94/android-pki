/**
 *  Created on  : 20/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	A fragment representing a section of the app, in this fragment the decoded
 * certificate issuer  is shown
 */
package cinvestav.pki.android.trustednetwork.details;

import java.security.cert.X509Certificate;

import org.spongycastle.util.encoders.Hex;

import android.os.Bundle;
import android.text.format.DateFormat;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.details.CertificateDecodedInformationFragment.OnClickCertificateDecodeListener;

import com.actionbarsherlock.app.SherlockFragment;

/**
 * A fragment representing a section of the app, in this fragment the decoded
 * certificate issuer information is shown
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 20/09/2012
 * @version 1.0
 */
public class CertificateIssuerInformationFragment extends SherlockFragment {

	/**
	 * Certificate position in the certificate view pager, to be used as
	 * reference when hide details is selected
	 */
	Integer certificatePosition;

	private java.text.DateFormat df;
	
	private static final String CERTIFICATE_POSITION = "CERTIFICATE_POSITION";

	public CertificateIssuerInformationFragment() {
		super();
		certificatePosition = 0;
	}

	public static CertificateIssuerInformationFragment newInstance(
			Integer certificatePosition) {
		CertificateIssuerInformationFragment f = new CertificateIssuerInformationFragment();
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
				R.layout.detail_certificate_fragment_decoded_issuer, container,
				false);

		setRetainInstance(true);
		
		if (savedInstanceState != null) {
			certificatePosition = savedInstanceState
					.getInt(CERTIFICATE_POSITION);
		}

		X509Certificate certificate = ((CertificateDetailsActivity) getActivity())
				.getSelectedCertificate();

		((TextView) rootView.findViewById(R.id.txtCertificateIssuerDN))
				.setText(certificate.getIssuerDN().getName());

		((TextView) rootView.findViewById(R.id.txtCertificateAuthKeyId))
				.setText(new String(Hex
						.encode(((CertificateDetailsActivity) getActivity())
								.getX509Utils().getAuthorityKeyIdentifier(
										certificate))).toUpperCase());

		((TextView) rootView.findViewById(R.id.lblImgSearchCertificate))
				.setOnClickListener(new View.OnClickListener() {

					@Override
					public void onClick(View v) {
						((OnClickCertificateIssuerListener) getActivity())
								.onSearchIssuerCertificate(certificatePosition);
					}
				});

		((TextView) rootView.findViewById(R.id.lblImgSeeMoreDetails))
				.setOnClickListener(new View.OnClickListener() {

					@Override
					public void onClick(View v) {

						((OnClickCertificateDecodeListener) getActivity())
								.onSeeExtention(certificatePosition);
					}
				});

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

	/**
	 * Interface that handles the click on SeeMoreDetails button for
	 * {@link CertificateIssuerInformationFragment}, this should be implemented
	 * by the Activity that holds the fragment
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	public interface OnClickCertificateIssuerListener {
		/**
		 * Search Issuer Certificate in the data base
		 * 
		 * @param certificatePosition
		 *            Certificate position in the certificate view pager as
		 *            reference for return to the correct certificate
		 */
		void onSearchIssuerCertificate(Integer certificatePosition);

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
