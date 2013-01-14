/**
 *  Created on  : 31/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	A fragment representing a section of the app, in this fragment the decoded
 * certificate extensions is shown
 */
package cinvestav.pki.android.trustednetwork.details;

import java.security.cert.X509Certificate;
import java.util.List;

import android.os.Bundle;
import android.text.format.DateFormat;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import cinvestav.android.pki.cryptography.utils.X509Utils;
import cinvestav.android.pki.cryptography.utils.X509UtilsDictionary;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

import com.actionbarsherlock.app.SherlockFragment;

/**
 * A fragment representing a section of the app, in this fragment the decoded
 * certificate extensions information is shown
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 31/08/2012
 * @version 1.0
 */
public class CertificateExtensionsInformationFragment extends SherlockFragment {

	/**
	 * Certificate position in the certificate view pager, to be used as
	 * reference when hide details is selected
	 */
	Integer certificatePosition;

	/**
	 * Certificate Details Page in the certificate details view pager, to be
	 * used as reference when hiding the extensions view
	 */
	Integer certificateDetailsPage;
	
	private static final String CERTIFICATE_POSITION = "CERTIFICATE_POSITION";
	private static final String CERTIFICATE_DETAIL_PAGE = "CERTIFICATE_DETAIL_PAGE";

	private java.text.DateFormat df;

	public CertificateExtensionsInformationFragment() {
		super();
		certificatePosition = 0;
		certificateDetailsPage = 0;
	}

	public static CertificateExtensionsInformationFragment newInstance(
			Integer certificatePosition, Integer certificateDetailsPage) {
		CertificateExtensionsInformationFragment f = new CertificateExtensionsInformationFragment();
		f.setCertificatePosition(certificatePosition);
		f.setCertificateDetailsPage(certificateDetailsPage);
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
	 * @return the certificateDetailsPage
	 */
	public Integer getCertificateDetailsPage() {
		return certificateDetailsPage;
	}

	/**
	 * @param certificateDetailsPage
	 *            the certificateDetailsPage to set
	 */
	public void setCertificateDetailsPage(Integer certificateDetailsPage) {
		this.certificateDetailsPage = certificateDetailsPage;
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
				R.layout.detail_certificate_fragment_extension, container,
				false);

		setRetainInstance(true);
		
		if (savedInstanceState != null) {
			certificatePosition = savedInstanceState
					.getInt(CERTIFICATE_POSITION);
			certificateDetailsPage = savedInstanceState
					.getInt(CERTIFICATE_DETAIL_PAGE);
		}


		X509Certificate certificate = ((CertificateDetailsActivity) getActivity())
				.getSelectedCertificate();

		X509Utils x509Utils = ((CertificateDetailsActivity) getActivity())
				.getX509Utils();

		List<Integer> keyUsage = x509Utils.getKeyUsageList(certificate);
		String keyUsageStr = "";
		for (Integer keyUsageValue : keyUsage) {
			keyUsageStr += X509UtilsDictionary.getX509KeyUsageStr(
					keyUsageValue, PKITrustNetworkActivity.LAN);
			keyUsageStr += "\n";
		}
		((TextView) rootView.findViewById(R.id.txtCertificateKeyUsage))
				.setText(keyUsageStr);

		((TextView) rootView.findViewById(R.id.txtCertificateIsCA))
				.setText(certificate.getBasicConstraints() > 0 ? getString(R.string.lblIsCAYes)
						: getString(R.string.lblIsCANo));

		((TextView) rootView.findViewById(R.id.txtCertificatePathLength))
				.setText(Integer.toString(certificate.getBasicConstraints()));

		((TextView) rootView.findViewById(R.id.lblImgHideDetails))
				.setOnClickListener(new View.OnClickListener() {

					@Override
					public void onClick(View v) {

						((OnClickCertificateExtensionListener) getActivity())
								.onHideExtension(certificatePosition,
										certificateDetailsPage);
					}
				});

		return rootView;
	}

	/**
	 * Interface that handles the click on SeeMoreDetails button for
	 * {@link CertificateExtensionsInformationFragment}, this should be
	 * implemented by the Activity that holds the fragment
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	public interface OnClickCertificateExtensionListener {

		/**
		 * Hide the certificate decoded information
		 * 
		 * @param certificatePosition
		 *            Certificate position in the certificate view pager as
		 *            reference for return to the correct certificate
		 * @param certificateDetailsPage
		 *            Certificate Details Page position, in the certificate
		 *            details view pager, to be used as reference when hiding
		 *            the extensions view
		 */
		void onHideExtension(Integer certificatePosition,
				Integer certificateDetailsPage);
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
		outState.putInt(CERTIFICATE_DETAIL_PAGE, certificateDetailsPage);

	}
}
