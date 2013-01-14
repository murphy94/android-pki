/**
 *  Created on  : 31/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	A fragment representing a section of the app, in this fragment the decoded
 * certificate custom extensions information is shown
 */
package cinvestav.pki.android.trustednetwork.details;

import java.security.cert.X509Certificate;

import android.os.Bundle;
import android.text.format.DateFormat;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import cinvestav.android.pki.cryptography.utils.X509Utils;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.details.CertificateExtensionsInformationFragment.OnClickCertificateExtensionListener;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

import com.actionbarsherlock.app.SherlockFragment;

/**
 * A fragment representing a section of the app, in this fragment the decoded
 * certificate custom extensions information is shown
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 31/08/2012
 * @version 1.0
 */
public class CertificateCustomExtensionsInformationFragment extends
		SherlockFragment {

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

	public CertificateCustomExtensionsInformationFragment() {
		super();
		certificatePosition = 0;
		certificateDetailsPage = 0;
	}

	public static CertificateCustomExtensionsInformationFragment newInstance(
			Integer certificatePosition, Integer certificateDetailsPage) {
		CertificateCustomExtensionsInformationFragment f = new CertificateCustomExtensionsInformationFragment();
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
				R.layout.detail_certificate_fragment_extension_custom,
				container, false);

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

		Log.i(PKITrustNetworkActivity.TAG, "CERTIFICATE CUSTOM EXTENSION");

		// Get the extension from the certificate
		String aux = x509Utils.getExtensionDeviceId(certificate);
		// Set the extension value in the corresponding textView or a extension
		// not found message
		((TextView) rootView.findViewById(R.id.txtCertificateDeviceId))
				.setText(aux != null ? aux
						: getString(R.string.lblExtensionNotFound));

		// Get the extension from the certificate
		aux = x509Utils.getExtensionSignDeviceId(certificate);
		// Set the extension value in the corresponding textView or a extension
		// not found message
		((TextView) rootView.findViewById(R.id.txtCertificateSignDeviceId))
				.setText(aux != null ? aux
						: getString(R.string.lblExtensionNotFound));

		// Get the extension from the certificate
		aux = x509Utils.getExtensionCertificateType(certificate,
				PKITrustNetworkActivity.LAN);
		// Set the extension value in the corresponding textView or a extension
		// not found message
		((TextView) rootView.findViewById(R.id.txtCertificateType))
				.setText(aux != null ? aux
						: getString(R.string.lblExtensionNotFound));

		// Get the extension from the certificate
		aux = x509Utils.getExtensionUserId(certificate);
		// Set the extension value in the corresponding textView or a extension
		// not found message
		((TextView) rootView.findViewById(R.id.txtCertificateUserId))
				.setText(aux != null ? aux
						: getString(R.string.lblExtensionNotFound));

		// Get the extension from the certificate
		aux = x509Utils.getExtensionUserPermissionId(certificate);
		// Set the extension value in the corresponding textView or a extension
		// not found message
		((TextView) rootView.findViewById(R.id.txtCertificateUserPermission))
				.setText(aux != null ? aux
						: getString(R.string.lblExtensionNotFound));

		// Get the extension from the certificate
		aux = x509Utils.getExtensionIdentificationDocument(certificate);
		// Set the extension value in the corresponding textView or a extension
		// not found message
		((TextView) rootView
				.findViewById(R.id.txtCertificateIdentificationDocument))
				.setText(aux != null ? aux
						: getString(R.string.lblExtensionNotFound));

		// Get both GPS coordinates from the extensions in the certificate
		aux = x509Utils.getExtensionCreationPositionLatitude(certificate);
		String aux2 = x509Utils
				.getExtensionCreationPositionLongitude(certificate);
		Boolean hasGPSPosition = (aux != null && aux2 != null);

		// Check if both coordinates are present, if not display an error
		// message
		((TextView) rootView.findViewById(R.id.txtCertificateCreationPossition))
				.setText(hasGPSPosition ? aux + " , " + aux2
						: getString(R.string.lblExtensionNotFound));

		TextView lblImgSearchPoint = ((TextView) rootView
				.findViewById(R.id.lblImgSearchPoint));
		if (!hasGPSPosition)
			lblImgSearchPoint.setVisibility(View.GONE);
		else {
			try {
				// If the gps position contains a , "comma" replace with "."
				// points
				aux = aux.replace(",", ".");
				aux2 = aux2.replace(",", ".");

				// Try to parse the coordinate into Float values, if the format
				// is
				// wrong, NumberFormatException is catched an the show gps map
				// button is hidden
				final Float lat = Float.parseFloat(aux);
				final Float lon = Float.parseFloat(aux2);
				lblImgSearchPoint
						.setOnClickListener(new View.OnClickListener() {

							@Override
							public void onClick(View v) {

								((OnClickCertificateCustomExtensionListener) getActivity())
										.onSeeMap(certificatePosition,
												certificateDetailsPage, lat,
												lon);
							}
						});
			} catch (NumberFormatException ex) {
				lblImgSearchPoint.setVisibility(View.GONE);
			}

		}

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
	 * {@link CertificateCustomExtensionsInformationFragment}, this should be
	 * implemented by the Activity that holds the fragment
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	public interface OnClickCertificateCustomExtensionListener {
		/**
		 * See the certificate creation position in a map
		 * 
		 * @param certificatePosition
		 *            Certificate position in the certificate view pager as
		 *            reference for return to the correct certificate
		 * @param certificateDetailsPage
		 *            Certificate Details Page position, in the certificate
		 *            details view pager, to be used as reference when hiding
		 *            the extensions view
		 * @param gpsPositionLat
		 *            GPS Position Latitude coordinate
		 * @param gpsPositionLon
		 *            GPS Position Longitude coordinate
		 */
		void onSeeMap(Integer certificatePosition,
				Integer certificateDetailsPage, Float gpsPositionLat,
				Float gpsPositionLon);
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
