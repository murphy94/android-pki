/**
 *  Created on  : 31/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	A fragment representing a section of the app, simply displays the basic certifciate
 * information.
 */
package cinvestav.pki.android.trustednetwork.details;

import android.os.Bundle;
import android.text.format.DateFormat;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import cinvestav.android.pki.db.controller.CertificateController;
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.common.CurrentlyNotAvailableFragment;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

import com.actionbarsherlock.app.SherlockFragment;

/**
 * A fragment representing a section of the app, simply displays the basic
 * certificate information.
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 31/08/2012
 * @version 1.0
 */
public class CertificateBasicInformationFragment extends SherlockFragment {

	CertificateDAO certificate;
	Integer certificateId;
	private java.text.DateFormat df;
	private static final String CERTIFICATE_ID = "CERTIFICATE_ID";

	static CertificateController certificateController;

	// static SubjectController certificateController;

	public CertificateBasicInformationFragment() {
		super();
		certificateId = 0;
	}

	/**
	 * Initialize the fragment
	 * 
	 * @param certificateId
	 *            Certificate id to be shown
	 * @param certificateController
	 *            certificate controller to be used in this fragment
	 * @return
	 */
	public static CertificateBasicInformationFragment newInstance(
			Integer certificateId, CertificateController certificateController) {
		CertificateBasicInformationFragment f = new CertificateBasicInformationFragment();
		f.setCertificateId(certificateId);
		CertificateBasicInformationFragment.certificateController = certificateController;
		return f;
	}

	/**
	 * @return the certificate
	 */
	public CertificateDAO getCertificate() {
		return certificate;
	}

	/**
	 * @return the certificateId
	 */
	public Integer getCertificateId() {
		return certificateId;
	}

	/**
	 * @param certificateId
	 *            the certificateId to set
	 */
	public void setCertificateId(Integer certificateId) {
		this.certificateId = certificateId;
	}

	/**
	 * @param certificate
	 *            the certificate to set
	 */
	public void setCertificate(CertificateDAO certificate) {
		this.certificate = certificate;
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
				R.layout.detail_certificate_fragment_basic_information,
				container, false);

		setRetainInstance(true);

		try {
			if (savedInstanceState != null && certificateId == 0) {
				certificateId = savedInstanceState.getInt(CERTIFICATE_ID);
				certificateController = new CertificateController(getActivity());
			}

			certificate = certificateController.getById(certificateId);
			certificateController.getCertificateDetails(certificate);

			((TextView) rootView.findViewById(R.id.txtCertificateSerialNumber))
					.setText(Integer.toString(certificate.getSerialNumber()));

			((TextView) rootView.findViewById(R.id.txtCertificateSubjectName))
					.setText(certificate.getOwner().getName());

			((TextView) rootView.findViewById(R.id.txtCertificateDBStatus))
					.setText(certificate
							.getStatusStr(PKITrustNetworkActivity.LAN));
			((TextView) rootView
					.findViewById(R.id.txtCertificateDBStatusLastUpdate))
					.setText(df.format(certificate.getLastStatusUpdateDate()));

			((TextView) rootView
					.findViewById(R.id.txtCertificateDBStatusLastUpdate))
					.setText(df.format(certificate.getLastStatusUpdateDate()));

			Integer caId = certificate.getCaCertificate().getId();
			((TextView) rootView.findViewById(R.id.txtCertificateCASubjectName))
					.setText(!caId.equals(0) ? certificate.getCaCertificate()
							.getOwner().getName()
							: getString(R.string.lblUnkwnown));

			((TextView) rootView.findViewById(R.id.lblImgSeeMoreDetails))
					.setOnClickListener(new View.OnClickListener() {

						@Override
						public void onClick(View v) {
							if (!certificate.getId().equals(0)) {
								((OnClickDetailsListener) getActivity())
										.onMoreDetails(certificate);
							}
						}
					});

		} catch (DBException e) {
			e.printStackTrace();
		}

		return rootView;
	}

	/**
	 * Interface that handles the click on SeeMoreDetails button for
	 * {@link CurrentlyNotAvailableFragment}, this interface should be
	 * implemented by the Activity that holds the fragment
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	public interface OnClickDetailsListener {
		/**
		 * See more detail action
		 * 
		 * @param certificate
		 *            The certificate that must be used for load the details
		 */
		void onMoreDetails(CertificateDAO certificate);
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
		outState.putInt(CERTIFICATE_ID, certificateId);
	}
}
