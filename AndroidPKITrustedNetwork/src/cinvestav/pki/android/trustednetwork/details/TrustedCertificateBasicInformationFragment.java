/**
 *  Created on  : 22/10/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	A fragment representing a section of the app, simply displays the basic 
 *  trusted certificate information.
 */
package cinvestav.pki.android.trustednetwork.details;

import java.text.DecimalFormat;

import android.os.Bundle;
import android.text.format.DateFormat;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.SeekBar;
import android.widget.SeekBar.OnSeekBarChangeListener;
import android.widget.TextView;
import cinvestav.android.pki.db.controller.CertificateController;
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.details.CertificateBasicInformationFragment.OnClickDetailsListener;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

import com.actionbarsherlock.app.SherlockFragment;

/**
 * A fragment representing a section of the app, simply displays the basic
 * trusted certificate information.
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 22/10/2012
 * @version 1.0
 */
public class TrustedCertificateBasicInformationFragment extends
		SherlockFragment implements OnSeekBarChangeListener {

	CertificateDAO certificate;
	Integer trustedCertificateId;
	Integer certificateId;
	Integer trustLevelDB;
	Boolean editable;
	private java.text.DateFormat df;
	DecimalFormat decimalFormat;
	TextView txtTrustLevel;

	static CertificateController certificateController;

	// static SubjectController certificateController;

	public TrustedCertificateBasicInformationFragment() {
		super();
	}

	/**
	 * Initialize the fragment including the trust level on the certificate
	 * 
	 * @param certificateId
	 *            Certificate id to be shown
	 * @param certificateController
	 *            certificate controller to be used in this fragment
	 * @param trustLevelDB
	 *            Trust level for the certificate in the trust list
	 * @return
	 */
	public static TrustedCertificateBasicInformationFragment newInstance(
			Integer certificateId, CertificateController certificateController,
			Integer trustLevel, Boolean editable, Integer trustedCertificateId) {
		TrustedCertificateBasicInformationFragment f = new TrustedCertificateBasicInformationFragment();
		f.setCertificateId(certificateId);
		f.setTrustLevelDB(trustLevel);
		f.setEditable(editable);
		f.setTrustedCertificateId(trustedCertificateId);
		TrustedCertificateBasicInformationFragment.certificateController = certificateController;
		return f;
	}
	
	/**
	 * @return the trustedCertificateId
	 */
	public Integer getTrustedCertificateId() {
		return trustedCertificateId;
	}

	/**
	 * @param trustedCertificateId the trustedCertificateId to set
	 */
	public void setTrustedCertificateId(Integer trustedCertificateId) {
		this.trustedCertificateId = trustedCertificateId;
	}

	/**
	 * @return the editable
	 */
	public Boolean getEditable() {
		return editable;
	}

	/**
	 * @param editable
	 *            the editable to set
	 */
	public void setEditable(Boolean editable) {
		this.editable = editable;
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

	/**
	 * @return the trustLevelDB in DB format [-100,100]
	 */
	public Integer getTrustLevelDB() {
		return trustLevelDB;
	}

	/**
	 * @param trustLevelDB
	 *            the trustLevelDB to set
	 */
	public void setTrustLevelDB(Integer trustLevelDB) {
		this.trustLevelDB = trustLevelDB;
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		df = DateFormat.getDateFormat(getActivity().getApplicationContext());
		decimalFormat = new DecimalFormat("#.##");
		View rootView = inflater.inflate(
				R.layout.detail_trusted_certificate_fragment_basic_information,
				container, false);

		setRetainInstance(true);

		try {

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

			txtTrustLevel = ((TextView) rootView
					.findViewById(R.id.txtCertificateTrustLevel));
			Double trustLvl = (trustLevelDB) / 10.0;
			txtTrustLevel.setText(decimalFormat.format(trustLvl));

			SeekBar seekCertificateTrustLevel = ((SeekBar) rootView
					.findViewById(R.id.seekCertificateTrustLevel));
			seekCertificateTrustLevel.setEnabled(editable);
			seekCertificateTrustLevel.setProgress(trustLevelDB+100);
			// Set seek bar Listener, since we are using this class as the
			// listener the class is "this"
			seekCertificateTrustLevel.setOnSeekBarChangeListener(this);

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
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return rootView;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * android.widget.SeekBar.OnSeekBarChangeListener#onProgressChanged(android
	 * .widget.SeekBar, int, boolean)
	 */
	@Override
	public void onProgressChanged(SeekBar seekBar, int progress,
			boolean fromUser) {
		// change progress text label with current seekbar value
		Double trustLvl = (progress-100) / 10.0;
		txtTrustLevel.setText(decimalFormat.format(trustLvl));
		trustLevelDB =(progress-100);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * android.widget.SeekBar.OnSeekBarChangeListener#onStartTrackingTouch(android
	 * .widget.SeekBar)
	 */
	@Override
	public void onStartTrackingTouch(SeekBar seekBar) {
		// TODO Auto-generated method stub

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * android.widget.SeekBar.OnSeekBarChangeListener#onStopTrackingTouch(android
	 * .widget.SeekBar)
	 */
	@Override
	public void onStopTrackingTouch(SeekBar seekBar) {
		// set the shade of the previous value.
		seekBar.setSecondaryProgress(seekBar.getProgress());

	}
}
