/**
 *  Created on  : 25/10/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Fragment that shows the verification result using the X509 method
 */
package cinvestav.pki.android.trustednetwork.crypto;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import android.widget.Toast;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.utils.X509Utils;
import cinvestav.android.pki.db.controller.CRLController;
import cinvestav.android.pki.db.controller.CertificateController;
import cinvestav.android.pki.db.dao.CRLDAO;
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

import com.actionbarsherlock.app.SherlockFragment;

/**
 * Fragment that shows the verification result using the X509 method
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 25/10/2012
 * @version 1.0
 */
public class ResultX509Fragment extends SherlockFragment {

	private CRLController crlController;
	private CertificateController certificateController;
	private CertificateDAO certificate;
	private Integer crlId;
	private X509Utils x509Utils;

	public ResultX509Fragment() {
		super();
	}

	/**
	 * @param crlController
	 *            the crlController to set
	 */
	public void setCrlController(CRLController crlController) {
		this.crlController = crlController;
	}

	/**
	 * @param certificate
	 *            the certificate to set
	 */
	public void setCertificate(CertificateDAO certificate) {
		this.certificate = certificate;
	}

	/**
	 * @param crlId
	 *            the crlId to set
	 */
	public void setCrlId(Integer crlId) {
		this.crlId = crlId;
	}

	/**
	 * @param x509Utils
	 *            the x509Utils to set
	 */
	public void setX509Utils(X509Utils x509Utils) {
		this.x509Utils = x509Utils;
	}

	/**
	 * @param certificateController
	 *            the certificateController to set
	 */
	public void setCertificateController(
			CertificateController certificateController) {
		this.certificateController = certificateController;
	}

	/**
	 * Create a new instance using the CRL Id and certificate
	 * 
	 * @return a new instance for this class filled out with the
	 */
	public static ResultX509Fragment newInstance(Integer crlId,
			CertificateDAO certificate, CRLController crlController,
			X509Utils x509Utils, CertificateController certificateController) {
		ResultX509Fragment f = new ResultX509Fragment();
		f.setCrlId(crlId);
		f.setCrlController(crlController);
		f.setCertificate(certificate);
		f.setX509Utils(x509Utils);
		f.setCertificateController(certificateController);
		return f;
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		setRetainInstance(true);

		View rootView = inflater
				.inflate(R.layout.result_x509, container, false);

		// Get CRL from data base
		CRLDAO crl;
		try {
			// Get CRL using the CRL id
			crl = crlController.getById(crlId);

			// Decode CRL
			X509CRL x509CRL = x509Utils.decodeCRL(crl.getCrlDataStr()
					.getBytes());

			// Decode certificate and CA certificate
			X509Certificate x509Cert = x509Utils.decode(certificate
					.getCertificateStr().getBytes());
			X509Certificate x509CACert = x509Utils.decode(certificate
					.getCaCertificate().getCertificateStr().getBytes());

			// Use the verification method
			Integer status = x509Utils.verifyCertificate(x509Cert, x509CACert,
					x509CRL);

			// Updates the status in the original certificate
			certificate.setStatus(status);

			TextView txtStatus = (TextView) rootView
					.findViewById(R.id.txtStatus);
			txtStatus.setText(certificate.getStatusStr(
					PKITrustNetworkActivity.LAN).toUpperCase());

			// Update the status in the data base
			certificateController.updateStatus(certificate);

		} catch (DBException e) {

			TextView txtStatus = (TextView) rootView
					.findViewById(R.id.txtStatus);
			txtStatus.setText(R.string.lblNotAvailable);

			Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
			e.printStackTrace();
			Toast.makeText(getActivity(), R.string.error_verify_x509,
					Toast.LENGTH_LONG).show();
		} catch (CryptoUtilsException e) {
			TextView txtStatus = (TextView) rootView
					.findViewById(R.id.txtStatus);
			txtStatus.setText(R.string.lblNotAvailable);
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
			e.printStackTrace();
			Toast.makeText(getActivity(), R.string.error_verify_x509,
					Toast.LENGTH_LONG).show();
		}

		return rootView;
	}
}
