/**
 *  Created on  : 24/10/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	List fragment that will contain all the signers for a determined certificate
 * key list saved in the device using a custom adapter so more details about the
 * list could be shown.
 */
package cinvestav.pki.android.trustednetwork.crypto;

import java.util.LinkedList;
import java.util.List;

import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Toast;
import cinvestav.android.pki.db.controller.CertificateController;
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.adapter.CertificatesListAdapter;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

import com.actionbarsherlock.app.SherlockFragmentActivity;
import com.actionbarsherlock.app.SherlockListFragment;

/**
 * List fragment that will contain all the signers for a determined certificate
 * key list saved in the device using a custom adapter so more details about the
 * list could be shown.
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 24/10/2012
 * @version 1.0
 */
public class CertificationPathListFragment extends SherlockListFragment {

	private CertificateController certificateController;
	private SearchCertificationPathTask searchCertificationPathTask;
	private CertificateDAO certificate;

	public CertificationPathListFragment() {
		super();
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
	 * @param certificate
	 *            the certificate to set
	 */
	public void setCertificate(CertificateDAO certificate) {
		this.certificate = certificate;
	}

	public static CertificationPathListFragment newInstance(
			CertificateController certificateController,
			CertificateDAO certificate) {
		CertificationPathListFragment f = new CertificationPathListFragment();
		f.setCertificateController(certificateController);
		f.setCertificate(certificate);
		return f;
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		setRetainInstance(true);

		final View rootView = inflater.inflate(R.layout.select_key, container,
				false);

		if (searchCertificationPathTask == null
				|| !searchCertificationPathTask.getStatus().equals(
						AsyncTask.Status.RUNNING)) {
			searchCertificationPathTask = new SearchCertificationPathTask();
			searchCertificationPathTask.execute(certificate);
		} else {
			Toast.makeText(getActivity(), R.string.msgWorking,
					Toast.LENGTH_SHORT).show();
		}

		return rootView;
	}

	/**
	 * Search in the data base all the certificates that are in the
	 * certification path from the source certificate, the search will end with
	 * a self-signed certificate or a loop in the certification path
	 * 
	 * @param sourceCertificate
	 *            CertificateDAO from which would be searched the path
	 * @return a List of certificates that are in the certification path
	 * @throws DBException
	 *             if the search in the data base has an error
	 */
	private List<CertificateDAO> searchCertificationPath(
			CertificateDAO sourceCertificate) throws DBException {

		// Create the list for saving the certification path
		List<CertificateDAO> certificateList = new LinkedList<CertificateDAO>();
		// Integer list that will save all the certificates path, so loop could
		// be detected
		List<Integer> certificatePathIds = new LinkedList<Integer>();
		// add the source certificate at the beginning of the certification path
		certificateList.add(sourceCertificate);

		CertificateDAO currentCert = sourceCertificate;
		// Add the inicial certificate id
		certificatePathIds.add(sourceCertificate.getId());
		while (true) {
			// Get CA certificate
			CertificateDAO caCertificate = currentCert.getCaCertificate();
			// If the CA Certificate is different from null and the
			// certificatePath list doesn't contains the CA certificate
			if (caCertificate != null
					&& !certificatePathIds.contains(caCertificate.getId())) {
				// Get CA certificate details and add it to the certificate path
				// list
				certificateController.getCertificateDetails(caCertificate);
				certificateList.add(caCertificate);

				// Add the ca certificate id to the list
				certificatePathIds.add(caCertificate.getId());
				// Move the current certificate to CA Certificate and continue
				// to the next certificate
				currentCert = caCertificate;
			} else {
				break;
			}
		}

		return certificateList;
	}

	/**
	 * Inner class that create an asynchronous task that searches in the data
	 * base all the certificates that are in the certification path of a
	 * determined certificate, the search will be ended when a self-signed
	 * certificate or a loop in the path is found.
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class SearchCertificationPathTask extends
			AsyncTask<CertificateDAO, Void, List<CertificateDAO>> {

		@Override
		protected void onPreExecute() {
			// Enable the indeterminate progress icon on the action bar
			((SherlockFragmentActivity) getActivity())
					.setSupportProgressBarIndeterminateVisibility(true);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see android.os.AsyncTask#doInBackground(Params[])
		 */
		@Override
		protected List<CertificateDAO> doInBackground(CertificateDAO... params) {

			try {
				return searchCertificationPath(params[0]);
			} catch (DBException e) {
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
				e.printStackTrace();
				Toast.makeText(getActivity(),
						R.string.error_db_load_trusted_certificate,
						Toast.LENGTH_LONG).show();
				return null;
			}

		}

		@Override
		protected void onPostExecute(List<CertificateDAO> certificationPathList) {
			if (certificationPathList != null) {

				// Create an adapter that when requested, will return a fragment
				// representing an object in the collection.
				// ViewPager and its adapters use support library fragments, so
				// we
				// must use getSupportFragmentManager.
				CertificatesListAdapter adapter = new CertificatesListAdapter(
						getActivity(), certificationPathList);

				// Set up list adapter
				setListAdapter(adapter);

			} else {
				Toast.makeText(getActivity(), R.string.error_cert_load_signers,
						Toast.LENGTH_LONG).show();
			}
			// Disable the indeterminate progress icon on the action bar
			((SherlockFragmentActivity) getActivity())
					.setSupportProgressBarIndeterminateVisibility(false);

		}
	}
}
