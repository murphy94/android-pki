/**
 *  Created on  : 24/10/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	List fragment that will contain all the signers for a determined certificate
 * key list saved in the device using a custom adapter so more details about the
 * list could be shown.
 */
package cinvestav.pki.android.trustednetwork.crypto;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Toast;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.utils.X509Utils;
import cinvestav.android.pki.db.controller.CertificateController;
import cinvestav.android.pki.db.controller.TrustedCertificateController;
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.android.pki.db.dao.TrustedCertificateDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.android.pki.utils.DataBaseDictionary;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.adapter.CertificateSignerListAdapter;
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
public class SignersListFragment extends SherlockListFragment {

	private TrustedCertificateController trustedCertificateController;
	private CertificateController certificateController;
	private Integer listOwnerId;
	private X509Utils x509Utils;
	private SearchSimilarCertificateTask searchSimilarCertificateTask;
	private CertificateDAO certificate;
	private NotifyListLoaded notifyListLoaded;

	public SignersListFragment() {
		super();
	}

	/**
	 * @return the trustedCertificateController
	 */
	public TrustedCertificateController getTrustedCertificateController() {
		return trustedCertificateController;
	}

	/**
	 * @param trustedCertificateController
	 *            the trustedCertificateController to set
	 */
	public void setTrustedCertificateController(
			TrustedCertificateController trustedCertificateController) {
		this.trustedCertificateController = trustedCertificateController;
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
	 * @return the notifyListLoaded
	 */
	public NotifyListLoaded getNotifyListLoaded() {
		return notifyListLoaded;
	}

	/**
	 * @param notifyListLoaded
	 *            the notifyListLoaded to set
	 */
	public void setNotifyListLoaded(NotifyListLoaded notifyListLoaded) {
		this.notifyListLoaded = notifyListLoaded;
	}

	/**
	 * @return the listOwnerId
	 */
	public Integer getListOwnerId() {
		return listOwnerId;
	}

	/**
	 * @param listOwnerId
	 *            the listOwnerId to set
	 */
	public void setListOwnerId(Integer listOwnerId) {
		this.listOwnerId = listOwnerId;
	}

	/**
	 * @param x509Utils
	 *            the x509Utils to set
	 */
	public void setX509Utils(X509Utils x509Utils) {
		this.x509Utils = x509Utils;
	}

	/**
	 * @param certificate
	 *            the certificate to set
	 */
	public void setCertificate(CertificateDAO certificate) {
		this.certificate = certificate;
	}

	public static SignersListFragment newInstance(
			TrustedCertificateController trustedCertificateController,
			CertificateController certificateController, Integer listOwnerId,
			X509Utils x509Utils, CertificateDAO certificate,
			NotifyListLoaded notifyListLoaded) {
		SignersListFragment f = new SignersListFragment();
		f.setTrustedCertificateController(trustedCertificateController);
		f.setCertificateController(certificateController);
		f.setListOwnerId(listOwnerId);
		f.setX509Utils(x509Utils);
		f.setCertificate(certificate);
		f.setNotifyListLoaded(notifyListLoaded);
		return f;
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		setRetainInstance(true);

		final View rootView = inflater.inflate(R.layout.select_key, container,
				false);

		if (searchSimilarCertificateTask == null
				|| !searchSimilarCertificateTask.getStatus().equals(
						AsyncTask.Status.RUNNING)) {
			searchSimilarCertificateTask = new SearchSimilarCertificateTask();
			searchSimilarCertificateTask.execute(certificate);
		} else {
			Toast.makeText(getActivity(), R.string.msgWorking,
					Toast.LENGTH_SHORT).show();
		}

		return rootView;
	}

	/**
	 * Search in the data base all the similar certificates from other one, a
	 * similar certificate is one that shares the same key id and has common
	 * fields and values stored in the holder name of the certificate
	 * 
	 * @param sourceCertificate
	 *            CertificateDAO from which would be searched all the similar
	 *            certificates
	 * @return a List of similar certificates to the one that has been send
	 * @throws DBException
	 *             if the search in the data base has an error
	 */
	private List<CertificateDAO> searchAllSimilarCertificates(
			CertificateDAO sourceCertificate) throws DBException {

		/*
		 * Filter map where: Key = Tag of the filter to be used, should be
		 * define in "DataBaseDictionary" Class, this tags must be written as a
		 * SQL WHERE clause using a PreparedStament form for example: 'DBfield =
		 * ?' or 'DBfield LIKE ?' Value = Must be a string array of 3 positions
		 * where: [0] = Value to be searched in the data base [1] = Data type,
		 * according to this, the PreparedStatemen will be constructed, the
		 * valid DataTypes are defined in the "DataBaseDictionary" Class
		 */
		Map<String, String[]> filterMap = new HashMap<String, String[]>();
		String[] value = new String[3];

		/*
		 * Establish filter properties
		 */
		// Filter value
		value[0] = sourceCertificate.getSubjectKeyId() + "";
		// Filter type
		value[1] = DataBaseDictionary.FILTER_TYPE_CERTIFICATE_SUBJECT_KEY_ID;
		filterMap.put(DataBaseDictionary.FILTER_CERTIFICATE_SUBJECT_KEY_ID,
				value);

		// Get all the certificates that has the same subjectKey
		List<CertificateDAO> certificateList = certificateController
				.getByAdvancedFilter(filterMap);

		Iterator<CertificateDAO> it = certificateList.iterator();

		try {
			X509Certificate x509SourceCertificate = x509Utils
					.decode(sourceCertificate.getCertificateStr().getBytes());

			// Get the information map from the decoded certificate
			HashMap<String, String> sourceInformation = x509Utils
					.getCertificateInformationMap(x509SourceCertificate);

			// Go over the certificate list and leave only the certificates that
			// has common fields into the subject name field of the certificate
			// and remove the other ones
			while (it.hasNext()) {
				CertificateDAO certificate = it.next();
				try {
					X509Certificate x509Certificate = x509Utils
							.decode(certificate.getCertificateStr().getBytes());
					HashMap<String, String> certInformation = x509Utils
							.getCertificateInformationMap(x509Certificate);

					// Go over the key set of the certificate Information map
					// and check what attributes appears in the source
					// certificate map, if an attribute appears, its value
					// should be equals taking in account RFC-5230 comparison
					// rules (caseIgnoreMatcha and ignoreInsignificatSpaces), if
					// any of the mutual attributes has the same value, the
					// certificate is removed from the similar certificate list
					Iterator<String> keyIterator = certInformation.keySet()
							.iterator();
					while (keyIterator.hasNext()) {
						String key = keyIterator.next();
						if (sourceInformation.containsKey(key)) {
							// Get the attribute value from the map and
							// eliminate white spaces
							String certificateKeyValue = certInformation.get(
									key).trim();

							// Get the attribute value from the map and
							// eliminate white spaces
							String sourceCertificateKeyValue = certInformation
									.get(key).trim();

							// If the values aren't equals, remove the
							// certificate from the similar certificate list
							if (!certificateKeyValue
									.equalsIgnoreCase(sourceCertificateKeyValue)) {
								it.remove();
							}
						}
					}

				} catch (CryptoUtilsException e) {
					// If a certificate could not be decoded, remove it from the
					// list
					it.remove();
				}
			}
		} catch (CryptoUtilsException e) {
			// if the source certificate could not be decoded, return an empty
			// list, because the certificate subject name could not be gotten so
			// no comparison between certificate holders information could be
			// made
			return new LinkedList<CertificateDAO>();
		}

		return certificateList;
	}

	/**
	 * Interface that will be implemented by the activity that holds this
	 * fragment in order to receive the trusted Certificate list after its
	 * loaded
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 25/10/2012
	 * @version 1.0
	 */
	public interface NotifyListLoaded {
		/**
		 * Set the Trusted Certificate List containing the signers of the
		 * certificate with the corresponding trust level
		 * 
		 * @param trustedCertificatesList
		 */
		public void setSignersList(
				List<TrustedCertificateDAO> trustedCertificatesList);
	}

	/**
	 * Inner class that create an asynchronous task that searches in the data
	 * base all the similar certificates from other one, a similar certificate
	 * is one that shares the same key id and has common fields and values
	 * stored in the holder name of the certificate
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class SearchSimilarCertificateTask extends
			AsyncTask<CertificateDAO, Void, List<TrustedCertificateDAO>> {

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
		protected List<TrustedCertificateDAO> doInBackground(
				CertificateDAO... params) {

			try {
				List<CertificateDAO> relatedCertificates = searchAllSimilarCertificates(params[0]);

				List<TrustedCertificateDAO> trustedCertificateList = trustedCertificateController
						.getBySubjectId(listOwnerId);

				List<TrustedCertificateDAO> resultList = new LinkedList<TrustedCertificateDAO>();
				List<Integer> addedCACert = new LinkedList<Integer>();

				// Go over the related certificates list and get its CA
				// certificates, then compare each CA to the ones in the trust
				// list in order to copy the trust levels
				Iterator<CertificateDAO> i = relatedCertificates.iterator();
				while (i.hasNext()) {
					// Get the CA certificates and compare it to the
					// certificates in the trusted list
					CertificateDAO cert = i.next();
					certificateController.getCertificateDetails(cert);
					CertificateDAO caCert = cert.getCaCertificate();
					// Check if the CA certificate has not been yet added to the
					// list
					if (addedCACert.contains(caCert.getId())) {
						continue;
					}
					TrustedCertificateDAO newTrustedCert = new TrustedCertificateDAO();
					certificateController.getCertificateDetails(caCert);

					newTrustedCert.setTrustedCertificate(caCert);
					// Search the certificate in the trusted certificate list,
					// if is in it, copy the trust level to the new trusted
					// certificate object
					for (TrustedCertificateDAO trustedCert : trustedCertificateList) {
						if (caCert.getId().equals(
								trustedCert.getTrustedCertificate().getId())) {
							newTrustedCert.setTrustLevel(trustedCert
									.getTrustLevel());
							break;
						}
					}
					// Add the CA to the added CA list and to the result list
					addedCACert.add(caCert.getId());
					resultList.add(newTrustedCert);
				}
				return resultList;

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
		protected void onPostExecute(
				List<TrustedCertificateDAO> trustedCertificateList) {
			if (trustedCertificateList != null) {

				// Create an adapter that when requested, will return a fragment
				// representing an object in the collection.
				// ViewPager and its adapters use support library fragments, so
				// we
				// must use getSupportFragmentManager.
				CertificateSignerListAdapter adapter = new CertificateSignerListAdapter(
						getActivity(), trustedCertificateList);

				// Set up list adapter
				setListAdapter(adapter);

				notifyListLoaded.setSignersList(trustedCertificateList);
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
