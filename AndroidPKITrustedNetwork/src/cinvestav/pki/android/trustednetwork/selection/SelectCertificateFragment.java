/**
 *  Created on  : 27/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	 Activity that contains a list of the keys owned by a determined subject or if
 * no subject is specified list all the keys saved in the data base 
 * 
 */
package cinvestav.pki.android.trustednetwork.selection;

import java.util.List;

import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ListView;
import android.widget.Toast;
import cinvestav.android.pki.db.controller.CertificateController;
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.adapter.CertificatesSelectableListAdapter;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

import com.actionbarsherlock.app.SherlockListFragment;

/**
 * Activity that contains a list of the certificates owned by a determined
 * subject or if no subject is specified list all the certificates saved in the
 * data base
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 31/08/2012
 * @version 1.0
 */
public class SelectCertificateFragment extends SherlockListFragment {

	List<CertificateDAO> certList;
	static CertificateController certificateController;
	private int subjectId;

	public SelectCertificateFragment() {
		super();
	}

	/**
	 * @return the certificateController
	 */
	public static CertificateController getCertificateController() {
		return certificateController;
	}

	/**
	 * @param certificateController
	 *            the certificateController to set
	 */
	public static void setCertificateController(
			CertificateController certificateController) {
		SelectCertificateFragment.certificateController = certificateController;
	}

	public static SelectCertificateFragment newInstance(
			CertificateController certificateController, Integer subjectId) {
		SelectCertificateFragment f = new SelectCertificateFragment();
		SelectCertificateFragment
				.setCertificateController(certificateController);
		f.setSubjectId(subjectId);
		return f;
	}

	/**
	 * @return the ownerId
	 */
	public int getSubjectId() {
		return subjectId;
	}

	/**
	 * @param ownerId
	 *            the ownerId to set
	 */
	public void setSubjectId(int subjectId) {
		this.subjectId = subjectId;
	}

	public Integer getSelectedCertificateId() {
		return ((CertificatesSelectableListAdapter) this.getListAdapter())
				.getSelectedId();
	}

	/**
	 * Gets the selected {@link CertificateDAO} object
	 * 
	 * @return The selected {@link CertificateDAO} object
	 */
	public CertificateDAO getSelectedCertificate() {
		return certList.get(((CertificatesSelectableListAdapter) this.getListAdapter())
				.getSelectedPosition());
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		setRetainInstance(true);

		final View rootView = inflater.inflate(R.layout.select_key, container,
				false);

		try {
			// Get all the Certificates that belongs to the selected owner
			certList = certificateController.getByOwnerId(subjectId);
			CertificatesSelectableListAdapter adapter = new CertificatesSelectableListAdapter(
					getActivity(), certList, certificateController);
			setListAdapter(adapter);

		} catch (DBException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
			e.printStackTrace();
			Toast.makeText(getActivity(), R.string.error_db_load_certs,
					Toast.LENGTH_LONG).show();
		}

		return rootView;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * android.support.v4.app.ListFragment#onListItemClick(android.widget.ListView
	 * , android.view.View, int, long)
	 */
	@Override
	public void onListItemClick(ListView l, View v, int position, long id) {
		super.onListItemClick(l, v, position, id);

		((CertificatesSelectableListAdapter) l.getAdapter()).setSelectedId((int) id);

	}
}
