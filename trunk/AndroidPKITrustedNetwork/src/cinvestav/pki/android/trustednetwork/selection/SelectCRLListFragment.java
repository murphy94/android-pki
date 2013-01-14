/**
 *  Created on  : 23/10/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  List fragment that will contain all the CRLs saved in the device,
 * using a custom adapter so more details about the list owner could be shown	
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
import cinvestav.android.pki.db.controller.CRLController;
import cinvestav.android.pki.db.controller.CertificateController;
import cinvestav.android.pki.db.dao.CRLDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.adapter.CRLSelectableListAdapter;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

import com.actionbarsherlock.app.SherlockListFragment;

/**
 * List fragment that will contain all the CRLs saved in the device, using a
 * custom adapter so more details about the list owner could be shown
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 23/10/2012
 * @version 1.0
 */
public class SelectCRLListFragment extends SherlockListFragment {

	List<CRLDAO> crlList;
	CRLController crlController;
	CertificateController certificateController;

	public SelectCRLListFragment() {
		super();
	}

	/**
	 * @return the crlController
	 */
	public CRLController getCrlController() {
		return crlController;
	}

	/**
	 * @param crlController
	 *            the crlController to set
	 */
	public void setCrlController(CRLController crlController) {
		this.crlController = crlController;
	}

	/**
	 * @return the certificateController
	 */
	public CertificateController getCertificateController() {
		return certificateController;
	}

	/**
	 * @param certificateController
	 *            the certificateController to set
	 */
	public void setCertificateController(
			CertificateController certificateController) {
		this.certificateController = certificateController;
	}

	public static SelectCRLListFragment newInstance(
			CRLController crlController,
			CertificateController certificateController) {
		SelectCRLListFragment f = new SelectCRLListFragment();
		f.setCrlController(crlController);
		f.setCertificateController(certificateController);
		return f;
	}

	public Integer getSelectedCRLId() {
		return ((CRLSelectableListAdapter) this
				.getListAdapter()).getSelectedId();
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		setRetainInstance(true);

		final View rootView = inflater.inflate(R.layout.select_key, container,
				false);

		try {
			crlList = crlController.getAll();
			for (CRLDAO crl : crlList) {
				certificateController.getCertificateDetails(crl
						.getIssuerCertificate());
			}
			CRLSelectableListAdapter adapter = new CRLSelectableListAdapter(getActivity(), crlList);
			setListAdapter(adapter);

		} catch (DBException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
			e.printStackTrace();
			Toast.makeText(getActivity(),
					R.string.error_db_load_crl,
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

		((CRLSelectableListAdapter) l.getAdapter())
				.setSelectedId((int) id);

	}

}
