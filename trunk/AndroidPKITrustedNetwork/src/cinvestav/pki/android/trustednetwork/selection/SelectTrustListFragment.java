/**
 *  Created on  : 23/10/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	List fragment that will contain all the trusted list saved in the device, using
 *  a custom adapter so more details about the list owner could be shown
 */
package cinvestav.pki.android.trustednetwork.selection;

import java.util.Iterator;
import java.util.List;

import android.os.Bundle;
import android.util.Log;
import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ListView;
import android.widget.Toast;
import cinvestav.android.pki.db.controller.SubjectController;
import cinvestav.android.pki.db.controller.TrustedCertificateController;
import cinvestav.android.pki.db.dao.SubjectDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.adapter.SubjectWithTrustedCertificateSelectableListAdapter;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

import com.actionbarsherlock.app.SherlockListFragment;

/**
 * List fragment that will contain all the trusted list saved in the device,
 * using a custom adapter so more details about the list owner could be shown
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 23/10/2012
 * @version 1.0
 */
public class SelectTrustListFragment extends SherlockListFragment {

	List<SubjectDAO> subjectList;
	SubjectController subjectController;
	TrustedCertificateController trustedCertificateController;

	public SelectTrustListFragment() {
		super();
	}

	/**
	 * @return the certificateController
	 */
	public SubjectController getSubjectController() {
		return subjectController;
	}

	/**
	 * @param certificateController
	 *            the certificateController to set
	 */
	public void setSubjectController(SubjectController subjectController) {
		this.subjectController = subjectController;
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

	public static SelectTrustListFragment newInstance(
			SubjectController subjectController,
			TrustedCertificateController trustedCertificateController) {
		SelectTrustListFragment f = new SelectTrustListFragment();
		f.setSubjectController(subjectController);
		f.setTrustedCertificateController(trustedCertificateController);
		return f;
	}

	public Integer getSelectedSubjectId() {
		return ((SubjectWithTrustedCertificateSelectableListAdapter) this
				.getListAdapter()).getSelectedId();
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		setRetainInstance(true);

		final View rootView = inflater.inflate(R.layout.select_key, container,
				false);

		try {
			subjectList = subjectController.getAll();
			Iterator<SubjectDAO> it = subjectList.iterator();
			Integer lblCertCount = 0;
			SparseArray<Integer> certificateCount = new SparseArray<Integer>();
			// Clean the list of subject, removing the ones that doesn't have at
			// least one certificate
			while (it.hasNext()) {
				SubjectDAO subject = it.next();
				lblCertCount = trustedCertificateController.getBySubjectId(
						subject.getId()).size();
				if (lblCertCount <= 0) {
					it.remove();
				} else {
					certificateCount.append(subject.getId(), lblCertCount);
				}
			}

			SubjectWithTrustedCertificateSelectableListAdapter adapter = new SubjectWithTrustedCertificateSelectableListAdapter(
					getActivity(), subjectList, certificateCount);
			setListAdapter(adapter);

		} catch (DBException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
			e.printStackTrace();
			Toast.makeText(getActivity(), R.string.error_db_load_trusted_certificate,
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

		((SubjectWithTrustedCertificateSelectableListAdapter) l.getAdapter())
				.setSelectedId((int) id);

	}
}
