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
import cinvestav.android.pki.db.controller.PersonalKeyController;
import cinvestav.android.pki.db.dao.PersonalKeyDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.adapter.KeyListAdapter;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

import com.actionbarsherlock.app.SherlockListFragment;

/**
 * Activity that contains a list of the keys owned by a determined subject or if
 * no subject is specified list all the keys saved in the data base
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 31/08/2012
 * @version 1.0
 */
public class SelectKeyFragment extends SherlockListFragment {

	List<PersonalKeyDAO> keyList;
	static PersonalKeyController personalKeyController;
	private int subjectId;

	public SelectKeyFragment() {
		super();
	}

	/**
	 * @return the certificateController
	 */
	public static PersonalKeyController getPersonalKeyController() {
		return personalKeyController;
	}

	/**
	 * @param certificateController
	 *            the certificateController to set
	 */
	public static void setPersonalKeyController(
			PersonalKeyController personalKeyController) {
		SelectKeyFragment.personalKeyController = personalKeyController;
	}

	public static SelectKeyFragment newInstance(
			PersonalKeyController personalKeyController, Integer subjectId) {
		SelectKeyFragment f = new SelectKeyFragment();
		SelectKeyFragment.setPersonalKeyController(personalKeyController);
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

	public Integer getSelectedKeyId() {
		return ((KeyListAdapter) this.getListAdapter()).getSelectedId();
	}

	/**
	 * Gets the selected {@link PersonalKeyDAO} object
	 * 
	 * @return The selected {@link PersonalKeyDAO} object
	 */
	public PersonalKeyDAO getSelectedKey() {
		return keyList.get(((KeyListAdapter) this.getListAdapter())
				.getSelectedPosition());
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		setRetainInstance(true);

		final View rootView = inflater.inflate(R.layout.select_key, container,
				false);

		try {
			// Get all the Private keys that belongs to the selected owner
			keyList = personalKeyController.getAllPrivateKeys(subjectId);

			KeyListAdapter adapter = new KeyListAdapter(getActivity(), keyList);
			setListAdapter(adapter);

		} catch (DBException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
			e.printStackTrace();
			Toast.makeText(getActivity(), R.string.error_db_load_key,
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

		((KeyListAdapter) l.getAdapter()).setSelectedId((int) id);

	}
}
