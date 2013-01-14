/**
 *  Created on  : 24/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	This Fragment includes all the Trust Network Management operations, like: 
 *  <ul> 
 * <li> See details
 * <li> List all
 * <li> Delete
 * <li> Add
 * <li> Share
 * <li> Modify
 *  </ul>
 */
package cinvestav.pki.android.trustednetwork.main;

import java.util.Iterator;
import java.util.List;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.Toast;
import cinvestav.android.pki.db.controller.SubjectController;
import cinvestav.android.pki.db.controller.TrustedCertificateController;
import cinvestav.android.pki.db.dao.SubjectDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.adapter.SubjectWithTrustedCertificatesListAdapter;
import cinvestav.pki.android.trustednetwork.selection.SelectOwnerActivity;

import com.actionbarsherlock.app.SherlockFragmentActivity;
import com.actionbarsherlock.app.SherlockListFragment;
import com.actionbarsherlock.view.ActionMode;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuInflater;
import com.actionbarsherlock.view.MenuItem;

/**
 * This Fragment includes all the Trust Network Management operations, like:
 * <ul>
 * <li>See details
 * <li>List all
 * <li>Delete
 * <li>Add
 * <li>Share
 * <li>Modify
 * </ul>
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 24/08/2012
 * @version 1.0
 */
public class TrustNetworkManagementSectionFragment extends SherlockListFragment {

	ActionMode mMode;
	Integer selectedItemID;
	static TrustedCertificateController trustedCertificateController;
	static SubjectController subjectController;
	List<SubjectDAO> subjectList;

	private static final int MENU_ADD = 0;
	private static final int MENU_IMPORT = 1;

	@Override
	public void onActivityCreated(Bundle savedInstanceState) {
		super.onActivityCreated(savedInstanceState);
		setHasOptionsMenu(true);

		if (trustedCertificateController == null) {
			trustedCertificateController = new TrustedCertificateController(
					getActivity());
		}
		if (subjectController == null) {
			subjectController = new SubjectController(getActivity());
		}
		try {
			subjectList = subjectController.getAll();
			Iterator<SubjectDAO> it = subjectList.iterator();
			Integer lblCertCount = 0;
			// Clean the list of subject, removing the ones that doesn't have at
			// least one certificate
			while (it.hasNext()) {
				SubjectDAO subject = it.next();
				lblCertCount = trustedCertificateController.getBySubjectId(
						subject.getId()).size();
				if (lblCertCount <= 0) {
					it.remove();
				}
			}

			SubjectWithTrustedCertificatesListAdapter adapter = new SubjectWithTrustedCertificatesListAdapter(
					getActivity(), subjectList, trustedCertificateController);
			setListAdapter(adapter);
		} catch (DBException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
			e.printStackTrace();
			Toast.makeText(getActivity(), R.string.error_db_load_cert,
					Toast.LENGTH_LONG).show();
		}

		getListView().setOnItemLongClickListener(
				new AdapterView.OnItemLongClickListener() {
					@Override
					public boolean onItemLongClick(AdapterView<?> av, View v,
							int pos, long id) {
						mMode = ((SherlockFragmentActivity) getActivity())
								.startActionMode(new AnActionMode());
						selectedItemID = (int) id;
						return false;
					}
				});

	}

	@Override
	public void onCreateOptionsMenu(Menu menu, MenuInflater inflater) {
		// Place an action bar item for add new Trust Certificate.
		menu.add(R.string.menu_add)
				.setIcon(R.drawable.ic_action_trust_cert_add)
				.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

		// Place an action bar item for import a Trust Certificate List.
		menu.add(R.string.menu_import)
				.setIcon(R.drawable.ic_action_trust_cert_import)
				.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);
	}

	private final class AnActionMode implements ActionMode.Callback {
		@Override
		public boolean onCreateActionMode(ActionMode mode, Menu menu) {

			menu.add(0, 0, 0, R.string.menu_details)
					.setIcon(R.drawable.ic_action_trust_cert_details)
					.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

			menu.add(0, 1, 1, R.string.menu_delete)
					.setIcon(R.drawable.ic_action_trust_cert_delete)
					.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

			menu.add(0, 2, 2, R.string.menu_export)
					.setIcon(R.drawable.ic_action_trust_cert_export)
					.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

			menu.add(0, 3, 3, R.string.menu_send)
					.setIcon(R.drawable.ic_action_trust_cert_send)
					.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);
			return true;
		}

		@Override
		public boolean onPrepareActionMode(ActionMode mode, Menu menu) {
			return false;
		}

		@Override
		public boolean onActionItemClicked(ActionMode mode, MenuItem item) {
			Toast.makeText(
					getActivity(),
					"Got click: " + item.getItemId() + "\nList item:"
							+ selectedItemID, Toast.LENGTH_SHORT).show();
			mode.finish();
			return true;
		}

		@Override
		public void onDestroyActionMode(ActionMode mode) {
		}
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		Intent intent;
		switch (item.getItemId()) {
		case android.R.id.home:
			// TODO handle clicking the app icon/logo
			return false;
		case MENU_IMPORT:
			// Import new key
			/*
			 * intent = new Intent(getActivity(), SelectOwnerActivity.class);
			 * intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
			 * PKITrustNetworkActivity.CERTIFICATE);
			 * intent.putExtra(PKITrustNetworkActivity.EXTRA_NEXT_OPERATION,
			 * SelectOwnerActivity.IMPORT); startActivity(intent);
			 */
			return true;
		case MENU_ADD:
			// Show Select list owner activity
			intent = new Intent(getActivity(), SelectOwnerActivity.class);
			intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
					PKITrustNetworkActivity.TRUST_NETWORK);
			intent.putExtra(PKITrustNetworkActivity.EXTRA_NEXT_OPERATION,
					PKITrustNetworkActivity.ADD);
			startActivity(intent);
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}
}
