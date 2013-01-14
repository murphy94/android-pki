/**
 *  Created on  : 24/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	This Fragment includes all the CRL Management operations, like: 
 *  <ul> 
 * <li> See details
 * <li> List all
 * <li> Delete
 * <li> Create
 * <li> Import
 * <li> Export
 * <li> Send
 * <li> Verify
 *  </ul>
 */
package cinvestav.pki.android.trustednetwork.main;

import java.util.List;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.Toast;
import cinvestav.android.pki.db.controller.CRLController;
import cinvestav.android.pki.db.controller.CertificateController;
import cinvestav.android.pki.db.dao.CRLDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.adapter.CRLListAdapter;

import com.actionbarsherlock.app.SherlockFragmentActivity;
import com.actionbarsherlock.app.SherlockListFragment;
import com.actionbarsherlock.view.ActionMode;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuInflater;
import com.actionbarsherlock.view.MenuItem;

/**
 * This Fragment includes all the CRL Management operations, like:
 * <ul>
 * <li>See details
 * <li>List all
 * <li>Delete
 * <li>Create
 * <li>Import
 * <li>Export
 * <li>Send
 * </ul>
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 24/08/2012
 * @version 1.0
 */
public class CRLManagementSectionFragment extends SherlockListFragment {

	ActionMode mMode;

	Integer selectedItemID;
	CRLController crlController;
	CertificateController certificateController;
	List<CRLDAO> crlList;

	private static final int MENU_ADD = 0;
	private static final int MENU_IMPORT = 1;

	@Override
	public void onActivityCreated(Bundle savedInstanceState) {
		super.onActivityCreated(savedInstanceState);
		setHasOptionsMenu(true);

		if (crlController == null) {
			crlController = new CRLController(getActivity());
		}

		if (certificateController == null) {
			certificateController = new CertificateController(getActivity());
		}

		try {
			crlList = crlController.getAll();
			for (CRLDAO crl : crlList) {
				certificateController.getCertificateDetails(crl
						.getIssuerCertificate());
			}
			CRLListAdapter adapter = new CRLListAdapter(getActivity(), crlList);
			setListAdapter(adapter);
		} catch (DBException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
			e.printStackTrace();
			Toast.makeText(getActivity(), R.string.error_db_load_crl,
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
		// Place an action bar item for add new CRL.
		menu.add(R.string.menu_add).setIcon(R.drawable.ic_action_crl_add)
				.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

		// Place an action bar item for import a CRL.
		menu.add(R.string.menu_import).setIcon(R.drawable.ic_action_crl_import)
				.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);
	}

	private final class AnActionMode implements ActionMode.Callback {
		@Override
		public boolean onCreateActionMode(ActionMode mode, Menu menu) {

			menu.add(0, 0, 0, R.string.menu_details)
					.setIcon(R.drawable.ic_action_crl_details)
					.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

			menu.add(0, 1, 1, R.string.menu_delete)
					.setIcon(R.drawable.ic_action_crl_delete)
					.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

			menu.add(0, 2, 2, R.string.menu_export)
					.setIcon(R.drawable.ic_action_crl_export)
					.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

			menu.add(0, 3, 3, R.string.menu_send)
					.setIcon(R.drawable.ic_action_crl_send)
					.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);
			return true;
		}

		@Override
		public boolean onPrepareActionMode(ActionMode mode, Menu menu) {
			return false;
		}

		@Override
		public boolean onActionItemClicked(ActionMode mode, MenuItem item) {
			Toast.makeText(getActivity(), "Got click: " + item.getItemId(),
					Toast.LENGTH_SHORT).show();
			mode.finish();
			return true;
		}

		@Override
		public void onDestroyActionMode(ActionMode mode) {
		}
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Intent intent;
		switch (item.getItemId()) {
		case android.R.id.home:
			// TODO handle clicking the app icon/logo
			return false;
		case MENU_IMPORT:
			// Import new CRL

			return true;
		case MENU_ADD:
			// Show create new CRL activity

			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}
}
