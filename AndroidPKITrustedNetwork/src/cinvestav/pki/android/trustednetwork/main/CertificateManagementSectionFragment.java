/**
 *  Created on  : 24/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	This Fragment includes all the Certificate Management operations, like: 
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

import java.util.Iterator;
import java.util.List;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.util.SparseArray;
import android.view.View;
import android.widget.AdapterView;
import android.widget.Toast;
import cinvestav.android.pki.db.controller.CertificateController;
import cinvestav.android.pki.db.controller.SubjectController;
import cinvestav.android.pki.db.dao.SubjectDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.adapter.SubjectWithCertificatesListAdapter;
import cinvestav.pki.android.trustednetwork.add.AddNewCertificateSelectKeyOptionsActivity;
import cinvestav.pki.android.trustednetwork.selection.SelectOwnerActivity;

import com.actionbarsherlock.app.SherlockFragmentActivity;
import com.actionbarsherlock.app.SherlockListFragment;
import com.actionbarsherlock.view.ActionMode;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuInflater;
import com.actionbarsherlock.view.MenuItem;

/**
 * This Fragment includes all the Certificate Management operations, like:
 * <ul>
 * <li>See details
 * <li>List all
 * <li>Delete
 * <li>Create
 * <li>Import
 * <li>Export
 * <li>Send
 * <li>Verify
 * </ul>
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 24/08/2012
 * @version 1.0
 */
public class CertificateManagementSectionFragment extends SherlockListFragment {

	ActionMode mMode;
	Integer selectedItemID;
	static CertificateController certificateController;
	static SubjectController subjectController;
	List<SubjectDAO> subjectList;

	private static final int MENU_ADD = 0;
	private static final int MENU_IMPORT = 1;

	@Override
	public void onActivityCreated(Bundle savedInstanceState) {
		super.onActivityCreated(savedInstanceState);
		setHasOptionsMenu(true);

		Log.i(PKITrustNetworkActivity.TAG,
				"CERTIFICATE MANAGEMENT onActivityCreated :"
						+ savedInstanceState);
		if (certificateController == null) {
			certificateController = new CertificateController(getActivity());
		}
		if (subjectController == null) {
			subjectController = new SubjectController(getActivity());
		}
		try {
			subjectList = subjectController.getAll();
			Iterator<SubjectDAO> it = subjectList.iterator();
			Integer lblCertCount = 0;
			SparseArray<Integer> certificateCount = new SparseArray<Integer>();
			// Clean the list of subject, removing the ones that doesn't have at
			// least one certificate
			while (it.hasNext()) {
				SubjectDAO subject = it.next();
				lblCertCount = certificateController.getByOwnerId(
						subject.getId()).size();
				if (lblCertCount <= 0) {
					it.remove();
				} else {
					certificateCount.append(subject.getId(), lblCertCount);
				}
			}

			SubjectWithCertificatesListAdapter adapter = new SubjectWithCertificatesListAdapter(
					getActivity(), subjectList, certificateCount);
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

		// Place an action bar item for add new Certificate.
		MenuItem itemAdd_cert = menu.add(0, MENU_ADD, 0, R.string.menu_add);
		itemAdd_cert.setIcon(R.drawable.ic_action_cert_add);
		itemAdd_cert.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

		// Place an action bar item for import a Certificate.
		MenuItem itemImport = menu.add(0, MENU_IMPORT, 0, R.string.menu_import);
		itemImport.setIcon(R.drawable.ic_action_cert_import);
		itemImport.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

	}

	private final class AnActionMode implements ActionMode.Callback {
		@Override
		public boolean onCreateActionMode(ActionMode mode, Menu menu) {

			menu.add(0, 0, 0, R.string.menu_details)
					.setIcon(R.drawable.ic_action_cert_details)
					.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

			menu.add(0, 1, 1, R.string.menu_delete)
					.setIcon(R.drawable.ic_action_cert_delete)
					.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

			menu.add(0, 2, 2, R.string.menu_export)
					.setIcon(R.drawable.ic_action_cert_export)
					.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

			menu.add(0, 3, 3, R.string.menu_send)
					.setIcon(R.drawable.ic_action_cert_send)
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
			intent = new Intent(getActivity(), SelectOwnerActivity.class);
			intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
					PKITrustNetworkActivity.CERTIFICATE);
			intent.putExtra(PKITrustNetworkActivity.EXTRA_NEXT_OPERATION,
					PKITrustNetworkActivity.IMPORT);
			startActivity(intent);
			return true;
		case MENU_ADD:
			// Show Select key options activity
			intent = new Intent(getActivity(),
					AddNewCertificateSelectKeyOptionsActivity.class);
			startActivity(intent);
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}
}
