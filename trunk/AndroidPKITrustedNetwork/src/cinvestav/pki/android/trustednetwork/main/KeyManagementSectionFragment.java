/**
 *  Created on  : 24/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	This Fragment includes all the Key Management operations, like: 
 *  <ul> 
 *  <li> See details
 *  <li> List all saved keys
 *  <li> Delete
 *  <li> Create
 *  <li> Import
 *  <li> Export
 *  <li> Send
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
import cinvestav.android.pki.db.controller.PersonalKeyController;
import cinvestav.android.pki.db.controller.SubjectController;
import cinvestav.android.pki.db.dao.PersonalKeyDAO;
import cinvestav.android.pki.db.dao.SubjectDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.adapter.SubjectListAdapter;
import cinvestav.pki.android.trustednetwork.details.KeyDetailsActivity;
import cinvestav.pki.android.trustednetwork.selection.SelectOwnerActivity;

import com.actionbarsherlock.app.SherlockFragmentActivity;
import com.actionbarsherlock.app.SherlockListFragment;
import com.actionbarsherlock.view.ActionMode;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuInflater;
import com.actionbarsherlock.view.MenuItem;

/**
 * This Fragment includes all the Key Management operations, like:
 * <ul>
 * <li>See details
 * <li>List all saved keys
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
public class KeyManagementSectionFragment extends SherlockListFragment {
	ActionMode mMode;
	private Integer selectedItemID;
	private Integer selectedItemPosition;
	static PersonalKeyController personalKeyController;
	static SubjectController subjectController;
	List<SubjectDAO> subjectList;

	private static final int MENU_ADD = 0;
	private static final int MENU_IMPORT = 1;

	@Override
	public void onActivityCreated(Bundle savedInstanceState) {
		super.onActivityCreated(savedInstanceState);
		setHasOptionsMenu(true);
		Log.i(PKITrustNetworkActivity.TAG, "KEY MANAGEMENT onActivityCreated: "
				+ savedInstanceState);

		if (personalKeyController == null) {
			personalKeyController = new PersonalKeyController(getActivity());

		}
		if (subjectController == null) {
			subjectController = new SubjectController(getActivity());
		}

		try {
			subjectList = subjectController.getAll();
			// Clean the list of subject, removing the ones that doesn't have at
			// least one key
			Iterator<SubjectDAO> it = subjectList.iterator();
			while (it.hasNext()) {
				SubjectDAO subject = it.next();
				subject.setKeyList(personalKeyController.getBySubjectId(subject
						.getId()));
				if (subject.getKeyList().size() <= 0) {
					it.remove();
				}
			}

			/*
			 * for (SubjectDAO subject : subjectList) {
			 * subject.setKeyList(certificateController.getBySubjectId(subject
			 * .getId())); }
			 */
			SubjectListAdapter adapter = new SubjectListAdapter(getActivity(),
					subjectList);
			setListAdapter(adapter);
		} catch (DBException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
			e.printStackTrace();
			Toast.makeText(getActivity(), R.string.error_db_load_key,
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
						selectedItemPosition = pos;
						return false;
					}
				});
	}

	@Override
	public void onCreateOptionsMenu(Menu menu, MenuInflater inflater) {
		// Place an action bar item for add new Key.
		MenuItem itemAdd_key = menu.add(0, MENU_ADD, 0, R.string.menu_add);
		itemAdd_key.setIcon(R.drawable.ic_action_key_add);
		itemAdd_key.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

		// Place an action bar item for import a Key.
		MenuItem itemImport = menu.add(0, MENU_IMPORT, 0, R.string.menu_import);
		itemImport.setIcon(R.drawable.ic_action_key_import);
		itemImport.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);
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
					PKITrustNetworkActivity.KEY);
			intent.putExtra(PKITrustNetworkActivity.EXTRA_NEXT_OPERATION,
					PKITrustNetworkActivity.IMPORT);
			startActivity(intent);
			return true;
		case MENU_ADD:
			// Show create new key fragment
			intent = new Intent(getActivity(), SelectOwnerActivity.class);
			intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
					PKITrustNetworkActivity.KEY);
			intent.putExtra(PKITrustNetworkActivity.EXTRA_NEXT_OPERATION,
					PKITrustNetworkActivity.ADD);
			startActivity(intent);
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}

	private final class AnActionMode implements ActionMode.Callback {
		@Override
		public boolean onCreateActionMode(ActionMode mode, Menu menu) {

			menu.add(0, 0, 0, R.string.menu_details)
					.setIcon(R.drawable.ic_action_key_details)
					.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

			menu.add(0, 1, 1, R.string.menu_delete)
					.setIcon(R.drawable.ic_action_key_delete)
					.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

			menu.add(0, 2, 2, R.string.menu_export)
					.setIcon(R.drawable.ic_action_key_export)
					.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

			menu.add(0, 3, 3, R.string.menu_send)
					.setIcon(R.drawable.ic_action_key_send)
					.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);
			return true;
		}

		@Override
		public boolean onPrepareActionMode(ActionMode mode, Menu menu) {
			return false;
		}

		@Override
		public boolean onActionItemClicked(ActionMode mode, MenuItem item) {
			switch (item.getItemId()) {
			case 0:
				// See details
				Intent intent = new Intent(getActivity(),
						KeyDetailsActivity.class);
				List<PersonalKeyDAO> keyList = subjectList.get(
						selectedItemPosition).getKeyList();
				int[] idArray = new int[keyList.size()];
				for (int i = 0; i < keyList.size(); i++) {
					idArray[i] = keyList.get(i).getId();
				}
				intent.putExtra(KeyDetailsActivity.EXTRA_ID_ARRAY, idArray);
				intent.putExtra(KeyDetailsActivity.EXTRA_CURRENT_ITEM, 0);
				getActivity().startActivity(intent);
				break;
			case 1:
				// Delete all keys
				Toast.makeText(
						getActivity(),
						"Got click: " + item.getItemId() + "\nList item:"
								+ selectedItemID + "\nList Position:"
								+ selectedItemPosition, Toast.LENGTH_SHORT)
						.show();
				mode.finish();
				break;
			case 2:
				// Export all keys
				break;
			case 3:
				// Send all Keys
				break;
			default:
				Toast.makeText(getActivity(),
						getString(R.string.menu_option_error),
						Toast.LENGTH_SHORT).show();
				mode.finish();
			}

			return true;
		}

		@Override
		public void onDestroyActionMode(ActionMode mode) {
		}
	}
}
