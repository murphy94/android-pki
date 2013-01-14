/**
 *  Created on  : 29/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Activity that contains a list of the current registered subjects so the user
 * could select one. In addition to this, this activity has the option to add a
 * new subject, this fragment will only show the subject that has at least one
 * private key registered
 */
package cinvestav.pki.android.trustednetwork.selection;

import java.util.Iterator;
import java.util.List;

import android.content.Intent;
import android.os.Bundle;
import android.support.v4.app.NavUtils;
import android.support.v4.app.TaskStackBuilder;
import android.util.Log;
import android.view.View;
import android.widget.ListView;
import android.widget.Toast;
import cinvestav.android.pki.db.controller.PersonalKeyController;
import cinvestav.android.pki.db.controller.SubjectController;
import cinvestav.android.pki.db.dao.SubjectDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.adapter.HolderListAdapter;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;
import cinvestav.pki.android.trustednetwork.main.SecureSectionActivity;

import com.actionbarsherlock.app.ActionBar;
import com.actionbarsherlock.app.SherlockListActivity;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuItem;

/**
 * Activity that contains a list of the current registered subjects so the user
 * could select one. In addition to this, this activity has the option to add a
 * new subject, this fragment will only show the subject that has at least one
 * private key registered
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 29/09/2012
 * @version 1.0
 */
public class SelectHolderWithKeysActivity extends SherlockListActivity {

	List<SubjectDAO> subjectList;
	public static final String EXTRA_SELECTED_HOLDER_ID = "EXTRA_SELECTED_CA_ID";
	public static final int MENU_NEXT = 0;

	private int current_option;
	private int nextOperation;
	static SubjectController subjectController;
	static PersonalKeyController personalKeyController;

	public SelectHolderWithKeysActivity() {
		super();
	}

	/**
	 * @return the certificateController
	 */
	public static SubjectController getSubjectController() {
		return subjectController;
	}

	/**
	 * @param certificateController
	 *            the certificateController to set
	 */
	public static void setSubjectController(SubjectController subjectController) {
		SelectHolderWithKeysActivity.subjectController = subjectController;
	}

	public static SelectHolderWithKeysActivity newInstance(
			SubjectController subjectController) {
		SelectHolderWithKeysActivity f = new SelectHolderWithKeysActivity();
		SelectHolderWithKeysActivity.setSubjectController(subjectController);
		return f;
	}

	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		setContentView(R.layout.select_holder_with_keys);
		setSupportProgressBarIndeterminateVisibility(false);

		current_option = this.getIntent().getExtras()
				.getInt(PKITrustNetworkActivity.CURRENT_OPTION);
		nextOperation = this.getIntent().getExtras()
				.getInt(PKITrustNetworkActivity.EXTRA_NEXT_OPERATION);

		// Set up action bar.
		final ActionBar actionBar = getSupportActionBar();

		// Specify that the Home button should show an "Up" caret, indicating
		// that touching the
		// button will take the user one step up in the application's hierarchy.
		actionBar.setDisplayHomeAsUpEnabled(true);
		actionBar.setSubtitle(R.string.subtitle_select_holder);

		try {

			// Init controllers if necessary
			if (subjectController == null) {
				subjectController = new SubjectController(
						getApplicationContext());
			}

			if (personalKeyController == null) {
				personalKeyController = new PersonalKeyController(
						getApplicationContext());
			}

			subjectList = subjectController.getAll();
			// Clean the list of subject, removing the ones that doesn't have at
			// least one private key
			Iterator<SubjectDAO> it = subjectList.iterator();
			while (it.hasNext()) {
				SubjectDAO subject = it.next();
				subject.setKeyList(personalKeyController
						.getAllPrivateKeys(subject.getId()));
				if (subject.getKeyList().size() <= 0) {
					it.remove();
				}
			}

			HolderListAdapter adapter = new HolderListAdapter(this, subjectList);
			setListAdapter(adapter);

		} catch (DBException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
			e.printStackTrace();
			Toast.makeText(getApplicationContext(),
					R.string.error_db_load_owner, Toast.LENGTH_LONG).show();
		}

		getListView().setChoiceMode(ListView.CHOICE_MODE_SINGLE);
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Place an action bar item for go the next view of the flow
		MenuItem itemNext = menu.add(0, 0, 0, R.string.menu_next);
		itemNext.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

		return super.onCreateOptionsMenu(menu);
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		switch (item.getItemId()) {
		case android.R.id.home:
			returnHome();
			return true;
		case MENU_NEXT:
			goToNext();
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}

	public void goToNext() {
		// Get the selected Holder ID and validate that in fact one subject is
		// selected

		int selectedHolderID = ((HolderListAdapter) getListAdapter())
				.getSelectedId();
		if (selectedHolderID == 0) {
			Toast.makeText(this, R.string.error_empty_holder,
					Toast.LENGTH_SHORT).show();
			return;
		}

		Intent intent;

		if (nextOperation == PKITrustNetworkActivity.ADD) {
			// Select key activity
			// Show create new key fragment
			intent = new Intent(getApplicationContext(),
					SelectKeyActivity.class);
			intent.putExtra(EXTRA_SELECTED_HOLDER_ID, selectedHolderID);
			intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
					current_option);
			intent.putExtra(PKITrustNetworkActivity.EXTRA_NEXT_OPERATION,
					PKITrustNetworkActivity.ADD);
			startActivity(intent);

		} else if (nextOperation == PKITrustNetworkActivity.IMPORT) {
			// Import certificates
		} else if (nextOperation == PKITrustNetworkActivity.SIGN
				|| nextOperation == PKITrustNetworkActivity.DECIPHER) {
			intent = new Intent(getApplicationContext(),
					SelectKeyActivity.class);
			intent.putExtra(EXTRA_SELECTED_HOLDER_ID, selectedHolderID);
			intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
					current_option);
			intent.putExtra(PKITrustNetworkActivity.EXTRA_NEXT_OPERATION,
					nextOperation);

			intent.putExtra(
					SecureSectionActivity.SELECTED_CERTIFICATE_CIPHER,
					getIntent().getExtras().getInt(
							SecureSectionActivity.SELECTED_CERTIFICATE_CIPHER));
			intent.putExtra(
					SecureSectionActivity.SELECTED_CERTIFICATE_VERIFY,
					getIntent().getExtras().getInt(
							SecureSectionActivity.SELECTED_CERTIFICATE_VERIFY));
			intent.putExtra(
					SecureSectionActivity.SELECTED_PRIVATE_KEY_DECIPHER,
					getIntent()
							.getExtras()
							.getInt(SecureSectionActivity.SELECTED_PRIVATE_KEY_DECIPHER));
			intent.putExtra(
					SecureSectionActivity.SELECTED_PRIVATE_KEY_SIGN,
					getIntent().getExtras().getInt(
							SecureSectionActivity.SELECTED_PRIVATE_KEY_SIGN));
			intent.putExtra(SecureSectionActivity.SELECTED_INPUT, getIntent()
					.getExtras().getInt(SecureSectionActivity.SELECTED_INPUT));
			intent.putExtra(
					SecureSectionActivity.EXISTING_OUTPUT_FILE,
					getIntent().getExtras().getString(
							SecureSectionActivity.EXISTING_OUTPUT_FILE));
			intent.putExtra(SecureSectionActivity.EXISTING_INPUT, getIntent()
					.getExtras()
					.getString(SecureSectionActivity.EXISTING_INPUT));
			intent.putExtra(
					SecureSectionActivity.SELECTED_OPERATION,
					getIntent().getExtras().getInt(
							SecureSectionActivity.SELECTED_OPERATION));
			intent.setFlags(Intent.FLAG_ACTIVITY_NO_HISTORY);
			startActivity(intent);
		}
	}

	/**
	 * This is called to return home in the application navigation scheme
	 */
	public void returnHome() {

		// This is called when the Home (Up) button is pressed in the action
		// bar.
		// Create a simple intent that starts the hierarchical parent
		// activity and
		// use NavUtils in the Support Package to ensure proper handling of
		// Up.
		Intent upIntent = new Intent(this, PKITrustNetworkActivity.class);

		upIntent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
				current_option);

		if (NavUtils.shouldUpRecreateTask(this, upIntent)) {
			// This activity is not part of the application's task, so
			// create a new task
			// with a synthesized back stack.
			TaskStackBuilder.create(this)
			// If there are ancestor activities, they should be added here.
					.addNextIntent(upIntent).startActivities();
			finish();
		} else {
			// This activity is part of the application's task, so simply
			// navigate up to the hierarchical parent activity.
			NavUtils.navigateUpTo(this, upIntent);
		}
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

		((HolderListAdapter) l.getAdapter()).setSelectedId((int) id);

	}

}