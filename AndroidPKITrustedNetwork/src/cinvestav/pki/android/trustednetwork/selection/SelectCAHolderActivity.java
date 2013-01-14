/**
 *  Created on  : 29/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	 Activity that contains a list of the current registered subjects so the user
 * could select one. This activity is used for selecting the CA that will sign a
 * certificate, so in the list of this activity, only the subjects with
 * certificates will be shown
 */
package cinvestav.pki.android.trustednetwork.selection;

import java.util.Iterator;
import java.util.List;

import android.content.Intent;
import android.os.Bundle;
import android.support.v4.app.NavUtils;
import android.support.v4.app.TaskStackBuilder;
import android.util.Log;
import android.util.SparseArray;
import android.view.View;
import android.widget.ListView;
import android.widget.Toast;
import cinvestav.android.pki.db.controller.CertificateController;
import cinvestav.android.pki.db.controller.PersonalKeyController;
import cinvestav.android.pki.db.controller.SubjectController;
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.android.pki.db.dao.SubjectDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.adapter.CAListAdapter;
import cinvestav.pki.android.trustednetwork.add.SignCertificateActivity;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

import com.actionbarsherlock.app.ActionBar;
import com.actionbarsherlock.app.SherlockListActivity;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuItem;

/**
 * Activity that contains a list of the current registered subjects so the user
 * could select one. This activity is used for selecting the CA that will sign a
 * certificate, so in the list of this activity, only the subjects with
 * certificates will be shown
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 29/09/2012
 * @version 1.0
 */
public class SelectCAHolderActivity extends SherlockListActivity {

	List<SubjectDAO> subjectList;
	public static final String EXTRA_SELECTED_CA_ID = "EXTRA_SELECTED_CA_ID";
	

	public static final int MENU_NEXT = 0;

	private int current_option;
	static SubjectController subjectController;
	static CertificateController certificateController;
	private PersonalKeyController personalKeyController;

	public SelectCAHolderActivity() {
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
		SelectCAHolderActivity.subjectController = subjectController;
	}

	public static SelectCAHolderActivity newInstance(
			SubjectController subjectController) {
		SelectCAHolderActivity f = new SelectCAHolderActivity();
		SelectCAHolderActivity.setSubjectController(subjectController);
		return f;
	}

	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		setContentView(R.layout.select_holder_with_keys);
		setSupportProgressBarIndeterminateVisibility(false);

		current_option = this.getIntent().getExtras()
				.getInt(PKITrustNetworkActivity.CURRENT_OPTION);

		// Set up action bar.
		final ActionBar actionBar = getSupportActionBar();

		// Specify that the Home button should show an "Up" caret, indicating
		// that touching the
		// button will take the user one step up in the application's hierarchy.
		actionBar.setDisplayHomeAsUpEnabled(true);
		actionBar.setSubtitle(R.string.subtitle_select_ca);

		try {

			// Init controllers if necessary
			if (subjectController == null) {
				subjectController = new SubjectController(
						getApplicationContext());
			}

			if (certificateController == null) {
				certificateController = new CertificateController(
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
			SparseArray<Integer> certificateCount = new SparseArray<Integer>();
			while (it.hasNext()) {
				SubjectDAO subject = it.next();
				List<CertificateDAO> aux = certificateController
						.getByOwnerId(subject.getId());
				subject.setKeyList(personalKeyController
						.getAllPrivateKeys(subject.getId()));
				if (aux.size() <= 0 || subject.getKeyList().size() <= 0) {
					it.remove();
				} else {
					certificateCount.append(subject.getId(), aux.size());
				}
			}

			CAListAdapter adapter = new CAListAdapter(this, subjectList,
					certificateCount);
			setListAdapter(adapter);

		} catch (DBException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
			e.printStackTrace();
			Toast.makeText(getApplicationContext(), R.string.error_db_load_ca,
					Toast.LENGTH_LONG).show();
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

		int selectedCAID = ((CAListAdapter) getListAdapter()).getSelectedId();
		if (selectedCAID == 0) {
			Toast.makeText(this, R.string.error_empty_ca, Toast.LENGTH_SHORT)
					.show();
			return;
		}

		Intent intent;

		// Select Certificate activity
		// Show the select Certificate activity
		intent = new Intent(getApplicationContext(), SelectCAElementsActivity.class);
		// Put extra parameters, one for selected CA subject id and the other is
		// the id of the certificate that will be signed
		intent.putExtra(EXTRA_SELECTED_CA_ID, selectedCAID);
		intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
				current_option);
		intent.putExtra(SignCertificateActivity.EXTRA_CERTIFICATE_ID,
				getIntent().getIntExtra(SignCertificateActivity.EXTRA_CERTIFICATE_ID, 0));
		startActivity(intent);

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

		((CAListAdapter) l.getAdapter()).setSelectedId((int) id);

	}
}
