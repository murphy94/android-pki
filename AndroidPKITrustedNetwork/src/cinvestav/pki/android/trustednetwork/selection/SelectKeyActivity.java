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

import android.content.Intent;
import android.os.Bundle;
import android.support.v4.app.NavUtils;
import android.support.v4.app.TaskStackBuilder;
import android.widget.Toast;
import cinvestav.android.pki.db.controller.PersonalKeyController;
import cinvestav.android.pki.db.dao.PersonalKeyDAO;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.add.AddNewCertificateActivity;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;
import cinvestav.pki.android.trustednetwork.main.SecureSectionActivity;

import com.actionbarsherlock.app.ActionBar;
import com.actionbarsherlock.app.SherlockFragmentActivity;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuItem;

/**
 * Activity that contains a list of the keys owned by a determined subject or if
 * no subject is specified list all the keys saved in the data base
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 31/08/2012
 * @version 1.0
 */
public class SelectKeyActivity extends SherlockFragmentActivity {

	List<PersonalKeyDAO> keyList;

	public static final String EXTRA_SELECTED_PERSONAL_KEY_ID = "EXTRA_SELECTED_PERSONAL_KEY_ID";

	public static final int MENU_NEXT = 0;

	private int nextOperation;
	private int current_option;
	static PersonalKeyController personalKeyController;
	private int subjectId;
	SelectKeyFragment listFragment;

	public SelectKeyActivity() {
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
		SelectKeyActivity.personalKeyController = personalKeyController;
	}

	public static SelectKeyActivity newInstance(
			PersonalKeyController personalKeyController) {
		SelectKeyActivity f = new SelectKeyActivity();
		SelectKeyActivity.setPersonalKeyController(personalKeyController);
		return f;
	}

	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		// setContentView(R.layout.select_key);
		setSupportProgressBarIndeterminateVisibility(false);

		// Set up action bar.
		final ActionBar actionBar = getSupportActionBar();

		// Specify that the Home button should show an "Up" caret, indicating
		// that touching the
		// button will take the user one step up in the application's hierarchy.
		actionBar.setDisplayHomeAsUpEnabled(true);
		actionBar.setSubtitle(R.string.subtitle_select_key);

		subjectId = getIntent().getIntExtra(
				SelectHolderWithKeysActivity.EXTRA_SELECTED_HOLDER_ID, 0);
		current_option = this.getIntent().getExtras()
				.getInt(PKITrustNetworkActivity.CURRENT_OPTION);
		nextOperation = this.getIntent().getExtras()
				.getInt(PKITrustNetworkActivity.EXTRA_NEXT_OPERATION);

		if (personalKeyController == null) {
			personalKeyController = new PersonalKeyController(
					getApplicationContext());
		}

		if (getSupportFragmentManager().findFragmentById(android.R.id.content) == null) {
			listFragment = SelectKeyFragment.newInstance(personalKeyController,
					subjectId);
			getSupportFragmentManager().beginTransaction()
					.add(android.R.id.content, listFragment, "ListFragment")
					.commit();
		} else {
			listFragment = (SelectKeyFragment) getSupportFragmentManager()
					.findFragmentByTag("ListFragment");
		}
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
		// Get the selected owner ID and validate that in fact one subject is
		// selected

		int selectedKeyID = listFragment.getSelectedKeyId();
		if (selectedKeyID == 0) {
			Toast.makeText(this, R.string.error_empty_key, Toast.LENGTH_SHORT)
					.show();
			return;
		}

		Intent intent;

		if (nextOperation == PKITrustNetworkActivity.ADD) {
			// Show create new certificate Activity
			intent = new Intent(getApplicationContext(),
					AddNewCertificateActivity.class);
			intent.putExtra(SelectOwnerActivity.EXTRA_SELECTED_OWNER_ID,
					subjectId);
			intent.putExtra(EXTRA_SELECTED_PERSONAL_KEY_ID, selectedKeyID);
			intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
					PKITrustNetworkActivity.CERTIFICATE);

			startActivity(intent);

		} else if (nextOperation == PKITrustNetworkActivity.IMPORT) {
			// Import certificates
		} else if (nextOperation == PKITrustNetworkActivity.SIGN) {
			intent = new Intent(getApplicationContext(),
					SecureSectionActivity.class);

			intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
					current_option);
			intent.putExtra(SecureSectionActivity.SELECTED_PRIVATE_KEY_SIGN,
					selectedKeyID);
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
			intent.putExtra(SecureSectionActivity.SELECTED_INPUT, getIntent()
					.getExtras().getInt(SecureSectionActivity.SELECTED_INPUT));
			intent.putExtra(SecureSectionActivity.EXISTING_INPUT, getIntent()
					.getExtras()
					.getString(SecureSectionActivity.EXISTING_INPUT));
			intent.putExtra(
					SecureSectionActivity.EXISTING_OUTPUT_FILE,
					getIntent().getExtras().getString(
							SecureSectionActivity.EXISTING_OUTPUT_FILE));
			intent.putExtra(
					SecureSectionActivity.SELECTED_OPERATION,
					getIntent().getExtras().getInt(
							SecureSectionActivity.SELECTED_OPERATION));
			intent.setFlags(Intent.FLAG_ACTIVITY_NO_HISTORY);
			startActivity(intent);
		} else if (nextOperation == PKITrustNetworkActivity.DECIPHER) {
			intent = new Intent(getApplicationContext(),
					SecureSectionActivity.class);

			intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
					current_option);
			intent.putExtra(
					SecureSectionActivity.SELECTED_PRIVATE_KEY_SIGN,
					getIntent()
							.getExtras()
							.getInt(SecureSectionActivity.SELECTED_PRIVATE_KEY_DECIPHER));
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
					selectedKeyID);
			intent.putExtra(SecureSectionActivity.SELECTED_INPUT, getIntent()
					.getExtras().getInt(SecureSectionActivity.SELECTED_INPUT));
			intent.putExtra(SecureSectionActivity.EXISTING_INPUT, getIntent()
					.getExtras()
					.getString(SecureSectionActivity.EXISTING_INPUT));
			intent.putExtra(
					SecureSectionActivity.EXISTING_OUTPUT_FILE,
					getIntent().getExtras().getString(
							SecureSectionActivity.EXISTING_OUTPUT_FILE));
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
}
