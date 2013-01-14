/**
 *  Created on  : 27/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Activity for selecting the certificate key and signing options, like: key
 * origin (new or existing) and certificate signing type (self-signed or CA
 * signed)
 *  
 */
package cinvestav.pki.android.trustednetwork.add;

import android.content.Intent;
import android.os.Bundle;
import android.support.v4.app.NavUtils;
import android.support.v4.app.TaskStackBuilder;
import android.widget.ArrayAdapter;
import android.widget.Spinner;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;
import cinvestav.pki.android.trustednetwork.selection.SelectHolderWithKeysActivity;
import cinvestav.pki.android.trustednetwork.selection.SelectOwnerActivity;

import com.actionbarsherlock.app.ActionBar;
import com.actionbarsherlock.app.SherlockFragmentActivity;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuItem;

/**
 * Activity for selecting the certificate key and signing options, like: key
 * origin (new or existing) and certificate signing type (self-signed or CA
 * signed)
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 27/09/2012
 * @version 1.0
 */
public class AddNewCertificateSelectKeyOptionsActivity extends
		SherlockFragmentActivity {

	static final int MENU_NEXT = 0;


	private static final int KEY_ORIGIN_EXISTING = 0;

	Spinner spinnerCertificateSignType;
	Spinner spinnerKeyOrigin;

	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		setContentView(R.layout.add_certificate_key_options);

		// Set up action bar.
		final ActionBar actionBar = getSupportActionBar();

		// Specify that the Home button should show an "Up" caret, indicating
		// that touching the
		// button will take the user one step up in the application's hierarchy.
		actionBar.setDisplayHomeAsUpEnabled(true);
		actionBar.setSubtitle(R.string.subtitle_cert_add);

		spinnerKeyOrigin = (Spinner) findViewById(R.id.spinnerKeyPairOrigin);
		ArrayAdapter<CharSequence> adapter = ArrayAdapter.createFromResource(
				getApplicationContext(), R.array.keyOrigin,
				android.R.layout.simple_spinner_item);
		adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		spinnerKeyOrigin.setAdapter(adapter);

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
		Integer keyOrigin = spinnerKeyOrigin.getSelectedItemPosition();

		Intent intent;
		if (keyOrigin == AddNewCertificateSelectKeyOptionsActivity.KEY_ORIGIN_EXISTING) {
			// Select Holder intent
			intent = new Intent(this, SelectHolderWithKeysActivity.class);
		} else {
			intent = new Intent(this, SelectOwnerActivity.class);
		}

		intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
				PKITrustNetworkActivity.CERTIFICATE);
		intent.putExtra(PKITrustNetworkActivity.EXTRA_NEXT_OPERATION,
				PKITrustNetworkActivity.ADD);
		// intent.putExtra(EXTRA_KEY_ORIGIN, keyOrigin);

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
				PKITrustNetworkActivity.CERTIFICATE);
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
