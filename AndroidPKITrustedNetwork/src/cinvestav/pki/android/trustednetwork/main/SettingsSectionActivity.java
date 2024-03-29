/**
 *  Created on  : 24/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	This Fragment includes all the Secure operations, like: 
 *  <ul> 
 *  <li> Change default cipher and key size
 *  <li> Compatibility options
 *  <li> Hash algorithm preferences
 *  </ul>
 */
package cinvestav.pki.android.trustednetwork.main;

import android.content.Intent;
import android.os.Bundle;
import android.support.v4.app.NavUtils;
import android.support.v4.app.TaskStackBuilder;
import cinvestav.pki.android.trustednetwork.R;

import com.actionbarsherlock.app.ActionBar;
import com.actionbarsherlock.app.SherlockFragmentActivity;
import com.actionbarsherlock.view.MenuItem;

/**
 * This Fragment includes all the settings operations, like:
 * <ul>
 * <li>Change default cipher and key size
 * <li>Compatibility options
 * <li>Hash algorithm preferences
 * </ul>
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 24/08/2012
 * @version 1.0
 */
public class SettingsSectionActivity extends SherlockFragmentActivity {
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.main_settings);

		// Set up action bar.
		final ActionBar actionBar = getSupportActionBar();

		// Specify that the Home button should show an "Up" caret, indicating
		// that touching the
		// button will take the user one step up in the application's hierarchy.
		actionBar.setDisplayHomeAsUpEnabled(true);
		actionBar.setDisplayShowTitleEnabled(true);
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		switch (item.getItemId()) {
		case android.R.id.home:
			// This is called when the Home (Up) button is pressed in the action
			// bar.
			// Create a simple intent that starts the hierarchical parent
			// activity and
			// use NavUtils in the Support Package to ensure proper handling of
			// Up.
			Intent upIntent = new Intent(this, PKITrustNetworkActivity.class);
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
			return true;
		}
		return super.onOptionsItemSelected(item);
	}
}
