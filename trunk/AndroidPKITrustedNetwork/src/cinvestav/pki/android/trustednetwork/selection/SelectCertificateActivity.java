/**
 *  Created on  : 23/10/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	 Activity that contains a list of the keys owned by a determined subject or if
 * no subject is specified list all the certificates saved in the data base 
 * 
 */
package cinvestav.pki.android.trustednetwork.selection;

import java.util.List;

import android.content.Intent;
import android.os.Bundle;
import android.support.v4.app.NavUtils;
import android.support.v4.app.TaskStackBuilder;
import android.util.Log;
import android.view.View;
import android.widget.ListView;
import android.widget.Toast;
import cinvestav.android.pki.db.controller.CertificateController;
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.adapter.CertificatesSelectableListAdapter;
import cinvestav.pki.android.trustednetwork.details.CertificateDetailsActivity;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;
import cinvestav.pki.android.trustednetwork.main.SecureSectionActivity;

import com.actionbarsherlock.app.ActionBar;
import com.actionbarsherlock.app.SherlockListActivity;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuItem;

/**
 * Activity that contains a list of the certificates owned by a determined
 * subject or if no subject is specified list all the certificates saved in the
 * data base
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 23/10/2012
 * @version 1.0
 */
public class SelectCertificateActivity extends SherlockListActivity {

	List<CertificateDAO> certList;
	static CertificateController certificateController;
	private int holderId;

	public static final String EXTRA_SELECTED_HOLDER_ID = "EXTRA_SELECTED_HOLDER_ID";

	public static final int MENU_NEXT = 0;

	private int current_option;
	private int nextOperation;

	public SelectCertificateActivity() {
		super();
	}

	/**
	 * @return the certificateController
	 */
	public static CertificateController getCertificateController() {
		return certificateController;
	}

	/**
	 * @param certificateController
	 *            the certificateController to set
	 */
	public static void setCertificateController(
			CertificateController certificateController) {
		SelectCertificateActivity.certificateController = certificateController;
	}

	public static SelectCertificateActivity newInstance(
			CertificateController certificateController, Integer holderId) {
		SelectCertificateActivity f = new SelectCertificateActivity();
		SelectCertificateActivity
				.setCertificateController(certificateController);
		f.setHolderId(holderId);
		return f;
	}

	/**
	 * @return the holderId
	 */
	public int getHolderId() {
		return holderId;
	}

	/**
	 * @param holderId
	 *            the holderId to set
	 */
	public void setHolderId(int holderId) {
		this.holderId = holderId;
	}

	public Integer getSelectedCertificateId() {
		return ((CertificatesSelectableListAdapter) this.getListAdapter())
				.getSelectedId();
	}

	/**
	 * Gets the selected {@link CertificateDAO} object
	 * 
	 * @return The selected {@link CertificateDAO} object
	 */
	public CertificateDAO getSelectedCertificate() {
		return certList.get(((CertificatesSelectableListAdapter) this
				.getListAdapter()).getSelectedPosition());
	}

	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		if (certificateController == null) {
			certificateController = new CertificateController(
					getApplicationContext());
		}

		setContentView(R.layout.select_key);

		current_option = this.getIntent().getExtras()
				.getInt(PKITrustNetworkActivity.CURRENT_OPTION);
		nextOperation = this.getIntent().getExtras()
				.getInt(PKITrustNetworkActivity.EXTRA_NEXT_OPERATION);

		holderId = this.getIntent().getExtras()
				.getInt(EXTRA_SELECTED_HOLDER_ID);

		// Set up action bar.
		final ActionBar actionBar = getSupportActionBar();

		// Specify that the Home button should show an "Up" caret, indicating
		// that touching the
		// button will take the user one step up in the application's hierarchy.
		actionBar.setDisplayHomeAsUpEnabled(true);
		actionBar.setSubtitle(R.string.subtitle_select_certificate);

		try {
			// Get all the Certificates that belongs to the selected owner
			certList = certificateController.getByOwnerId(holderId);
			CertificatesSelectableListAdapter adapter = new CertificatesSelectableListAdapter(
					this, certList, certificateController);
			setListAdapter(adapter);

		} catch (DBException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
			e.printStackTrace();
			Toast.makeText(this, R.string.error_db_load_certs,
					Toast.LENGTH_LONG).show();
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

		((CertificatesSelectableListAdapter) l.getAdapter())
				.setSelectedId((int) id);

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

		int selectedCertificateID = ((CertificatesSelectableListAdapter) getListAdapter())
				.getSelectedId();
		if (selectedCertificateID == 0) {
			switch (current_option) {
			case PKITrustNetworkActivity.KEY:
				Toast.makeText(this, R.string.error_empty_owner,
						Toast.LENGTH_SHORT).show();
				break;
			case PKITrustNetworkActivity.CERTIFICATE:
				Toast.makeText(this, R.string.error_empty_holder,
						Toast.LENGTH_SHORT).show();
				break;
			case PKITrustNetworkActivity.TRUST_NETWORK:
				Toast.makeText(this, R.string.error_empty_holder,
						Toast.LENGTH_SHORT).show();
				break;

			default:
				break;
			}

			return;
		}

		Intent intent;
		if (nextOperation == PKITrustNetworkActivity.CIPHER) {
			intent = new Intent(getApplicationContext(),
					SecureSectionActivity.class);

			intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
					current_option);
			intent.putExtra(
					SecureSectionActivity.SELECTED_PRIVATE_KEY_SIGN,
					getIntent().getExtras().getInt(
							SecureSectionActivity.SELECTED_PRIVATE_KEY_SIGN));
			intent.putExtra(SecureSectionActivity.SELECTED_CERTIFICATE_CIPHER,
					selectedCertificateID);
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

		} else if (nextOperation == PKITrustNetworkActivity.VERIFY) {
			intent = new Intent(getApplicationContext(),
					SecureSectionActivity.class);

			intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
					current_option);
			intent.putExtra(
					SecureSectionActivity.SELECTED_PRIVATE_KEY_SIGN,
					getIntent().getExtras().getInt(
							SecureSectionActivity.SELECTED_PRIVATE_KEY_SIGN));
			intent.putExtra(
					SecureSectionActivity.SELECTED_CERTIFICATE_CIPHER,
					getIntent().getExtras().getInt(
							SecureSectionActivity.SELECTED_CERTIFICATE_CIPHER));
			intent.putExtra(SecureSectionActivity.SELECTED_CERTIFICATE_VERIFY,
					selectedCertificateID);
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

		}

		switch (current_option) {
		case PKITrustNetworkActivity.KEY:

			break;
		case PKITrustNetworkActivity.CERTIFICATE:

			break;
		case PKITrustNetworkActivity.CRL:
			break;
		case PKITrustNetworkActivity.TRUST_NETWORK:
			if (nextOperation == PKITrustNetworkActivity.ADD) {
				// Show the detail certificate information, so the user could
				// assign a trust level
				intent = new Intent(getApplicationContext(),
						CertificateDetailsActivity.class);
				intent.putExtra(
						CertificateDetailsActivity.EXTRA_TRUSTED_CERTIFICATE_ID,
						selectedCertificateID);
				intent.putExtra(
						CertificateDetailsActivity.EXTRA_LIST_OWNER_ID,
						this.getIntent()
								.getExtras()
								.getInt(CertificateDetailsActivity.EXTRA_LIST_OWNER_ID));
				intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
						PKITrustNetworkActivity.TRUST_NETWORK);
				startActivity(intent);

			} else if (nextOperation == PKITrustNetworkActivity.IMPORT) {
				// Import certificates
				/*
				 * intent = new Intent(getApplicationContext(),
				 * ImportCertificateActivity.class);
				 * intent.putExtra(EXTRA_SELECTED_OWNER_ID, selectedOwnerID);
				 * startActivity(intent);
				 */
			}
			break;
		default:
			return;
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
