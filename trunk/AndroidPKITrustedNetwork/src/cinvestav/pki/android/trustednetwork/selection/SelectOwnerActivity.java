/**
 *  Created on  : 31/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Activity that contains a list of the current registered subjects so the user
 * could select one. In addition to this, this activity has the option to add a
 * new owner
 */
package cinvestav.pki.android.trustednetwork.selection;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import android.content.Intent;
import android.os.Bundle;
import android.support.v4.app.NavUtils;
import android.support.v4.app.TaskStackBuilder;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;
import cinvestav.android.pki.db.controller.SubjectController;
import cinvestav.android.pki.db.dao.SubjectDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.android.pki.utils.DataBaseDictionary;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.adapter.OwnerListAdapter;
import cinvestav.pki.android.trustednetwork.add.AddNewKeyActivity;
import cinvestav.pki.android.trustednetwork.details.CertificateDetailsActivity;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;
import cinvestav.pki.android.trustednetwork.share.ImportCertificateActivity;
import cinvestav.pki.android.trustednetwork.share.ImportNewKeyActivity;

import com.actionbarsherlock.app.ActionBar;
import com.actionbarsherlock.app.SherlockListActivity;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuItem;

/**
 * Activity that contains a list of the current registered subjects so the user
 * could select one. In addition to this, this activity has the option to add a
 * new owner
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 31/08/2012
 * @version 1.0
 */
public class SelectOwnerActivity extends SherlockListActivity {

	List<SubjectDAO> subjectList;
	private EditText txtNewOwnerName;
	private LinearLayout mLinearLayout;
	public static final String EXTRA_SELECTED_OWNER_ID = "EXTRA_SELECTED_OWNER_ID";
	public static final int MENU_NEXT = 0;

	private int current_option;
	private int nextOperation;
	static SubjectController subjectController;

	public SelectOwnerActivity() {
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
		SelectOwnerActivity.subjectController = subjectController;
	}

	public static SelectOwnerActivity newInstance(
			SubjectController subjectController) {
		SelectOwnerActivity f = new SelectOwnerActivity();
		SelectOwnerActivity.setSubjectController(subjectController);
		return f;
	}

	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		setContentView(R.layout.select_owner);
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

		Log.i(PKITrustNetworkActivity.TAG, "OWNER ACTIVITY CREATED");
		try {
			if (subjectController == null) {
				subjectController = new SubjectController(
						getApplicationContext());
			}
			subjectList = subjectController.getAll();
			OwnerListAdapter adapter = new OwnerListAdapter(this, subjectList);
			setListAdapter(adapter);

			// get references to UI components
			txtNewOwnerName = (EditText) findViewById(R.id.txtOwnerName);
			switch (current_option) {
			case PKITrustNetworkActivity.KEY:
				actionBar.setSubtitle(R.string.subtitle_select_owner);
				txtNewOwnerName.setHint(R.string.lblOwnerAlias);
				break;
			case PKITrustNetworkActivity.CERTIFICATE:
				actionBar.setSubtitle(R.string.subtitle_select_holder);
				txtNewOwnerName.setHint(R.string.lblHolderAlias);
				break;
			case PKITrustNetworkActivity.TRUST_NETWORK:
				actionBar.setSubtitle(R.string.subtitle_select_list_owner);
				txtNewOwnerName.setHint(R.string.lblOwnerAlias);
				break;

			default:
				break;
			}
			mLinearLayout = (LinearLayout) findViewById(R.id.linearLayout_focus);

			TextView addNewOwner = (TextView) findViewById(R.id.lblImgAddNewOwner);

			addNewOwner.setOnClickListener(new View.OnClickListener() {

				@Override
				public void onClick(View v) {
					onClickAddNewOwner(txtNewOwnerName.getText().toString());
				}
			});

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
		// Get the selected owner ID and validate that in fact one subject is
		// selected

		int selectedOwnerID = ((OwnerListAdapter) getListAdapter())
				.getSelectedId();
		if (selectedOwnerID == 0) {
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
				Toast.makeText(this, R.string.error_empty_owner,
						Toast.LENGTH_SHORT).show();
				break;

			default:
				break;
			}

			return;
		}

		Intent intent;
		switch (current_option) {
		case PKITrustNetworkActivity.KEY:
			if (nextOperation == PKITrustNetworkActivity.ADD) {
				// Show create new key fragment
				intent = new Intent(getApplicationContext(),
						AddNewKeyActivity.class);
				intent.putExtra(EXTRA_SELECTED_OWNER_ID, selectedOwnerID);
				intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
						PKITrustNetworkActivity.KEY);
				startActivity(intent);
			} else if (nextOperation == PKITrustNetworkActivity.IMPORT) {
				intent = new Intent(getApplicationContext(),
						ImportNewKeyActivity.class);
				intent.putExtra(EXTRA_SELECTED_OWNER_ID, selectedOwnerID);
				startActivity(intent);
			}

			break;
		case PKITrustNetworkActivity.CERTIFICATE:

			if (nextOperation == PKITrustNetworkActivity.ADD) {
				// Show create new key fragment
				intent = new Intent(getApplicationContext(),
						AddNewKeyActivity.class);
				intent.putExtra(EXTRA_SELECTED_OWNER_ID, selectedOwnerID);
				intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
						PKITrustNetworkActivity.CERTIFICATE);

				startActivity(intent);

			} else if (nextOperation == PKITrustNetworkActivity.IMPORT) {
				// Import certificates
				intent = new Intent(getApplicationContext(),
						ImportCertificateActivity.class);
				intent.putExtra(EXTRA_SELECTED_OWNER_ID, selectedOwnerID);
				startActivity(intent);
			}

			break;
		case PKITrustNetworkActivity.CRL:
			break;
		case PKITrustNetworkActivity.TRUST_NETWORK:
			if (nextOperation == PKITrustNetworkActivity.ADD) {
				// Show the certificate holder list, in order to select the one
				// that should
				// be added to the trust list
				intent = new Intent(getApplicationContext(),
						SelectHolderWithCertificateActivity.class);
				intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
						PKITrustNetworkActivity.TRUST_NETWORK);
				intent.putExtra(PKITrustNetworkActivity.EXTRA_NEXT_OPERATION,
						PKITrustNetworkActivity.ADD);
				intent.putExtra(
						CertificateDetailsActivity.EXTRA_LIST_OWNER_ID,
						selectedOwnerID);
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

	/**
	 * OnClick listener for the Add new Owner image, add the owner to the data
	 * base, if this owner does not exist in it
	 * 
	 * @param ownerName
	 *            Name to be added to the owners table
	 */
	public void onClickAddNewOwner(String ownerName) {
		/*
		 * Filter map where: Key = Tag of the filter to be used, should be
		 * define in "DataBaseDictionary" Class, this tags must be written as a
		 * SQL WHERE clause using a PreparedStament form for example: 'DBfield =
		 * ?' or 'DBfield LIKE ?' Value = Must be a string array of 3 positions
		 * where: [0] = Value to be searched in the data base [1] = Data type,
		 * according to this, the PreparedStatemen will be constructed, the
		 * valid DataTypes are defined in the "DataBaseDictionary"
		 */
		Map<String, String[]> filterMap = new HashMap<String, String[]>();
		String[] value = new String[3];

		/*
		 * Establish filter properties
		 */
		// Filter value
		value[0] = ownerName + "";
		// Filter type
		value[1] = DataBaseDictionary.FILTER_TYPE_SUBJECT_NAME_EXACT;

		filterMap.put(DataBaseDictionary.FILTER_SUBJECT_NAME_EXACT, value);

		value = new String[3];

		/*
		 * Establish filter properties
		 */
		// Filter value
		value[0] = PKITrustNetworkActivity.ANDROID_ID + "";
		// Filter type
		value[1] = DataBaseDictionary.FILTER_TYPE_SUBJECT_DEVICE;

		filterMap.put(DataBaseDictionary.FILTER_SUBJECT_DEVICE, value);

		try {
			List<SubjectDAO> res = subjectController
					.getByAdvancedFilter(filterMap);
			if (res.isEmpty()) {
				SubjectDAO subject = new SubjectDAO();
				subject.setActive(Boolean.TRUE);
				subject.setDeviceID(PKITrustNetworkActivity.ANDROID_ID);
				subject.setName(ownerName);
				Integer id = subjectController.insert(subject);
				subject.setId(id);
				subjectList.add(subject);
				((OwnerListAdapter) getListAdapter()).notifyDataSetChanged();
				txtNewOwnerName.setText("");
				Toast.makeText(getApplicationContext(), R.string.msgAddOwnerOK,
						Toast.LENGTH_LONG).show();
			} else {
				Toast.makeText(getApplicationContext(),
						R.string.error_existing_owner, Toast.LENGTH_LONG)
						.show();
			}
		} catch (DBException e) {
			e.printStackTrace();
			Toast.makeText(getApplicationContext(),
					R.string.error_db_add_subject, Toast.LENGTH_LONG).show();
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.support.v4.app.Fragment#onResume()
	 */
	@Override
	public void onResume() {

		super.onResume();
		// do not give the editbox focus automatically when activity starts
		txtNewOwnerName.clearFocus();
		mLinearLayout.requestFocus();

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

		((OwnerListAdapter) l.getAdapter()).setSelectedId((int) id);

	}
}
