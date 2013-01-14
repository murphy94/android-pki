/**
 *  Created on  : 13/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Activity that contains the options for exporting a certificate like: encoding
 */
package cinvestav.pki.android.trustednetwork.share;

import java.io.File;
import java.security.cert.X509Certificate;

import android.content.Intent;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Environment;
import android.support.v4.app.FragmentTransaction;
import android.support.v4.app.NavUtils;
import android.support.v4.app.TaskStackBuilder;
import android.util.Log;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;
import cinvestav.android.pki.cryptography.utils.X509Utils;
import cinvestav.android.pki.db.controller.CertificateController;
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.common.SelectFileDialogFragment;
import cinvestav.pki.android.trustednetwork.details.CertificateDetailsActivity;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

import com.actionbarsherlock.app.ActionBar;
import com.actionbarsherlock.app.SherlockFragmentActivity;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuItem;
import com.actionbarsherlock.view.Window;

/**
 * Activity that contains the options for exporting a certificate like: encoding
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 13/09/2012
 * @version 1.0
 */
public class ExportCertificateActivity extends SherlockFragmentActivity {

	public static final String EXTRA_SELECTED_CERTIFICATE_ID = "EXTRA_SELECTED_CERTIFICATE_ID";
	public static final int REQUEST_OPEN_FILE_ID = 1;

	static final int MENU_ACCEPT = 0;
	static final int MENU_CANCEL = 1;

	Integer certificateID;
	CertificateDAO certificate;

	RelativeLayout layoutEncoding;
	Spinner spinnerEncoding;

	private X509Utils _X509Utils;

	String fileName;

	SelectFileDialogFragment selectFileFragment;

	CertificateController certificateController;

	ExportCertificateTask exportCertificateTask;

	public ExportCertificateActivity() {
		super();

	}

	/**
	 * Dummy layout that get focused when the activity starts
	 */
	private LinearLayout mLinearLayout;

	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		try {
			_X509Utils = new X509Utils();
		} catch (CryptoUtilsException e) {
			e.printStackTrace();
		}

		if (certificateController == null) {
			certificateController = new CertificateController(
					getApplicationContext());
		}

		// This has to be called before setContentView and you must use the
		// class in com.actionbarsherlock.view and NOT android.view
		requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

		setContentView(R.layout.export_cert);
		setSupportProgressBarIndeterminateVisibility(false);

		// Set up action bar.
		final ActionBar actionBar = getSupportActionBar();

		// Specify that the Home button should show an "Up" caret, indicating
		// that touching the
		// button will take the user one step up in the application's hierarchy.
		actionBar.setDisplayHomeAsUpEnabled(true);
		actionBar.setSubtitle(R.string.subtitle_cert_export);

		mLinearLayout = (LinearLayout) findViewById(R.id.linearLayout_focus);

		// Get intent Extras, in order to obtain the selected certificate id
		certificateID = getIntent().getIntExtra(
				CertificateDetailsActivity.EXTRA_CURRENT_CERTIFICATE_ID, 0);

		// Load certificate information from database
		try {
			certificate = certificateController.getById(certificateID);
			certificateController.getCertificateDetails(certificate);

		} catch (DBException e) {
			Toast.makeText(this, R.string.error_db_load_cert,
					Toast.LENGTH_SHORT).show();
			Log.e(PKITrustNetworkActivity.TAG, e.toString(), e);
			returnHome();
		}

		// Init certificate default name
		fileName = getDefaultFileName();
		File f = new File(fileName);
		if (!f.getParentFile().exists()) {
			f.getParentFile().mkdir();
		}

		((TextView) findViewById(R.id.txtCertificateId)).setText(certificate
				.getId().toString());
		((TextView) findViewById(R.id.txtCertificateSerialNumber))
				.setText(certificate.getSerialNumber().toString());

		if (savedInstanceState == null) {
			// First-time init; create fragment to embed in activity.
			FragmentTransaction ft = getSupportFragmentManager()
					.beginTransaction();
			selectFileFragment = SelectFileDialogFragment.newInstance(
					R.string.dialog_select_file_title,
					R.string.lblMessageExportFile, "", fileName, REQUEST_OPEN_FILE_ID);
			ft.add(R.id.embedded, selectFileFragment);
			ft.commit();
		}

		layoutEncoding = ((RelativeLayout) findViewById(R.id.layoutEncoding));
		layoutEncoding.setVisibility(View.VISIBLE);
		((TextView) findViewById(R.id.lblRecomended))
				.setVisibility(View.VISIBLE);

		spinnerEncoding = (Spinner) findViewById(R.id.spinnerEncoding);
		ArrayAdapter<CharSequence> adapter = ArrayAdapter.createFromResource(
				getApplicationContext(), R.array.arrayEncoding,
				android.R.layout.simple_spinner_item);
		adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		spinnerEncoding.setAdapter(adapter);
		spinnerEncoding.setSelection(0);
		// layoutPasswordCertificate.setVisibility(RelativeLayout.VISIBLE);

	}

	/**
	 * Creates a default certificate suffix depending on the certificate type
	 * 
	 * @param certificateType
	 * @return
	 */
	public String getDefaultFileName() {
		String res = Environment.getExternalStorageDirectory()
				+ "/PKI_Trust_Network/X509Certificate";
		return res;
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Place an action bar item for export the Certificate.
		MenuItem itemExport_certificate = menu.add(0, MENU_ACCEPT, 0,
				R.string.menu_export);
		itemExport_certificate.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

		// Place an action bar item for cancel the creation of the new
		// Certificate.
		MenuItem itemCancel = menu.add(0, MENU_CANCEL, 1, R.string.menu_cancel);
		itemCancel.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

		return super.onCreateOptionsMenu(menu);
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		switch (item.getItemId()) {
		case android.R.id.home:
			returnHome();
			return true;
		case MENU_ACCEPT:
			export();
			// update();
			return true;
		case MENU_CANCEL:
			returnHome();
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}

	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data) {
		switch (requestCode) {
		case REQUEST_OPEN_FILE_ID: {
			if (resultCode == RESULT_OK && data != null) {
				String filename = data.getDataString();
				if (filename != null) {
					// Get rid of URI prefix:
					if (filename.startsWith("file://")) {
						filename = filename.substring(7);
					}
					// replace %20 and so on
					filename = Uri.decode(filename);

					((EditText) selectFileFragment.getView().findViewById(
							R.id.txtFileName)).setText(filename);
					fileName = filename;

				}
			}
			return;
		}

		default: {
			break;
		}
		}
		super.onActivityResult(requestCode, resultCode, data);
	}

	/**
	 * Export the selected certificate to the selected file using the selected
	 * configurations
	 */
	public void export() {

		fileName = ((EditText) selectFileFragment.getView().findViewById(
				R.id.txtFileName)).getText().toString();

		// If the task is not null, its running so make the user aware of it
		if (exportCertificateTask == null
				|| !exportCertificateTask.getStatus().equals(
						AsyncTask.Status.RUNNING)) {
			exportCertificateTask = new ExportCertificateTask();
			exportCertificateTask.execute(certificate);
		} else {
			Toast.makeText(this, R.string.msgWorking, Toast.LENGTH_SHORT)
					.show();
		}

	}

	/**
	 * This is called to return home in the application navigation scheme
	 */
	private void returnHome() {

		if (exportCertificateTask != null) {
			exportCertificateTask.cancel(true);
		}

		// This is called when the Home (Up) button is pressed in the action
		// bar.
		// Create a simple intent that starts the hierarchical parent
		// activity and
		// use NavUtils in the Support Package to ensure proper handling of
		// Up.
		Intent upIntent;
		upIntent = new Intent(this, CertificateDetailsActivity.class);
		upIntent.putExtra(CertificateDetailsActivity.EXTRA_OWNER_ID,
				certificate.getOwner().getId());
		upIntent.putExtra(
				CertificateDetailsActivity.EXTRA_CURRENT_CERTIFICATE_ID,
				certificateID);

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
	 * @see android.support.v4.app.Fragment#onResume()
	 */
	@Override
	public void onResume() {

		super.onResume();
		// do not give the editbox focus automatically when activity starts
		// txtNewOwnerName.clearFocus();
		mLinearLayout.requestFocus();

	}

	/**
	 * Inner class that create an asynchronous task in which a
	 * {@link RSAPrivateCertificate} is exported
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class ExportCertificateTask extends
			AsyncTask<CertificateDAO, Void, Boolean> {

		@Override
		protected void onPreExecute() {
			// Enable the indeterminate progress icon on the action bar
			setSupportProgressBarIndeterminateVisibility(true);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see android.os.AsyncTask#doInBackground(Params[])
		 */
		@Override
		protected Boolean doInBackground(CertificateDAO... params) {

			try {
				X509Certificate x509Certificate = _X509Utils.decode(certificate
						.getCertificateStr().getBytes());

				if (spinnerEncoding.getSelectedItemPosition() == 0) {
					fileName += ".pem";

					_X509Utils.saveCertificate(fileName, x509Certificate,
							CryptoUtils.ENCODING_PEM);
				} else {
					fileName += ".der";
					_X509Utils.saveCertificate(fileName, x509Certificate,
							CryptoUtils.ENCODING_DER);
				}
				Log.i(PKITrustNetworkActivity.TAG, "EXPORT CERTIFICATE: "
						+ fileName);
			} catch (CryptoUtilsException e) {
				e.printStackTrace();
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
				return Boolean.FALSE;
			}
			return Boolean.TRUE;
		}

		@Override
		protected void onPostExecute(Boolean res) {
			if (res) {
				Toast.makeText(getApplicationContext(),
						R.string.msgExportCertificateOK, Toast.LENGTH_LONG)
						.show();
				returnHome();
			} else {
				Toast.makeText(getApplicationContext(),
						R.string.error_cert_export, Toast.LENGTH_LONG).show();
			}
			// Disable the indeterminate progress icon on the action bar
			setSupportProgressBarIndeterminateVisibility(false);
		}
	}
}
