/**
 *  Created on  : 05/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Activity for creating a new key pair
 */
package cinvestav.pki.android.trustednetwork.share;

import java.security.cert.Certificate;
import java.util.concurrent.ExecutionException;

import android.content.Intent;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v4.app.DialogFragment;
import android.support.v4.app.FragmentTransaction;
import android.support.v4.app.NavUtils;
import android.support.v4.app.TaskStackBuilder;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.Toast;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.key.ECKeyPair;
import cinvestav.android.pki.cryptography.key.ECPrivateKey;
import cinvestav.android.pki.cryptography.key.ECPublicKey;
import cinvestav.android.pki.cryptography.key.RSAKeyPair;
import cinvestav.android.pki.cryptography.key.RSAPrivateKey;
import cinvestav.android.pki.cryptography.key.RSAPublicKey;
import cinvestav.android.pki.cryptography.utils.AsymmetricCryptoUtils;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;
import cinvestav.android.pki.cryptography.utils.DigestCryptoUtils;
import cinvestav.android.pki.db.controller.PersonalKeyController;
import cinvestav.android.pki.db.dao.PersonalKeyDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.common.MyPasswordDialogFragment;
import cinvestav.pki.android.trustednetwork.common.MyPasswordDialogFragment.OnPositiveButtonClickListener;
import cinvestav.pki.android.trustednetwork.common.MyPasswordPKCSDialogFragment;
import cinvestav.pki.android.trustednetwork.common.SelectFileDialogFragment;
import cinvestav.pki.android.trustednetwork.details.KeyDetailsActivity;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;
import cinvestav.pki.android.trustednetwork.selection.SelectOwnerActivity;

import com.actionbarsherlock.app.ActionBar;
import com.actionbarsherlock.app.SherlockFragmentActivity;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuItem;
import com.actionbarsherlock.view.Window;

/**
 * Fragment Activity for creating a new key pair
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 05/09/2012
 * @version 1.0
 */
public class ImportNewKeyActivity extends SherlockFragmentActivity {

	static final int MENU_ACCEPT = 0;
	static final int MENU_CANCEL = 1;
	public static final int REQUEST_OPEN_FILE_ID =1;

	static final int RSA_PUBLIC = 0;
	static final int RSA_PRIVATE = 1;
	static final int RSA_PKCS = 2;
	static final int EC_PUBLIC = 3;
	static final int EC_PRIVATE = 4;
	static final int EC_PKCS = 5;
	static final int UNKNOWN = 6;

	/**
	 * Password for the private key
	 */
	String password;

	/**
	 * Password for the private PKCS file
	 */
	String passwordPKCS;

	/**
	 * Owner of the key
	 */
	Integer subjectID;

	/**
	 * Comment for that key to import
	 */
	EditText txtComment;

	/**
	 * Asynchronous task for importing RSA Public keys
	 */
	ImportRSAPublicKeyTask importRSAPublicKeyTask;

	/**
	 * Asynchronous task for importing RSA Private keys
	 */
	ImportRSAPrivateKeyTask importRSAPrivateKeyTask;

	/**
	 * Asynchronous task for importing RSA PKCS keys
	 */
	ImportRSAPKCSTask importRSAPKCSTask;

	/**
	 * Asynchronous task for importing RSA Public keys
	 */
	ImportECPublicKeyTask importECPublicKeyTask;

	/**
	 * Asynchronous task for importing RSA Private keys
	 */
	ImportECPrivateKeyTask importECPrivateKeyTask;

	/**
	 * Asynchronous task for importing RSA PKCS keys
	 */
	ImportECPKCSTask importECPKCSTask;

	String fileName = "";

	SelectFileDialogFragment selectFileFragment;
	Spinner spinnerType;

	AsymmetricCryptoUtils asymmetricCryptoUtils;
	DigestCryptoUtils digestCryptoUtils;

	static PersonalKeyController personalKeyController;

	Boolean showErrorMessage;

	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		showErrorMessage = Boolean.FALSE;
		personalKeyController = new PersonalKeyController(
				getApplicationContext());
		int message = R.string.lblMessageImportFile;
		selectFileFragment = SelectFileDialogFragment.newInstance(
				R.string.dialog_select_file_title, message, "", "",REQUEST_OPEN_FILE_ID);
		if (savedInstanceState == null) {
			Log.i(PKITrustNetworkActivity.TAG, "ADD FRAGMENT");
			// First-time init; create fragment to embed in activity.
			FragmentTransaction ft = getSupportFragmentManager()
					.beginTransaction();
			ft.add(R.id.embedded, selectFileFragment);
			ft.commit();
			Log.i(PKITrustNetworkActivity.TAG, "FINISH ADD FRAGMENT");
		}

		Log.i(PKITrustNetworkActivity.TAG, "CREATE VIEW");
		// This has to be called before setContentView and you must use the
		// class in com.actionbarsherlock.view and NOT android.view
		requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

		setContentView(R.layout.import_key);
		setSupportProgressBarIndeterminateVisibility(false);

		// Set up action bar.
		final ActionBar actionBar = getSupportActionBar();

		// Specify that the Home button should show an "Up" caret, indicating
		// that touching the
		// button will take the user one step up in the application's hierarchy.
		actionBar.setDisplayHomeAsUpEnabled(true);
		actionBar.setSubtitle(R.string.subtitle_keys_import);

		// Get Selected subject ID
		subjectID = getIntent().getIntExtra(
				SelectOwnerActivity.EXTRA_SELECTED_OWNER_ID, 0);

		spinnerType = (Spinner) findViewById(R.id.spinnerKeyType);
		ArrayAdapter<CharSequence> adapter = ArrayAdapter.createFromResource(
				getApplicationContext(), R.array.keyType,
				android.R.layout.simple_spinner_item);
		adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		spinnerType.setAdapter(adapter);
		spinnerType
				.setOnItemSelectedListener(new TypeSpinnerItemSelectedListener());
		spinnerType.setSelection(0);

		txtComment = (EditText) findViewById(R.id.txtKeyComment);

		asymmetricCryptoUtils = new AsymmetricCryptoUtils();
		digestCryptoUtils = new DigestCryptoUtils();
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Place an action bar item for create the new Key.
		MenuItem itemAdd_key = menu
				.add(0, MENU_ACCEPT, 0, R.string.menu_import);
		itemAdd_key.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

		// Place an action bar item for cancel the creation of the new Key.
		MenuItem itemCancel = menu.add(0, MENU_CANCEL, 1, R.string.menu_cancel);
		itemCancel.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

		return super.onCreateOptionsMenu(menu);
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		switch (item.getItemId()) {
		case android.R.id.home:
			returnHome(android.R.id.home);
			return true;
		case MENU_ACCEPT:
			importKey();
			return true;
		case MENU_CANCEL:
			returnHome(MENU_CANCEL);
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}

	/**
	 * This is called to return home in the application navigation scheme
	 */
	private void returnHome(Integer option) {

		if (importRSAPrivateKeyTask != null) {
			importRSAPrivateKeyTask.cancel(true);
		}
		if (importRSAPublicKeyTask != null) {
			importRSAPublicKeyTask.cancel(true);
		}

		if (importRSAPKCSTask != null) {
			importRSAPKCSTask.cancel(true);
		}

		if (importECPrivateKeyTask != null) {
			importECPrivateKeyTask.cancel(true);
		}
		if (importECPublicKeyTask != null) {
			importECPublicKeyTask.cancel(true);
		}

		if (importECPKCSTask != null) {
			importECPKCSTask.cancel(true);
		}
		// This is called when the Home (Up) button is pressed in the action
		// bar.
		// Create a simple intent that starts the hierarchical parent
		// activity and
		// use NavUtils in the Support Package to ensure proper handling of
		// Up.
		Intent upIntent;
		upIntent = new Intent(this, PKITrustNetworkActivity.class);
		upIntent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
				PKITrustNetworkActivity.KEY);

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
	 * Item Selection Listener for Key Type spinner, should change the view
	 * flipper to set the fragment that contains the corresponding fields of the
	 * selected key type
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 10/09/2012
	 * @version 1.0
	 */
	public class TypeSpinnerItemSelectedListener implements
			OnItemSelectedListener {

		public void onItemSelected(AdapterView<?> parent, View v, int pos,
				long id) {
			if (pos == 6) {
				selectFileFragment
						.setWarning(getString(R.string.lblWarningImportUnknown));
			} else {
				selectFileFragment.setWarning("");
			}
		}

		public void onNothingSelected(AdapterView<?> arg0) {

		}

	}

	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data) {
		Log.i(PKITrustNetworkActivity.TAG, "ON ACTIVITY RESULT");
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

					Log.i(PKITrustNetworkActivity.TAG, "FILE NAME: " + filename);
					Log.i(PKITrustNetworkActivity.TAG, "FileFragment: "
							+ selectFileFragment);
					// selectFileFragment.setFileName(filename);
					((EditText) findViewById(R.id.txtFileName))
							.setText(filename);
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

	public void importKey() {
		showErrorMessage = Boolean.TRUE;
		fileName = ((EditText) findViewById(R.id.txtFileName)).getText()
				.toString();
		DialogFragment newFragment;
		switch (spinnerType.getSelectedItemPosition()) {
		case RSA_PUBLIC:
			// If the task is not null, its running so make the user aware of it
			if (importRSAPublicKeyTask == null
					|| !importRSAPublicKeyTask.getStatus().equals(
							AsyncTask.Status.RUNNING)) {
				importRSAPublicKeyTask = new ImportRSAPublicKeyTask();
				importRSAPublicKeyTask.execute(fileName);
			} else {
				Toast.makeText(this, R.string.msgWorking, Toast.LENGTH_SHORT)
						.show();
			}
			break;
		case RSA_PRIVATE:
			// If is a RSAPrivateKey ask for the password
			newFragment = MyPasswordDialogFragment.newInstance(
					R.string.alert_dialog_key_open_private_title, null,
					new OnPositiveButtonClickListenerImportRSAImp());
			newFragment.show(getSupportFragmentManager(), "password");

			break;
		case RSA_PKCS:
			// If is a RSAPKCS ask for the password
			newFragment = MyPasswordPKCSDialogFragment.newInstance(
					R.string.alert_dialog_key_open_private_title, null,
					new OnPositiveButtonClickListenerImportRSAImp());
			newFragment.show(getSupportFragmentManager(), "password");
			break;
		case EC_PUBLIC:
			// If the task is not null, its running so make the user aware of it
			if (importECPublicKeyTask == null
					|| !importECPublicKeyTask.getStatus().equals(
							AsyncTask.Status.RUNNING)) {
				importECPublicKeyTask = new ImportECPublicKeyTask();
				importECPublicKeyTask.execute(fileName);
			} else {
				Toast.makeText(this, R.string.msgWorking, Toast.LENGTH_SHORT)
						.show();
			}
			break;
		case EC_PRIVATE:
			// If is a ECPrivateKey ask for the password
			newFragment = MyPasswordDialogFragment.newInstance(
					R.string.alert_dialog_key_open_private_title, null,
					new OnPositiveButtonClickListenerImportECImp());
			newFragment.show(getSupportFragmentManager(), "password");
			break;
		case EC_PKCS:
			// If is a ECPKCS ask for the password
			newFragment = MyPasswordPKCSDialogFragment.newInstance(
					R.string.alert_dialog_key_open_private_title, null,
					new OnPositiveButtonClickListenerImportECImp());
			newFragment.show(getSupportFragmentManager(), "password");
			break;
		case UNKNOWN:

			showErrorMessage = Boolean.FALSE;

			// Try to decode both public keys (RSA and EC)
			// If the task is not null, its running so make the user aware of it
			if (importRSAPublicKeyTask == null
					|| !importRSAPublicKeyTask.getStatus().equals(
							AsyncTask.Status.RUNNING)) {
				importRSAPublicKeyTask = new ImportRSAPublicKeyTask();
				importRSAPublicKeyTask.execute(fileName);
			} else {
				Toast.makeText(this, R.string.msgWorking, Toast.LENGTH_SHORT)
						.show();
			}

			// If the task is not null, its running so make the user aware of it
			if (importECPublicKeyTask == null
					|| !importECPublicKeyTask.getStatus().equals(
							AsyncTask.Status.RUNNING)) {
				importECPublicKeyTask = new ImportECPublicKeyTask();
				importECPublicKeyTask.execute(fileName);
			} else {
				Toast.makeText(this, R.string.msgWorking, Toast.LENGTH_SHORT)
						.show();
			}

			// Wait until both public tasks are finished
			try {
				importRSAPublicKeyTask.get();
				importECPublicKeyTask.get();
			} catch (InterruptedException e) {
			} catch (ExecutionException e) {
			}

			// Try to decode both private key (RSA and EC)
			// If is a ECPrivateKey ask for the password
			newFragment = MyPasswordDialogFragment.newInstance(
					R.string.alert_dialog_key_open_private_title, null,
					new OnPositiveButtonClickListenerImportParallelImp());
			newFragment.show(getSupportFragmentManager(), "password");

			break;

		default:
			break;
		}
	}

	/**
	 * Implements the OnPositiveButtonClickListener for import operation, after
	 * the password dialog is shown, this function is called for an RSA key
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 14/09/2012
	 * @version 1.0
	 */
	public class OnPositiveButtonClickListenerImportRSAImp implements
			OnPositiveButtonClickListener {

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * cinvestav.pki.android.trustednetwork.common.MyPasswordDialogFragment
		 * .OnPositiveButtonClickListener
		 * #onPositiveButtonClick(cinvestav.android
		 * .pki.db.dao.PersonalKeyDAO, java.lang.String)
		 */
		@Override
		public void onPositiveButtonClick(PersonalKeyDAO key, String passwordKey) {
			// If the task is not null, its running so make the user aware of it
			if (importRSAPrivateKeyTask == null
					|| !importRSAPrivateKeyTask.getStatus().equals(
							AsyncTask.Status.RUNNING)) {
				password = passwordKey;
				importRSAPrivateKeyTask = new ImportRSAPrivateKeyTask();
				importRSAPrivateKeyTask.execute(fileName);
			} else {
				Toast.makeText(getApplicationContext(), R.string.msgWorking,
						Toast.LENGTH_SHORT).show();
			}

		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * cinvestav.pki.android.trustednetwork.common.MyPasswordDialogFragment
		 * .OnPositiveButtonClickListener
		 * #onPositiveButtonClick(cinvestav.android
		 * .pki.db.dao.PersonalKeyDAO, java.lang.String,
		 * java.lang.String)
		 */
		@Override
		public void onPositiveButtonClick(PersonalKeyDAO key,
				String passwordKey, String passwordPKCS) {
			// If the task is not null, its running so make the user aware of it
			if (importRSAPKCSTask == null
					|| !importRSAPKCSTask.getStatus().equals(
							AsyncTask.Status.RUNNING)) {
				password = passwordKey;
				ImportNewKeyActivity.this.passwordPKCS = passwordPKCS;
				importRSAPKCSTask = new ImportRSAPKCSTask();
				importRSAPKCSTask.execute(fileName);
			} else {
				Toast.makeText(getApplicationContext(), R.string.msgWorking,
						Toast.LENGTH_SHORT).show();
			}

		}

	}

	/**
	 * Implements the OnPositiveButtonClickListener for import operation, after
	 * the password dialog is shown, this function is called for an EC key
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 14/09/2012
	 * @version 1.0
	 */
	public class OnPositiveButtonClickListenerImportECImp implements
			OnPositiveButtonClickListener {

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * cinvestav.pki.android.trustednetwork.common.MyPasswordDialogFragment
		 * .OnPositiveButtonClickListener
		 * #onPositiveButtonClick(cinvestav.android
		 * .pki.db.dao.PersonalKeyDAO, java.lang.String)
		 */
		@Override
		public void onPositiveButtonClick(PersonalKeyDAO key, String passwordKey) {
			// If the task is not null, its running so make the user aware of it
			if (importECPrivateKeyTask == null
					|| !importECPrivateKeyTask.getStatus().equals(
							AsyncTask.Status.RUNNING)) {
				password = passwordKey;
				importECPrivateKeyTask = new ImportECPrivateKeyTask();
				importECPrivateKeyTask.execute(fileName);
			} else {
				Toast.makeText(getApplicationContext(), R.string.msgWorking,
						Toast.LENGTH_SHORT).show();
			}

		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * cinvestav.pki.android.trustednetwork.common.MyPasswordDialogFragment
		 * .OnPositiveButtonClickListener
		 * #onPositiveButtonClick(cinvestav.android
		 * .pki.db.dao.PersonalKeyDAO, java.lang.String,
		 * java.lang.String)
		 */
		@Override
		public void onPositiveButtonClick(PersonalKeyDAO key,
				String passwordKey, String passwordPKCS) {
			// If the task is not null, its running so make the user aware of it
			if (importECPKCSTask == null
					|| !importECPKCSTask.getStatus().equals(
							AsyncTask.Status.RUNNING)) {
				password = passwordKey;
				ImportNewKeyActivity.this.passwordPKCS = passwordPKCS;
				importECPKCSTask = new ImportECPKCSTask();
				importECPKCSTask.execute(fileName);
			} else {
				Toast.makeText(getApplicationContext(), R.string.msgWorking,
						Toast.LENGTH_SHORT).show();
			}

		}

	}

	/**
	 * Implements the OnPositiveButtonClickListener for import operation, after
	 * the password dialog is shown, this function is called for an RSA and EC
	 * key to be tries in parallel
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 14/09/2012
	 * @version 1.0
	 */
	public class OnPositiveButtonClickListenerImportParallelImp implements
			OnPositiveButtonClickListener {

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * cinvestav.pki.android.trustednetwork.common.MyPasswordDialogFragment
		 * .OnPositiveButtonClickListener
		 * #onPositiveButtonClick(cinvestav.android
		 * .pki.db.dao.PersonalKeyDAO, java.lang.String)
		 */
		@Override
		public void onPositiveButtonClick(PersonalKeyDAO key, String passwordKey) {
			// If the task is not null, its running so make the user aware of it
			if (importRSAPrivateKeyTask == null
					|| !importRSAPrivateKeyTask.getStatus().equals(
							AsyncTask.Status.RUNNING)) {
				password = passwordKey;
				importRSAPrivateKeyTask = new ImportRSAPrivateKeyTask();
				importRSAPrivateKeyTask.execute(fileName);
			} else {
				Toast.makeText(getApplicationContext(), R.string.msgWorking,
						Toast.LENGTH_SHORT).show();
			}

			if (importECPrivateKeyTask == null
					|| !importECPrivateKeyTask.getStatus().equals(
							AsyncTask.Status.RUNNING)) {
				password = passwordKey;
				importECPrivateKeyTask = new ImportECPrivateKeyTask();
				importECPrivateKeyTask.execute(fileName);
			} else {
				Toast.makeText(getApplicationContext(), R.string.msgWorking,
						Toast.LENGTH_SHORT).show();
			}

			// Wait until both private tasks are finished
			try {
				importRSAPrivateKeyTask.get();
				importECPrivateKeyTask.get();
			} catch (InterruptedException e) {
			} catch (ExecutionException e) {
			}

			// If is a ECPKCS ask for the password
			DialogFragment newFragment = MyPasswordPKCSDialogFragment
					.newInstance(
							R.string.alert_dialog_key_open_private_title,
							null,
							new OnPositiveButtonClickListenerImportParallelImp());
			newFragment.show(getSupportFragmentManager(), "password");
			// Try to decode both PKCS key (RSA and EC)

		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * cinvestav.pki.android.trustednetwork.common.MyPasswordDialogFragment
		 * .OnPositiveButtonClickListener
		 * #onPositiveButtonClick(cinvestav.android
		 * .pki.db.dao.PersonalKeyDAO, java.lang.String,
		 * java.lang.String)
		 */
		@Override
		public void onPositiveButtonClick(PersonalKeyDAO key,
				String passwordKey, String passwordPKCS) {
			// If the task is not null, its running so make the user aware of it
			if (importRSAPKCSTask == null
					|| !importRSAPKCSTask.getStatus().equals(
							AsyncTask.Status.RUNNING)) {
				password = passwordKey;
				ImportNewKeyActivity.this.passwordPKCS = passwordPKCS;
				importRSAPKCSTask = new ImportRSAPKCSTask();
				importRSAPKCSTask.execute(fileName);
			} else {
				Toast.makeText(getApplicationContext(), R.string.msgWorking,
						Toast.LENGTH_SHORT).show();
			}

			// If the task is not null, its running so make the user aware of it
			if (importECPKCSTask == null
					|| !importECPKCSTask.getStatus().equals(
							AsyncTask.Status.RUNNING)) {
				password = passwordKey;
				ImportNewKeyActivity.this.passwordPKCS = passwordPKCS;
				importECPKCSTask = new ImportECPKCSTask();
				importECPKCSTask.execute(fileName);
			} else {
				Toast.makeText(getApplicationContext(), R.string.msgWorking,
						Toast.LENGTH_SHORT).show();
			}

			// Wait until both private tasks are finished
			try {
				Object res = importRSAPKCSTask.get();
				Object res2 = importECPKCSTask.get();

				if (res == null && res2 == null) {
					Toast.makeText(getApplicationContext(),
							R.string.error_key_import, Toast.LENGTH_LONG)
							.show();
					// Disable the indeterminate progress icon on the action bar
					setSupportProgressBarIndeterminateVisibility(false);
				}
			} catch (InterruptedException e) {
			} catch (ExecutionException e) {
			}
		}

	}

	/**
	 * Inner class that create an asynchronous task in which a
	 * {@link RSAPublicKey} is imported
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class ImportRSAPublicKeyTask extends
			AsyncTask<String, Void, PersonalKeyDAO> {

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
		protected PersonalKeyDAO doInBackground(String... params) {
			try {
				RSAPublicKey publicKey = RSAPublicKey.loadDER(params[0]);

				PersonalKeyDAO key = new PersonalKeyDAO();
				String encodedKeyStr = "";
				String keyId = "";
				// ADD RSA Public key
				key.setKeyType(PersonalKeyDAO.PUBLIC_RSA);
				encodedKeyStr = new String(publicKey.encode());
				key.setKeyStr(encodedKeyStr);
				keyId = digestCryptoUtils.getDigest(encodedKeyStr,
						CryptoUtils.DIGEST_FUNCTION_SHA_1,
						CryptoUtils.ENCODER_BASE64);
				key.setKeyID(keyId);
				key.setComment(txtComment.getText().toString());
				Integer id = personalKeyController.insert(key, subjectID);
				key.setId(id);
				return key;

			} catch (CryptoUtilsException e) {
				e.printStackTrace();
			} catch (DBException e) {
				e.printStackTrace();
			} catch (Exception e) {
				e.printStackTrace();
			}

			return null;

		}

		@Override
		protected void onPostExecute(PersonalKeyDAO key) {
			if (key != null) {
				Toast.makeText(getApplicationContext(),
						R.string.msgImportKeyOK, Toast.LENGTH_LONG).show();
				// Disable the indeterminate progress icon on the action bar
				setSupportProgressBarIndeterminateVisibility(false);

				// Show the imported key details
				Intent intent = new Intent(getApplicationContext(),
						KeyDetailsActivity.class);

				int[] idArray = { key.getId() };
				intent.putExtra(KeyDetailsActivity.EXTRA_ID_ARRAY, idArray);
				intent.putExtra(KeyDetailsActivity.EXTRA_CURRENT_ITEM, 0);
				startActivity(intent);
			} else {
				if (showErrorMessage) {
					Toast.makeText(getApplicationContext(),
							R.string.error_key_import, Toast.LENGTH_LONG)
							.show();
					// Disable the indeterminate progress icon on the action bar
					setSupportProgressBarIndeterminateVisibility(false);
				}
			}

		}
	}

	/**
	 * Inner class that create an asynchronous task in which a
	 * {@link RSAKeyPair} is imported
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class ImportRSAPKCSTask extends
			AsyncTask<String, Void, PersonalKeyDAO> {

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
		protected PersonalKeyDAO doInBackground(String... params) {
			try {
				Object[] pkcsElement = RSAKeyPair.loadPKCS12(params[0],
						passwordPKCS, password);

				PersonalKeyDAO key = new PersonalKeyDAO();
				String encodedKeyStr = "";
				String keyId = "";
				// ADD RSA Public key
				key.setKeyType(PersonalKeyDAO.PKCS12_RSA);
				encodedKeyStr = new String(
						((RSAKeyPair) pkcsElement[0]).encodePKCS12(
								passwordPKCS, password,
								(Certificate[]) pkcsElement[1]));
				key.setKeyStr(encodedKeyStr);
				keyId = digestCryptoUtils.getDigest(encodedKeyStr,
						CryptoUtils.DIGEST_FUNCTION_SHA_1,
						CryptoUtils.ENCODER_BASE64);
				key.setKeyID(keyId);
				key.setComment(txtComment.getText().toString());
				Integer id = personalKeyController.insert(key, subjectID);
				key.setId(id);

				return key;

			} catch (CryptoUtilsException e) {
				e.printStackTrace();
			} catch (DBException e) {
				e.printStackTrace();
			} catch (Exception e) {
				e.printStackTrace();
			}

			return null;

		}

		@Override
		protected void onPostExecute(PersonalKeyDAO keyPair) {
			if (keyPair != null) {
				Toast.makeText(getApplicationContext(),
						R.string.msgImportKeyOK, Toast.LENGTH_LONG).show();
				// Disable the indeterminate progress icon on the action bar
				setSupportProgressBarIndeterminateVisibility(false);

				// Show the imported key details
				Intent intent = new Intent(getApplicationContext(),
						KeyDetailsActivity.class);

				int[] idArray = { keyPair.getId() };
				intent.putExtra(KeyDetailsActivity.EXTRA_ID_ARRAY, idArray);
				intent.putExtra(KeyDetailsActivity.EXTRA_CURRENT_ITEM, 0);
				startActivity(intent);

			} else {
				if (showErrorMessage) {
					Toast.makeText(getApplicationContext(),
							R.string.error_key_import, Toast.LENGTH_LONG)
							.show();
					// Disable the indeterminate progress icon on the action bar
					setSupportProgressBarIndeterminateVisibility(false);
				}
			}
		}
	}

	/**
	 * Inner class that create an asynchronous task in which a
	 * {@link RSAPrivateKey} is imported
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class ImportRSAPrivateKeyTask extends
			AsyncTask<String, Void, PersonalKeyDAO> {

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
		protected PersonalKeyDAO doInBackground(String... params) {
			RSAPrivateKey privateKey;
			try {
				// Tries to load the key using PEM protected format
				privateKey = RSAPrivateKey.loadPKCS8PEM(params[0], password);
			} catch (CryptoUtilsException e) {
				e.printStackTrace();

				try {
					// Tries to load the key using PEM plain format
					privateKey = RSAPrivateKey.loadPKCS8PEM(params[0]);
				} catch (CryptoUtilsException e2) {
					e.printStackTrace();
					try {
						// Tries to load the key using DER plain format
						privateKey = RSAPrivateKey.loadPKCS8DER(params[0]);
					} catch (CryptoUtilsException e3) {
						e.printStackTrace();
						return null;
					}
				}

			} catch (Exception e) {
				e.printStackTrace();
				return null;
			}

			try {

				// Ones the key is loaded, insert it into the data base
				PersonalKeyDAO key = new PersonalKeyDAO();
				String encodedKeyStr = "";
				String keyId = "";
				// ADD RSA Private key
				key.setKeyType(PersonalKeyDAO.PRIVATE_RSA);
				encodedKeyStr = new String(privateKey.encode(password));
				key.setKeyStr(encodedKeyStr);
				keyId = digestCryptoUtils.getDigest(encodedKeyStr,
						CryptoUtils.DIGEST_FUNCTION_SHA_1,
						CryptoUtils.ENCODER_BASE64);
				key.setKeyID(keyId);
				key.setComment(txtComment.getText().toString());
				Integer id = personalKeyController.insert(key, subjectID);
				key.setId(id);

				return key;

			} catch (DBException e) {
				e.printStackTrace();
			} catch (CryptoUtilsException e) {
				e.printStackTrace();
			}

			return null;

		}

		@Override
		protected void onPostExecute(PersonalKeyDAO key) {
			if (key != null) {
				Toast.makeText(getApplicationContext(),
						R.string.msgImportKeyOK, Toast.LENGTH_LONG).show();
				// Disable the indeterminate progress icon on the action bar
				setSupportProgressBarIndeterminateVisibility(false);

				// Show the imported key details
				Intent intent = new Intent(getApplicationContext(),
						KeyDetailsActivity.class);

				int[] idArray = { key.getId() };
				intent.putExtra(KeyDetailsActivity.EXTRA_ID_ARRAY, idArray);
				intent.putExtra(KeyDetailsActivity.EXTRA_CURRENT_ITEM, 0);
				startActivity(intent);

			} else {
				if (showErrorMessage) {
					Toast.makeText(getApplicationContext(),
							R.string.error_key_import, Toast.LENGTH_LONG)
							.show();
					// Disable the indeterminate progress icon on the action bar
					setSupportProgressBarIndeterminateVisibility(false);
				}

			}
		}
	}

	/**
	 * Inner class that create an asynchronous task in which a
	 * {@link ECPublicKey} is imported
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class ImportECPublicKeyTask extends
			AsyncTask<String, Void, PersonalKeyDAO> {

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
		protected PersonalKeyDAO doInBackground(String... params) {
			try {
				ECPublicKey publicKey = ECPublicKey.loadDER(params[0]);

				PersonalKeyDAO key = new PersonalKeyDAO();
				String encodedKeyStr = "";
				String keyId = "";
				// ADD RSA Public key
				key.setKeyType(PersonalKeyDAO.PUBLIC_EC);
				encodedKeyStr = new String(publicKey.encode());
				key.setKeyStr(encodedKeyStr);
				keyId = digestCryptoUtils.getDigest(encodedKeyStr,
						CryptoUtils.DIGEST_FUNCTION_SHA_1,
						CryptoUtils.ENCODER_BASE64);
				key.setKeyID(keyId);
				key.setComment(txtComment.getText().toString());
				Integer id = personalKeyController.insert(key, subjectID);
				key.setId(id);

				return key;

			} catch (CryptoUtilsException e) {
				e.printStackTrace();
			} catch (DBException e) {
				e.printStackTrace();
			} catch (Exception e) {
				e.printStackTrace();
			}

			return null;

		}

		@Override
		protected void onPostExecute(PersonalKeyDAO key) {
			if (key != null) {
				Toast.makeText(getApplicationContext(),
						R.string.msgImportKeyOK, Toast.LENGTH_LONG).show();
				// Disable the indeterminate progress icon on the action bar
				setSupportProgressBarIndeterminateVisibility(false);

				// Show the imported key details
				Intent intent = new Intent(getApplicationContext(),
						KeyDetailsActivity.class);

				int[] idArray = { key.getId() };
				intent.putExtra(KeyDetailsActivity.EXTRA_ID_ARRAY, idArray);
				intent.putExtra(KeyDetailsActivity.EXTRA_CURRENT_ITEM, 0);
				startActivity(intent);

			} else {
				if (showErrorMessage) {
					Toast.makeText(getApplicationContext(),
							R.string.error_key_import, Toast.LENGTH_LONG)
							.show();
					// Disable the indeterminate progress icon on the action bar
					setSupportProgressBarIndeterminateVisibility(false);
				}

			}
		}
	}

	/**
	 * Inner class that create an asynchronous task in which a {@link ECKeyPair}
	 * is imported
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class ImportECPKCSTask extends
			AsyncTask<String, Void, PersonalKeyDAO> {

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
		protected PersonalKeyDAO doInBackground(String... params) {

			try {
				Object[] pkcsElement = ECKeyPair.loadPKCS12(params[0],
						passwordPKCS, password);

				PersonalKeyDAO key = new PersonalKeyDAO();
				String encodedKeyStr = "";
				String keyId = "";
				// ADD RSA Public key
				key.setKeyType(PersonalKeyDAO.PKCS12_EC);
				encodedKeyStr = new String(
						((ECKeyPair) pkcsElement[0]).encodePKCS12(passwordPKCS,
								password, (Certificate[]) pkcsElement[1]));
				key.setKeyStr(encodedKeyStr);
				keyId = digestCryptoUtils.getDigest(encodedKeyStr,
						CryptoUtils.DIGEST_FUNCTION_SHA_1,
						CryptoUtils.ENCODER_BASE64);
				key.setKeyID(keyId);
				key.setComment(txtComment.getText().toString());
				Integer id = personalKeyController.insert(key, subjectID);
				key.setId(id);

				return key;

			} catch (CryptoUtilsException e) {
				e.printStackTrace();
			} catch (DBException e) {
				e.printStackTrace();
			} catch (Exception e) {
				e.printStackTrace();
			}

			return null;

		}

		@Override
		protected void onPostExecute(PersonalKeyDAO keyPair) {
			if (keyPair != null) {
				Toast.makeText(getApplicationContext(),
						R.string.msgImportKeyOK, Toast.LENGTH_LONG).show();
				// Disable the indeterminate progress icon on the action bar
				setSupportProgressBarIndeterminateVisibility(false);

				// Show the imported key details
				Intent intent = new Intent(getApplicationContext(),
						KeyDetailsActivity.class);

				int[] idArray = { keyPair.getId() };
				intent.putExtra(KeyDetailsActivity.EXTRA_ID_ARRAY, idArray);
				intent.putExtra(KeyDetailsActivity.EXTRA_CURRENT_ITEM, 0);
				startActivity(intent);

			} else {
				if (showErrorMessage) {
					Toast.makeText(getApplicationContext(),
							R.string.error_key_import, Toast.LENGTH_LONG)
							.show();
					// Disable the indeterminate progress icon on the action bar
					setSupportProgressBarIndeterminateVisibility(false);
				}

			}
		}
	}

	/**
	 * Inner class that create an asynchronous task in which a
	 * {@link ECPrivateKey} is imported
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class ImportECPrivateKeyTask extends
			AsyncTask<String, Void, PersonalKeyDAO> {

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
		protected PersonalKeyDAO doInBackground(String... params) {

			ECPrivateKey privateKey;
			try {
				// Tries to load the key using PEM protected format
				privateKey = ECPrivateKey.loadPKCS8PEM(params[0], password);
			} catch (CryptoUtilsException e) {
				e.printStackTrace();

				try {
					// Tries to load the key using PEM plain format
					privateKey = ECPrivateKey.loadPKCS8PEM(params[0]);
				} catch (CryptoUtilsException e2) {
					e.printStackTrace();
					try {
						// Tries to load the key using DER plain format
						privateKey = ECPrivateKey.loadPKCS8DER(params[0]);
					} catch (CryptoUtilsException e3) {
						e.printStackTrace();
						return null;
					}
				}

			} catch (Exception e) {
				e.printStackTrace();
				return null;
			}

			try {

				// Ones the key is loaded, insert it into the data base
				PersonalKeyDAO key = new PersonalKeyDAO();
				String encodedKeyStr = "";
				String keyId = "";
				// ADD EC Private key
				key.setKeyType(PersonalKeyDAO.PRIVATE_EC);
				encodedKeyStr = new String(privateKey.encode(password));
				key.setKeyStr(encodedKeyStr);
				keyId = digestCryptoUtils.getDigest(encodedKeyStr,
						CryptoUtils.DIGEST_FUNCTION_SHA_1,
						CryptoUtils.ENCODER_BASE64);
				key.setKeyID(keyId);
				key.setComment(txtComment.getText().toString());
				Integer id = personalKeyController.insert(key, subjectID);
				key.setId(id);
				return key;

			} catch (DBException e) {
				e.printStackTrace();
			} catch (CryptoUtilsException e) {
				e.printStackTrace();
			}

			return null;

		}

		@Override
		protected void onPostExecute(PersonalKeyDAO key) {
			if (key != null) {
				Toast.makeText(getApplicationContext(),
						R.string.msgImportKeyOK, Toast.LENGTH_LONG).show();
				// Disable the indeterminate progress icon on the action bar
				setSupportProgressBarIndeterminateVisibility(false);

				// Show the imported key details
				Intent intent = new Intent(getApplicationContext(),
						KeyDetailsActivity.class);

				int[] idArray = { key.getId() };
				intent.putExtra(KeyDetailsActivity.EXTRA_ID_ARRAY, idArray);
				intent.putExtra(KeyDetailsActivity.EXTRA_CURRENT_ITEM, 0);
				startActivity(intent);

			} else {
				if (showErrorMessage) {
					Toast.makeText(getApplicationContext(),
							R.string.error_key_import, Toast.LENGTH_LONG)
							.show();
					// Disable the indeterminate progress icon on the action bar
					setSupportProgressBarIndeterminateVisibility(false);
				}

			}
		}
	}

}
