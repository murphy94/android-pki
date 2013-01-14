/**
 *  Created on  : 13/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Activity that contains the options for exporting a key like: encoding, key
 * password and pkcs12 file password
 */
package cinvestav.pki.android.trustednetwork.share;

import java.io.File;
import java.security.cert.Certificate;

import android.content.Intent;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Environment;
import android.support.v4.app.DialogFragment;
import android.support.v4.app.FragmentTransaction;
import android.support.v4.app.NavUtils;
import android.support.v4.app.TaskStackBuilder;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.ArrayAdapter;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.key.ECKeyPair;
import cinvestav.android.pki.cryptography.key.ECPrivateKey;
import cinvestav.android.pki.cryptography.key.ECPublicKey;
import cinvestav.android.pki.cryptography.key.RSAKeyPair;
import cinvestav.android.pki.cryptography.key.RSAPrivateKey;
import cinvestav.android.pki.cryptography.key.RSAPublicKey;
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

import com.actionbarsherlock.app.ActionBar;
import com.actionbarsherlock.app.SherlockFragmentActivity;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuItem;
import com.actionbarsherlock.view.Window;

/**
 * Activity that contains the options for exporting a key like: encoding, key
 * password and pkcs12 file password
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 13/09/2012
 * @version 1.0
 */
public class ExportKeyActivity extends SherlockFragmentActivity {

	public static final String EXTRA_SELECTED_KEY_ID = "EXTRA_SELECTED_KEY_ID";
	public static final int REQUEST_OPEN_FILE_ID = 1;

	static final int MENU_ACCEPT = 0;
	static final int MENU_CANCEL = 1;

	Integer keyID;
	PersonalKeyDAO key;

	String oldPasswordKey;
	String oldPasswordPKCS;

	int currentItem;
	int[] ids;

	CheckBox chkProtectKey;
	RelativeLayout layoutEncoding;
	RelativeLayout layoutChkProtectKey;

	Spinner spinnerEncoding;

	DigestCryptoUtils digestCryptoUtils;

	ExportRSAPrivateKeyTask exportRSAPrivateKeyTask;
	ExportECPrivateKeyTask exportECPrivateKeyTask;

	ExportRSAKeyPairTask exportRSAKeyPairTask;
	ExportECKeyPairTask exportECKeyPairTask;

	ExportRSAPublicKeyTask exportRSAPublicKeyTask;
	ExportECPublicKeyTask exportECPublicKeyTask;

	String fileName;
	int message;
	String warningsBase;

	String password;
	String passwordPKCS;

	SelectFileDialogFragment selectFileFragment;

	static PersonalKeyController personalKeyController;

	public ExportKeyActivity() {
		super();
		digestCryptoUtils = new DigestCryptoUtils();
	}

	/**
	 * Dummy layout that get focused when the activity starts
	 */
	private LinearLayout mLinearLayout;

	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		if (personalKeyController == null) {
			personalKeyController = new PersonalKeyController(
					getApplicationContext());

		}

		message = R.string.lblMessageExportFile;
		warningsBase = getString(R.string.lblWarningFileOverWrite) + "\n";

		// This has to be called before setContentView and you must use the
		// class in com.actionbarsherlock.view and NOT android.view
		requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

		setContentView(R.layout.export_key);
		setSupportProgressBarIndeterminateVisibility(false);

		// Set up action bar.
		final ActionBar actionBar = getSupportActionBar();

		// Specify that the Home button should show an "Up" caret, indicating
		// that touching the
		// button will take the user one step up in the application's hierarchy.
		actionBar.setDisplayHomeAsUpEnabled(true);
		actionBar.setSubtitle(R.string.subtitle_keys_export);

		mLinearLayout = (LinearLayout) findViewById(R.id.linearLayout_focus);

		// Get intent Extras, in order to obtain the selected key id
		ids = getIntent().getIntArrayExtra(KeyDetailsActivity.EXTRA_ID_ARRAY);
		currentItem = getIntent().getIntExtra(
				KeyDetailsActivity.EXTRA_CURRENT_ITEM, 0);

		keyID = ids[currentItem];

		// Load key information from database
		try {
			key = personalKeyController.getById(keyID);

		} catch (DBException e) {
			Toast.makeText(this, R.string.error_db_load_key, Toast.LENGTH_SHORT)
					.show();
			Log.e(PKITrustNetworkActivity.TAG, e.toString(), e);
			returnHome();
		}

		Integer keyType = key.getKeyType();

		// Init key default name
		fileName = getDefaultFileName(keyType);
		File f = new File(fileName);
		if (!f.getParentFile().exists()) {
			f.getParentFile().mkdir();
		}

		// Set the password fields
		((TextView) findViewById(R.id.txtKeyId))
				.setText(key.getId().toString());
		((TextView) findViewById(R.id.txtKeyType)).setText(key
				.getKeyTypeStr(PKITrustNetworkActivity.LAN));

		if (!keyType.equals(PersonalKeyDAO.PUBLIC_EC)
				&& !keyType.equals(PersonalKeyDAO.PUBLIC_RSA)) {
			warningsBase = warningsBase
					+ getString(R.string.lblWarningExportPrivateKey) + "\n";

			if (savedInstanceState == null) {
				// First-time init; create fragment to embed in activity.
				FragmentTransaction ft = getSupportFragmentManager()
						.beginTransaction();
				selectFileFragment = SelectFileDialogFragment.newInstance(
						R.string.dialog_select_file_title, message,
						warningsBase, fileName, REQUEST_OPEN_FILE_ID);
				ft.add(R.id.embedded, selectFileFragment);
				ft.commit();
			}

			// if its a private key (EC or RSA) or PKCS show the corresponding
			// controls
			layoutChkProtectKey = ((RelativeLayout) findViewById(R.id.layoutChkProtectKey));
			layoutChkProtectKey.setVisibility(RelativeLayout.VISIBLE);
			// layoutPasswordKey = ((RelativeLayout)
			// findViewById(R.id.layoutPassword));
			layoutEncoding = ((RelativeLayout) findViewById(R.id.layoutEncoding));
			layoutEncoding.setVisibility(View.VISIBLE);
			((TextView) findViewById(R.id.lblRecomended))
					.setVisibility(View.VISIBLE);

			spinnerEncoding = (Spinner) findViewById(R.id.spinnerEncoding);
			ArrayAdapter<CharSequence> adapter = ArrayAdapter
					.createFromResource(getApplicationContext(),
							R.array.arrayEncoding,
							android.R.layout.simple_spinner_item);
			adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
			spinnerEncoding.setAdapter(adapter);
			spinnerEncoding
					.setOnItemSelectedListener(new EncodingSpinnerItemSelectedListener());
			spinnerEncoding.setSelection(0);
			// layoutPasswordKey.setVisibility(RelativeLayout.VISIBLE);

			if (key.getKeyType().equals(PersonalKeyDAO.PKCS12_RSA)
					|| key.getKeyType().equals(PersonalKeyDAO.PKCS12_EC)) {
				// layoutPasswordPKCS = ((RelativeLayout)
				// findViewById(R.id.layoutPasswordPKCS));
				layoutEncoding.setVisibility(View.GONE);
				// layoutPasswordPKCS.setVisibility(RelativeLayout.VISIBLE);
				((TextView) findViewById(R.id.lblRecomended))
						.setVisibility(View.GONE);
				layoutChkProtectKey.setVisibility(View.GONE);
			}

			chkProtectKey = (CheckBox) findViewById(R.id.chkProtectKey);
			chkProtectKey.setOnClickListener(new View.OnClickListener() {

				@Override
				public void onClick(View v) {
					onCheckBoxClick(v);
				}
			});

		} else {
			// If its a public key
			warningsBase = warningsBase
					+ getString(R.string.lblWarningExportPublicKey) + "\n";

			if (savedInstanceState == null) {
				// First-time init; create fragment to embed in activity.
				FragmentTransaction ft = getSupportFragmentManager()
						.beginTransaction();
				selectFileFragment = SelectFileDialogFragment.newInstance(
						R.string.dialog_select_file_title, message,
						warningsBase, fileName, REQUEST_OPEN_FILE_ID);
				ft.add(R.id.embedded, selectFileFragment);
				ft.commit();
			}
		}
	}

	/**
	 * Creates a default key suffix depending on the key type
	 * 
	 * @param keyType
	 * @return
	 */
	public String getDefaultFileName(Integer keyType) {
		String res = Environment.getExternalStorageDirectory()
				+ "/PKI_Trust_Network/";
		if (keyType.equals(PersonalKeyDAO.PUBLIC_EC)) {
			res += "EC_PublicKey";
		} else if (keyType.equals(PersonalKeyDAO.PUBLIC_RSA)) {
			res += "RSA_PublicKey";
		} else if (keyType.equals(PersonalKeyDAO.PRIVATE_EC)) {
			res += "EC_PrivateKey";
		} else if (keyType.equals(PersonalKeyDAO.PRIVATE_RSA)) {
			res += "RSA_PrivateKey";
		} else if (keyType.equals(PersonalKeyDAO.PKCS12_EC)) {
			res += "EC_PKCS12";
		} else {
			res += "RSA_PKCS12";
		}
		return res;
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Place an action bar item for export the Key.
		MenuItem itemExport_key = menu.add(0, MENU_ACCEPT, 0,
				R.string.menu_export);
		itemExport_key.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

		// Place an action bar item for cancel the creation of the new Key.
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
	 * Export the selected key to the selected file using the selected
	 * configurations
	 */
	public void export() {

		fileName = ((EditText) selectFileFragment.getView().findViewById(
				R.id.txtFileName)).getText().toString();
		Integer keyType = key.getKeyType();
		// If its a public key
		if (keyType.equals(PersonalKeyDAO.PUBLIC_EC)) {
			// export the EC Public key
			exportECPublicKey();
			return;

		}

		if (keyType.equals(PersonalKeyDAO.PUBLIC_RSA)) {
			// export the RSA Public key
			exportRSAPublicKey();
			return;
		}

		// Determine the key type and decode it
		if (keyType.equals(PersonalKeyDAO.PRIVATE_RSA)) {
			// If is a RSAPrivateKey ask for the password
			DialogFragment newFragment = MyPasswordDialogFragment.newInstance(
					R.string.alert_dialog_key_update_private_title, key,
					new OnPositiveButtonClickListenerExportImp());
			newFragment.show(getSupportFragmentManager(), "password");
		} else if (keyType.equals(PersonalKeyDAO.PKCS12_RSA)) {
			// If is a PKCS_RSA file, ask for the password
			DialogFragment newFragment = MyPasswordPKCSDialogFragment
					.newInstance(
							R.string.alert_dialog_key_update_private_title,
							key, new OnPositiveButtonClickListenerExportImp());
			newFragment.show(getSupportFragmentManager(), "password");
		} else if (keyType.equals(PersonalKeyDAO.PRIVATE_EC)) {
			// If is a ECPrivateKey ask for the password
			DialogFragment newFragment = MyPasswordDialogFragment.newInstance(
					R.string.alert_dialog_key_update_private_title, key,
					new OnPositiveButtonClickListenerExportImp());
			newFragment.show(getSupportFragmentManager(), "password");
		} else if (keyType.equals(PersonalKeyDAO.PKCS12_EC)) {
			// If is a PKCS_RC file, ask for the password
			DialogFragment newFragment = MyPasswordPKCSDialogFragment
					.newInstance(
							R.string.alert_dialog_key_update_private_title,
							key, new OnPositiveButtonClickListenerExportImp());
			newFragment.show(getSupportFragmentManager(), "password");
		}

	}

	/**
	 * Perform the export operation of a {@link RSAPublicKey}
	 */
	public void exportRSAPublicKey() {
		// If the task is not null, its running so make the user aware of it
		if (exportRSAPublicKeyTask == null
				|| !exportRSAPublicKeyTask.getStatus().equals(
						AsyncTask.Status.RUNNING)) {
			exportRSAPublicKeyTask = new ExportRSAPublicKeyTask();
			exportRSAPublicKeyTask.execute(key);
		} else {
			Toast.makeText(this, R.string.msgWorking, Toast.LENGTH_SHORT)
					.show();
		}
	}

	/**
	 * Perform the export operation of a {@link ECPublicKey}
	 * 
	 * @param publicKey
	 *            {@link PersonalKeyDAO} object containing an
	 *            {@link ECPublicKey} object
	 */
	public void exportECPublicKey() {
		// If the task is not null, its running so make the user aware of it
		if (exportECPublicKeyTask == null
				|| !exportECPublicKeyTask.getStatus().equals(
						AsyncTask.Status.RUNNING)) {
			exportECPublicKeyTask = new ExportECPublicKeyTask();
			exportECPublicKeyTask.execute(key);
		} else {
			Toast.makeText(this, R.string.msgWorking, Toast.LENGTH_SHORT)
					.show();
		}
	}

	/**
	 * Perform the export operation over a {@link RSAPrivateKey} that was
	 * decoded in {@link MyPasswordDialogFrament}
	 * 
	 * @param privateKey
	 *            Decoded RSA private key
	 */
	public void export(RSAPrivateKey privateKey) {
		// If the task is not null, its running so make the user aware of it
		if (exportRSAPrivateKeyTask == null
				|| !exportRSAPrivateKeyTask.getStatus().equals(
						AsyncTask.Status.RUNNING)) {
			exportRSAPrivateKeyTask = new ExportRSAPrivateKeyTask();
			exportRSAPrivateKeyTask.execute(privateKey);
		} else {
			Toast.makeText(this, R.string.msgWorking, Toast.LENGTH_SHORT)
					.show();
		}
	}

	/**
	 * Perform the export operation over a {@link ECPrivateKey} that was decoded
	 * in {@link MyPasswordDialogFrament}
	 * 
	 * @param privateKey
	 *            Decoded EC private key
	 */
	public void export(ECPrivateKey privateKey) {
		// If the task is not null, its running so make the user aware of it
		if (exportECPrivateKeyTask == null
				|| !exportECPrivateKeyTask.getStatus().equals(
						AsyncTask.Status.RUNNING)) {
			exportECPrivateKeyTask = new ExportECPrivateKeyTask();
			exportECPrivateKeyTask.execute(privateKey);
		} else {
			Toast.makeText(this, R.string.msgWorking, Toast.LENGTH_SHORT)
					.show();
		}
	}

	/**
	 * Perform the export operation over a {@link RSAKeyPair} that was decoded
	 * in {@link MyPasswordPKCSDialogFrament}
	 * 
	 * @param keyPair
	 *            Decoded RSA key pair
	 */
	public void export(RSAKeyPair keyPair, Certificate[] chain) {
		// If the task is not null, its running so make the user aware of it
		if (exportRSAKeyPairTask == null
				|| !exportRSAKeyPairTask.getStatus().equals(
						AsyncTask.Status.RUNNING)) {
			exportRSAKeyPairTask = new ExportRSAKeyPairTask();
			exportRSAKeyPairTask.execute(keyPair, chain);
		} else {
			Toast.makeText(this, R.string.msgWorking, Toast.LENGTH_SHORT)
					.show();
		}
	}

	/**
	 * Perform the export operation over a {@link ECKeyPair} that was decoded in
	 * {@link MyPasswordPKCSDialogFrament}
	 * 
	 * @param keyPair
	 *            Decoded RSA key pair
	 */
	public void export(ECKeyPair keyPair, Certificate[] chain) {
		// If the task is not null, its running so make the user aware of it
		if (exportECKeyPairTask == null
				|| !exportECKeyPairTask.getStatus().equals(
						AsyncTask.Status.RUNNING)) {
			exportECKeyPairTask = new ExportECKeyPairTask();
			exportECKeyPairTask.execute(keyPair, chain);
		} else {
			Toast.makeText(this, R.string.msgWorking, Toast.LENGTH_SHORT)
					.show();
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
	public class EncodingSpinnerItemSelectedListener implements
			OnItemSelectedListener {

		public void onItemSelected(AdapterView<?> parent, View v, int pos,
				long id) {
			if (pos == 0) {
				layoutChkProtectKey.setVisibility(View.VISIBLE);
			} else {
				((TextView) selectFileFragment.getView().findViewById(
						R.id.lblWarningExport)).setText(warningsBase
						+ getString(R.string.lblWarningExportPrivateKeyPlain));
				layoutChkProtectKey.setVisibility(View.GONE);
			}
		}

		public void onNothingSelected(AdapterView<?> arg0) {
			// TODO Auto-generated method stub

		}

	}

	/**
	 * When a check box is clicked this method is called and toggles the
	 * visibility of password EditText fields of the general view
	 * 
	 * @param v
	 */
	public void onCheckBoxClick(View v) {
		// Is the view now checked?
		boolean checked = ((CheckBox) v).isChecked();

		if (checked) {

			((TextView) selectFileFragment.getView().findViewById(
					R.id.lblWarningExport)).setText(warningsBase);
		} else {
			((TextView) selectFileFragment.getView().findViewById(
					R.id.lblWarningExport)).setText(warningsBase
					+ getString(R.string.lblWarningExportPrivateKeyPlain));
		}
	}

	/**
	 * This is called to return home in the application navigation scheme
	 */
	private void returnHome() {
		if (exportECPrivateKeyTask != null) {
			exportECPrivateKeyTask.cancel(true);
		}
		if (exportRSAPrivateKeyTask != null) {
			exportRSAPrivateKeyTask.cancel(true);
		}
		if (exportECKeyPairTask != null) {
			exportECKeyPairTask.cancel(true);
		}
		if (exportRSAKeyPairTask != null) {
			exportRSAKeyPairTask.cancel(true);
		}

		// This is called when the Home (Up) button is pressed in the action
		// bar.
		// Create a simple intent that starts the hierarchical parent
		// activity and
		// use NavUtils in the Support Package to ensure proper handling of
		// Up.
		Intent upIntent;
		upIntent = new Intent(this, KeyDetailsActivity.class);
		upIntent.putExtra(KeyDetailsActivity.EXTRA_ID_ARRAY, ids);
		upIntent.putExtra(KeyDetailsActivity.EXTRA_CURRENT_ITEM, currentItem);

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
	 * Implements the OnPositiveButtonClickListener for export operation, after
	 * the password dialog is shown, this function is called
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 14/09/2012
	 * @version 1.0
	 */
	public class OnPositiveButtonClickListenerExportImp implements
			OnPositiveButtonClickListener {

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * cinvestav.pki.android.trustednetwork.common.MyPasswordDialogFragment
		 * .OnPositiveButtonClickListener
		 * #onPositiveButtonClick(cinvestav.android .pki.db.dao.PersonalKeyDAO,
		 * java.lang.String)
		 */
		@Override
		public void onPositiveButtonClick(PersonalKeyDAO key, String passwordKey) {
			// The key should be decoded, if no exception is thrown, it means
			// that the inserted password is OK, so the operation process should
			// continue, if the password is wrong cancel the operation
			try {
				if (key.getKeyType().equals(PersonalKeyDAO.PRIVATE_EC)) {
					// If the key is a Private EC key

					ECPrivateKey privKey = ECPrivateKey.decode(key.getKeyStr()
							.getBytes(), passwordKey);

					// Send the decoded key to update process
					password = passwordKey;
					export(privKey);

				} else {
					// If the key is a Private RSA key

					RSAPrivateKey privKey = RSAPrivateKey.decode(key
							.getKeyStr().getBytes(), passwordKey);

					// Send the decoded key to update process
					password = passwordKey;
					export(privKey);

				}
			} catch (CryptoUtilsException e) {
				// If the key could no be decoded, show a toast and return
				// the previews activity
				Toast.makeText(getApplicationContext(),
						R.string.error_db_load_key_password, Toast.LENGTH_LONG)
						.show();
				return;
			}
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * cinvestav.pki.android.trustednetwork.common.MyPasswordDialogFragment
		 * .OnPositiveButtonClickListener
		 * #onPositiveButtonClick(cinvestav.android .pki.db.dao.PersonalKeyDAO,
		 * java.lang.String, java.lang.String)
		 */
		@Override
		public void onPositiveButtonClick(PersonalKeyDAO key,
				String passwordKey, String passwordPKCS) {
			// The key should be decoded, if no exception is thrown, it means
			// that the inserted password is OK, so the operation process should
			// continue, if the password is wrong cancel the operation
			try {
				if (key.getKeyType().equals(PersonalKeyDAO.PKCS12_EC)) {
					// If the key is a PKCS EC key

					Object[] decodedECKeyPair = ECKeyPair.decodePKCS12(key
							.getKeyStr().getBytes(), passwordPKCS, passwordKey);

					// Send the decoded key to update process
					password = passwordKey;
					ExportKeyActivity.this.passwordPKCS = passwordPKCS;
					export((ECKeyPair) decodedECKeyPair[0],
							(Certificate[]) decodedECKeyPair[1]);

				} else {
					// If the key is a PKCS RSA key
					Object[] decodedRSAKeyPair = RSAKeyPair.decodePKCS12(key
							.getKeyStr().getBytes(), passwordPKCS, passwordKey);

					// Send the decoded key to update process
					password = passwordKey;
					ExportKeyActivity.this.passwordPKCS = passwordPKCS;
					export((RSAKeyPair) decodedRSAKeyPair[0],
							(Certificate[]) decodedRSAKeyPair[1]);

				}
			} catch (CryptoUtilsException e) {
				// If the key could no be decoded, show a toast and return
				// the previews activity
				Toast.makeText(getApplicationContext(),
						R.string.error_db_load_key_password, Toast.LENGTH_LONG)
						.show();
				return;
			}

		}

	}

	/**
	 * Inner class that create an asynchronous task in which a
	 * {@link RSAPrivateKey} is exported
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class ExportRSAPrivateKeyTask extends
			AsyncTask<RSAPrivateKey, Void, Boolean> {

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
		protected Boolean doInBackground(RSAPrivateKey... params) {

			try {
				if (spinnerEncoding.getSelectedItemPosition() == 0) {
					fileName += ".pem";
					if (chkProtectKey.isChecked()) {
						params[0].savePKCS8PEM(fileName,
								CryptoUtils.AES_256_CBC, password);
					} else {

						params[0].savePKCS8PEM(fileName);

					}
				} else {
					fileName += ".der";
					params[0].savePKCS8DER(fileName);
				}
				Log.i(PKITrustNetworkActivity.TAG, "EXPORT EC PRIVATE KEY: "
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
						R.string.msgExportKeyOK, Toast.LENGTH_LONG).show();
				returnHome();
			} else {
				Toast.makeText(getApplicationContext(),
						R.string.error_db_export_key, Toast.LENGTH_LONG).show();
			}
			// Disable the indeterminate progress icon on the action bar
			setSupportProgressBarIndeterminateVisibility(false);
		}
	}

	/**
	 * Inner class that create an asynchronous task in which a
	 * {@link ECPrivateKey} is exported
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class ExportECPrivateKeyTask extends
			AsyncTask<ECPrivateKey, Void, Boolean> {

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
		protected Boolean doInBackground(ECPrivateKey... params) {

			try {
				if (spinnerEncoding.getSelectedItemPosition() == 0) {
					fileName += ".pem";
					if (chkProtectKey.isChecked()) {
						params[0].savePKCS8PEM(fileName,
								CryptoUtils.AES_256_CBC, password);
					} else {

						params[0].savePKCS8PEM(fileName);

					}
				} else {
					fileName += ".der";
					params[0].savePKCS8DER(fileName);
				}
				Log.i(PKITrustNetworkActivity.TAG, "EXPORT EC PRIVATE KEY: "
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
						R.string.msgExportKeyOK, Toast.LENGTH_LONG).show();
				returnHome();
			} else {
				Toast.makeText(getApplicationContext(),
						R.string.error_db_export_key, Toast.LENGTH_LONG).show();
			}
			// Disable the indeterminate progress icon on the action bar
			setSupportProgressBarIndeterminateVisibility(false);
		}
	}

	/**
	 * Inner class that create an asynchronous task in which a
	 * {@link RSAKeyPair} is exported
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class ExportRSAKeyPairTask extends AsyncTask<Object, Void, Boolean> {

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
		protected Boolean doInBackground(Object... params) {

			fileName += ".p12";
			try {
				Log.i(PKITrustNetworkActivity.TAG, "EXPORT RSA PKCS KEY:"
						+ fileName);
				((RSAKeyPair) params[0]).savePKCS12(fileName, passwordPKCS,
						password, (Certificate[]) params[1]);
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
						R.string.msgExportKeyOK, Toast.LENGTH_LONG).show();
				returnHome();
			} else {
				Toast.makeText(getApplicationContext(),
						R.string.error_db_export_key, Toast.LENGTH_LONG).show();
			}
			// Disable the indeterminate progress icon on the action bar
			setSupportProgressBarIndeterminateVisibility(false);
		}
	}

	/**
	 * Inner class that create an asynchronous task in which a {@link ECKeyPair}
	 * is exported
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class ExportECKeyPairTask extends AsyncTask<Object, Void, Boolean> {

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
		protected Boolean doInBackground(Object... params) {

			fileName += ".p12";
			try {
				Log.i(PKITrustNetworkActivity.TAG, "EXPORT EC PKCS KEY:"
						+ fileName);
				((ECKeyPair) params[0]).savePKCS12(fileName, passwordPKCS,
						password, (Certificate[]) params[1]);
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
						R.string.msgExportKeyOK, Toast.LENGTH_LONG).show();
				returnHome();
			} else {
				Toast.makeText(getApplicationContext(),
						R.string.error_db_export_key, Toast.LENGTH_LONG).show();
			}
			// Disable the indeterminate progress icon on the action bar
			setSupportProgressBarIndeterminateVisibility(false);
		}
	}

	/**
	 * Inner class that create an asynchronous task in which a
	 * {@link ECPublicKey} is exported
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class ExportECPublicKeyTask extends
			AsyncTask<PersonalKeyDAO, Void, Boolean> {

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
		protected Boolean doInBackground(PersonalKeyDAO... params) {

			fileName += ".der";

			Log.i(PKITrustNetworkActivity.TAG, "EXPORT EC PUBLIC KEY: "
					+ fileName);
			try {
				ECPublicKey.decode(params[0].getKeyStr().getBytes()).saveDER(
						fileName);
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
						R.string.msgExportKeyOK, Toast.LENGTH_LONG).show();
				returnHome();
			} else {
				Toast.makeText(getApplicationContext(),
						R.string.error_db_export_key, Toast.LENGTH_LONG).show();
			}
			// Disable the indeterminate progress icon on the action bar
			setSupportProgressBarIndeterminateVisibility(false);
		}
	}

	/**
	 * Inner class that create an asynchronous task in which a
	 * {@link ECPublicKey} is exported
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class ExportRSAPublicKeyTask extends
			AsyncTask<PersonalKeyDAO, Void, Boolean> {

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
		protected Boolean doInBackground(PersonalKeyDAO... params) {

			fileName += ".der";

			Log.i(PKITrustNetworkActivity.TAG, "EXPORT RSA PUBLIC KEY: "
					+ fileName);
			try {
				RSAPublicKey.decode(params[0].getKeyStr().getBytes()).saveDER(
						fileName);
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
						R.string.msgExportKeyOK, Toast.LENGTH_LONG).show();
				returnHome();
			} else {
				Toast.makeText(getApplicationContext(),
						R.string.error_db_export_key, Toast.LENGTH_LONG).show();
			}
			// Disable the indeterminate progress icon on the action bar
			setSupportProgressBarIndeterminateVisibility(false);
		}
	}
}
