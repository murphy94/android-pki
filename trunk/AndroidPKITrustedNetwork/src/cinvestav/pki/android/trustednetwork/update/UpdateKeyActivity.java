/**
 *  Created on  : 13/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Activity that contains the fields that could be updated for a key like:
 * comment, key password and pkcs12 file password
 */
package cinvestav.pki.android.trustednetwork.update;

import java.security.cert.Certificate;

import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v4.app.DialogFragment;
import android.support.v4.app.NavUtils;
import android.support.v4.app.TaskStackBuilder;
import android.util.Log;
import android.view.View;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.Toast;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.key.ECKeyPair;
import cinvestav.android.pki.cryptography.key.ECPrivateKey;
import cinvestav.android.pki.cryptography.key.RSAKeyPair;
import cinvestav.android.pki.cryptography.key.RSAPrivateKey;
import cinvestav.android.pki.cryptography.utils.DigestCryptoUtils;
import cinvestav.android.pki.db.controller.PersonalKeyController;
import cinvestav.android.pki.db.dao.PersonalKeyDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.common.MyPasswordDialogFragment;
import cinvestav.pki.android.trustednetwork.common.MyPasswordDialogFragment.OnPositiveButtonClickListener;
import cinvestav.pki.android.trustednetwork.common.MyPasswordPKCSDialogFragment;
import cinvestav.pki.android.trustednetwork.details.KeyDetailsActivity;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

import com.actionbarsherlock.app.ActionBar;
import com.actionbarsherlock.app.SherlockFragmentActivity;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuItem;
import com.actionbarsherlock.view.Window;

/**
 * Activity that contains the fields that could be updated for a key like:
 * comment, key password and pkcs12 file password
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 13/09/2012
 * @version 1.0
 */
public class UpdateKeyActivity extends SherlockFragmentActivity {

	public static final String EXTRA_SELECTED_KEY_ID = "EXTRA_SELECTED_KEY_ID";

	static final int MENU_ACCEPT = 0;
	static final int MENU_CANCEL = 1;

	Integer keyID;
	PersonalKeyDAO key;

	String oldPasswordKey;
	String oldPasswordPKCS;

	int currentItem;
	int[] ids;

	CheckBox chkUpdatePasswordKey;
	RelativeLayout layoutPasswordKey;
	RelativeLayout layoutPasswordPKCS;

	EditText txtPasswordKey;
	EditText txtPasswordPKCS12;

	EditText txtPasswordConfirmKey;
	EditText txtPasswordConfirmPKCS12;

	EditText txtComment;

	DigestCryptoUtils digestCryptoUtils;

	UpdateRSAPrivateKeyTask updateRSAPrivateKeyTask;
	UpdateECPrivateKeyTask updateECPrivateKeyTask;

	UpdateRSAKeyPairTask updateRSAKeyPairTask;
	UpdateECKeyPairTask updateECKeyPairTask;

	static PersonalKeyController personalKeyController;
	
	public UpdateKeyActivity() {
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
			personalKeyController = new PersonalKeyController(getApplicationContext());

		}
		
		// This has to be called before setContentView and you must use the
		// class in com.actionbarsherlock.view and NOT android.view
		requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

		setContentView(R.layout.update_key);
		setSupportProgressBarIndeterminateVisibility(false);

		// Set up action bar.
		final ActionBar actionBar = getSupportActionBar();

		// Specify that the Home button should show an "Up" caret, indicating
		// that touching the
		// button will take the user one step up in the application's hierarchy.
		actionBar.setDisplayHomeAsUpEnabled(true);
		actionBar.setSubtitle(R.string.subtitle_keys_update);

		mLinearLayout = (LinearLayout) findViewById(R.id.linearLayout_focus);

		// Get intent Extras, in order to obtain the selected key id
		ids = getIntent().getIntArrayExtra(KeyDetailsActivity.EXTRA_ID_ARRAY);
		currentItem = getIntent().getIntExtra(
				KeyDetailsActivity.EXTRA_CURRENT_ITEM, 0);

		keyID = ids[currentItem];

		// Load key information from database
		try {
			key = personalKeyController
					.getById(keyID);

		} catch (DBException e) {
			Toast.makeText(this, R.string.error_db_load_key, Toast.LENGTH_SHORT)
					.show();
			Log.e(PKITrustNetworkActivity.TAG, e.toString(), e);
			returnHome();
		}

		Integer keyType = key.getKeyType();
		if (!keyType.equals(PersonalKeyDAO.PUBLIC_EC)
				&& !keyType.equals(PersonalKeyDAO.PUBLIC_RSA)) {
			((RelativeLayout) findViewById(R.id.layoutChkUpdatePassword))
					.setVisibility(RelativeLayout.VISIBLE);
			layoutPasswordKey = ((RelativeLayout) findViewById(R.id.layoutPassword));
			if (key.getKeyType().equals(PersonalKeyDAO.PKCS12_RSA)
					|| key.getKeyType().equals(PersonalKeyDAO.PKCS12_EC)) {
				layoutPasswordPKCS = ((RelativeLayout) findViewById(R.id.layoutPasswordPKCS));
			}
			/*
			 * ((RelativeLayout) findViewById(R.id.layoutChkUpdatePassword))
			 * .setVisibility(RelativeLayout.VISIBLE); ((RelativeLayout)
			 * findViewById(R.id.layoutPassword))
			 * .setVisibility(RelativeLayout.VISIBLE);
			 */

			chkUpdatePasswordKey = (CheckBox) findViewById(R.id.chkUpdateKeyPassword);
			chkUpdatePasswordKey.setOnClickListener(new View.OnClickListener() {

				@Override
				public void onClick(View v) {
					onCheckBoxClick(v);
				}
			});
			chkUpdatePasswordKey.setChecked(true);
			onCheckBoxClick(chkUpdatePasswordKey);
		}

		txtPasswordKey = (EditText) findViewById(R.id.txtPassword);
		txtPasswordConfirmKey = (EditText) findViewById(R.id.txtPasswordConfirm);
		txtPasswordPKCS12 = (EditText) findViewById(R.id.txtPasswordPKCS);
		txtPasswordConfirmPKCS12 = (EditText) findViewById(R.id.txtPasswordConfirmPKCS);
		txtComment = (EditText) findViewById(R.id.txtKeyComment);
		txtComment.setText(key.getComment());
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Place an action bar item for create the new Key.
		MenuItem itemAdd_key = menu
				.add(0, MENU_ACCEPT, 0, R.string.menu_update);
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
			returnHome();
			return true;
		case MENU_ACCEPT:
			update();
			return true;
		case MENU_CANCEL:
			returnHome();
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}

	/**
	 * Performs the actual update operation over the selected key with the new
	 * values
	 */
	public void update() {

		Integer keyType = key.getKeyType();
		// If its a public key, update the key
		if (keyType.equals(PersonalKeyDAO.PUBLIC_EC)
				|| keyType.equals(PersonalKeyDAO.PUBLIC_RSA)) {
			// Update the key comment with the one in the layout
			key.setComment(txtComment.getText().toString());

			try {
				personalKeyController.update(key,
						key.getSubjectId());
				returnHome();
			} catch (DBException e) {
				Toast.makeText(this, R.string.error_db_update_key,
						Toast.LENGTH_LONG).show();
				e.printStackTrace();
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
			}
			return;
		}

		// If its a private key validate the password fields

		if (chkUpdatePasswordKey.isChecked()) {
			String password = txtPasswordKey.getText().toString();

			// If the password field is empty show a error message and return
			if (password.isEmpty()) {
				Toast.makeText(this, R.string.error_empty_password_key,
						Toast.LENGTH_SHORT).show();
				return;
			}

			String passwordConfirm = txtPasswordConfirmKey.getText().toString();

			// Check if both passwords are equals and not empty
			if (password.equals(passwordConfirm)) {

				Boolean isPkcs = keyType.equals(PersonalKeyDAO.PKCS12_RSA)
						|| keyType.equals(PersonalKeyDAO.PKCS12_EC);
				// if the key is a PKCS check its password fields to.
				if (isPkcs) {
					// Get the password and password confirm fields
					String passwordPKCS = txtPasswordPKCS12.getText()
							.toString();
					// If the password field is empty show a error message and
					// return
					if (passwordPKCS.isEmpty()) {
						Toast.makeText(this,
								R.string.error_empty_password_pkcs,
								Toast.LENGTH_SHORT).show();
						return;
					}

					String passwordConfirmPKCS = txtPasswordConfirmPKCS12
							.getText().toString();

					// Check if both passwords are equals and not empty
					if (!passwordPKCS.equals(passwordConfirmPKCS)) {
						Toast.makeText(this,
								R.string.error_notmatch_password_pkcs,
								Toast.LENGTH_SHORT).show();
						return;
					}

				}
			} else {
				Toast.makeText(this, R.string.error_notmatch_password_key,
						Toast.LENGTH_SHORT).show();
				return;
			}

		}

		// Determine the key type and decode it
		if (keyType.equals(PersonalKeyDAO.PRIVATE_RSA)) {
			// If is a RSAPrivateKey ask for the password
			DialogFragment newFragment = MyPasswordDialogFragment.newInstance(
					R.string.alert_dialog_key_update_private_title, key,
					new OnPositiveButtonClickListenerUpdateImp());
			newFragment.show(getSupportFragmentManager(), "password");
		} else if (keyType.equals(PersonalKeyDAO.PKCS12_RSA)) {
			// If is a PKCS_RSA file, ask for the password
			DialogFragment newFragment = MyPasswordPKCSDialogFragment
					.newInstance(
							R.string.alert_dialog_key_update_private_title,
							key, new OnPositiveButtonClickListenerUpdateImp());
			newFragment.show(getSupportFragmentManager(), "password");
		} else if (keyType.equals(PersonalKeyDAO.PRIVATE_EC)) {
			// If is a ECPrivateKey ask for the password
			DialogFragment newFragment = MyPasswordDialogFragment.newInstance(
					R.string.alert_dialog_key_update_private_title, key,
					new OnPositiveButtonClickListenerUpdateImp());
			newFragment.show(getSupportFragmentManager(), "password");
		} else if (keyType.equals(PersonalKeyDAO.PKCS12_EC)) {
			// If is a PKCS_RC file, ask for the password
			DialogFragment newFragment = MyPasswordPKCSDialogFragment
					.newInstance(
							R.string.alert_dialog_key_update_private_title,
							key, new OnPositiveButtonClickListenerUpdateImp());
			newFragment.show(getSupportFragmentManager(), "password");
		}

	}

	/**
	 * Perform the actual update operation over a {@link RSAPrivateKey} that was
	 * decoded in {@link MyPasswordDialogFrament}
	 * 
	 * @param privateKey
	 *            Decoded RSA private key
	 */
	public void update(RSAPrivateKey privateKey) {
		// Update the key comment with the one in the layout
		key.setComment(txtComment.getText().toString());
		if (updateRSAPrivateKeyTask == null) {
			updateRSAPrivateKeyTask = new UpdateRSAPrivateKeyTask();
			updateRSAPrivateKeyTask.execute(privateKey);
		} else {
			Toast.makeText(this, R.string.msgWorking, Toast.LENGTH_SHORT)
					.show();
		}
	}

	/**
	 * Perform the actual update operation over a {@link ECPrivateKey} that was
	 * decoded in {@link MyPasswordDialogFrament}
	 * 
	 * @param privateKey
	 *            Decoded EC private key
	 */
	public void update(ECPrivateKey privateKey) {
		// Update the key comment with the one in the layout
		key.setComment(txtComment.getText().toString());
		if (updateECPrivateKeyTask == null) {
			updateECPrivateKeyTask = new UpdateECPrivateKeyTask();
			updateECPrivateKeyTask.execute(privateKey);
		} else {
			Toast.makeText(this, R.string.msgWorking, Toast.LENGTH_SHORT)
					.show();
		}
	}

	/**
	 * Perform the actual update operation over a {@link RSAKeyPair} that was
	 * decoded in {@link MyPasswordPKCSDialogFrament}
	 * 
	 * @param keyPair
	 *            Decoded RSA key pair
	 */
	public void update(RSAKeyPair keyPair, Certificate[] chain) {
		// Update the key comment with the one in the layout
		key.setComment(txtComment.getText().toString());
		if (updateRSAKeyPairTask == null) {
			updateRSAKeyPairTask = new UpdateRSAKeyPairTask();
			updateRSAKeyPairTask.execute(keyPair, chain);
		} else {
			Toast.makeText(this, R.string.msgWorking, Toast.LENGTH_SHORT)
					.show();
		}
	}

	/**
	 * Perform the actual update operation over a {@link ECKeyPair} that was
	 * decoded in {@link MyPasswordPKCSDialogFrament}
	 * 
	 * @param keyPair
	 *            Decoded RSA key pair
	 */
	public void update(ECKeyPair keyPair, Certificate[] chain) {
		// Update the key comment with the one in the layout
		key.setComment(txtComment.getText().toString());
		if (updateECKeyPairTask == null) {
			updateECKeyPairTask = new UpdateECKeyPairTask();
			updateECKeyPairTask.execute(keyPair, chain);
		} else {
			Toast.makeText(this, R.string.msgWorking, Toast.LENGTH_SHORT)
					.show();
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
			layoutPasswordKey.setVisibility(RelativeLayout.VISIBLE);
			// If the PKCS password layout is null, its visibility should
			// not change
			if (layoutPasswordPKCS != null) {
				layoutPasswordPKCS.setVisibility(RelativeLayout.VISIBLE);
			}
		} else {
			layoutPasswordKey.setVisibility(RelativeLayout.GONE);
			// If the PKCS password layout is null, its visibility should
			// not change
			if (layoutPasswordPKCS != null) {
				layoutPasswordPKCS.setVisibility(RelativeLayout.GONE);
			}
		}
	}

	/**
	 * This is called to return home in the application navigation scheme
	 */
	private void returnHome() {
		if (updateECPrivateKeyTask != null) {
			updateECPrivateKeyTask.cancel(true);
		}
		if (updateRSAPrivateKeyTask != null) {
			updateRSAPrivateKeyTask.cancel(true);
		}
		if (updateECKeyPairTask != null) {
			updateECKeyPairTask.cancel(true);
		}
		if (updateRSAKeyPairTask != null) {
			updateRSAKeyPairTask.cancel(true);
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
	 * Implements the OnPositiveButtonClickListener for update operation, after
	 * the password dialog is shown, this function is called
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 14/09/2012
	 * @version 1.0
	 */
	public class OnPositiveButtonClickListenerUpdateImp implements
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
			// The key should be decoded, if no exception is thrown, it means
			// that the inserted password is OK, so the operation process should
			// continue, if the password is wrong cancel the operation
			try {
				if (key.getKeyType().equals(PersonalKeyDAO.PRIVATE_EC)) {
					// If the key is a Private EC key

					ECPrivateKey privKey = ECPrivateKey.decode(key.getKeyStr()
							.getBytes(), passwordKey);

					// Send the decoded key to update process
					update(privKey);

				} else {
					// If the key is a Private RSA key

					RSAPrivateKey privKey = RSAPrivateKey.decode(key
							.getKeyStr().getBytes(), passwordKey);

					// Send the decoded key to update process
					update(privKey);

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
		 * #onPositiveButtonClick(cinvestav.android
		 * .pki.db.dao.PersonalKeyDAO, java.lang.String,
		 * java.lang.String)
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
					update((ECKeyPair) decodedECKeyPair[0],
							(Certificate[]) decodedECKeyPair[1]);

				} else {
					// If the key is a PKCS RSA key
					Object[] decodedRSAKeyPair = RSAKeyPair.decodePKCS12(key
							.getKeyStr().getBytes(), passwordPKCS, passwordKey);

					// Send the decoded key to update process
					update((RSAKeyPair) decodedRSAKeyPair[0],
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
	 * {@link RSAPrivateKey} is updated
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class UpdateRSAPrivateKeyTask extends
			AsyncTask<RSAPrivateKey, Void, PersonalKeyDAO> {

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
		protected PersonalKeyDAO doInBackground(RSAPrivateKey... params) {

			try {
				if (chkUpdatePasswordKey.isChecked()) {
					String encodedKeyStr = "";
					encodedKeyStr = new String(params[0].encode(txtPasswordKey
							.getText().toString()));
					key.setKeyStr(encodedKeyStr);
				}

				personalKeyController.update(key,
						key.getSubjectId());
				return key;
			} catch (DBException e) {
				e.printStackTrace();
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
			} catch (CryptoUtilsException e) {
				e.printStackTrace();
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
			}
			return null;
		}

		@Override
		protected void onPostExecute(PersonalKeyDAO keyPair) {
			if (keyPair != null) {
				Toast.makeText(getApplicationContext(),
						R.string.msgUpdateKeyOK, Toast.LENGTH_LONG).show();
				returnHome();
			} else {
				Toast.makeText(getApplicationContext(),
						R.string.error_db_update_key, Toast.LENGTH_LONG).show();
			}
			// Disable the indeterminate progress icon on the action bar
			setSupportProgressBarIndeterminateVisibility(false);
		}
	}

	/**
	 * Inner class that create an asynchronous task in which a
	 * {@link ECPrivateKey} is updated
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class UpdateECPrivateKeyTask extends
			AsyncTask<ECPrivateKey, Void, PersonalKeyDAO> {

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
		protected PersonalKeyDAO doInBackground(ECPrivateKey... params) {

			try {
				if (chkUpdatePasswordKey.isChecked()) {
					String encodedKeyStr = "";
					encodedKeyStr = new String(params[0].encode(txtPasswordKey
							.getText().toString()));
					key.setKeyStr(encodedKeyStr);
				}

				personalKeyController.update(key,
						key.getSubjectId());
				return key;
			} catch (DBException e) {

				e.printStackTrace();
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
			} catch (CryptoUtilsException e) {
				e.printStackTrace();
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
			}
			return null;
		}

		@Override
		protected void onPostExecute(PersonalKeyDAO keyPair) {
			if (keyPair != null) {
				Toast.makeText(getApplicationContext(),
						R.string.msgUpdateKeyOK, Toast.LENGTH_LONG).show();
				returnHome();
			} else {
				Toast.makeText(getApplicationContext(),
						R.string.error_db_update_key, Toast.LENGTH_LONG).show();
			}
			// Disable the indeterminate progress icon on the action bar
			setSupportProgressBarIndeterminateVisibility(false);
		}
	}

	/**
	 * Inner class that create an asynchronous task in which a
	 * {@link RSAKeyPair} is updated
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class UpdateRSAKeyPairTask extends
			AsyncTask<Object, Void, PersonalKeyDAO> {

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
		protected PersonalKeyDAO doInBackground(Object... params) {

			try {
				if (chkUpdatePasswordKey.isChecked()) {
					String encodedKeyStr = "";
					encodedKeyStr = new String(
							((RSAKeyPair) params[0]).encodePKCS12(
									txtPasswordPKCS12.getText().toString(),
									txtPasswordKey.getText().toString(),
									(Certificate[]) params[1]));
					key.setKeyStr(encodedKeyStr);
				}

				personalKeyController.update(key,
						key.getSubjectId());
				return key;
			} catch (DBException e) {
				e.printStackTrace();
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
			} catch (CryptoUtilsException e) {
				e.printStackTrace();
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
			}
			return null;
		}

		@Override
		protected void onPostExecute(PersonalKeyDAO keyPair) {
			if (keyPair != null) {
				Toast.makeText(getApplicationContext(),
						R.string.msgUpdateKeyOK, Toast.LENGTH_LONG).show();
				returnHome();
			} else {
				Toast.makeText(getApplicationContext(),
						R.string.error_db_update_key, Toast.LENGTH_LONG).show();
			}
			// Disable the indeterminate progress icon on the action bar
			setSupportProgressBarIndeterminateVisibility(false);
		}
	}

	/**
	 * Inner class that create an asynchronous task in which a {@link ECKeyPair}
	 * is updated
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class UpdateECKeyPairTask extends
			AsyncTask<Object, Void, PersonalKeyDAO> {

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
		protected PersonalKeyDAO doInBackground(Object... params) {

			try {
				if (chkUpdatePasswordKey.isChecked()) {
					String encodedKeyStr = "";
					encodedKeyStr = new String(
							((ECKeyPair) params[0]).encodePKCS12(
									txtPasswordPKCS12.getText().toString(),
									txtPasswordKey.getText().toString(),
									(Certificate[]) params[1]));
					key.setKeyStr(encodedKeyStr);
				}

				personalKeyController.update(key,
						key.getSubjectId());
				return key;
			} catch (DBException e) {
				e.printStackTrace();
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
			} catch (CryptoUtilsException e) {
				e.printStackTrace();
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
			}
			return null;
		}

		@Override
		protected void onPostExecute(PersonalKeyDAO keyPair) {
			if (keyPair != null) {
				Toast.makeText(getApplicationContext(),
						R.string.msgUpdateKeyOK, Toast.LENGTH_LONG).show();
				returnHome();
			} else {
				Toast.makeText(getApplicationContext(),
						R.string.error_db_update_key, Toast.LENGTH_LONG).show();
			}
			// Disable the indeterminate progress icon on the action bar
			setSupportProgressBarIndeterminateVisibility(false);
		}
	}
}
