/**
 *  Created on  : 05/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Activity for creating a new key pair
 */
package cinvestav.pki.android.trustednetwork.add;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Parcelable;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentActivity;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentStatePagerAdapter;
import android.support.v4.app.NavUtils;
import android.support.v4.app.TaskStackBuilder;
import android.support.v4.view.ViewPager;
import android.util.Log;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.Toast;
import cinvestav.android.pki.cryptography.cert.CertificateInformationKeys;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsX509ExtensionException;
import cinvestav.android.pki.cryptography.key.ECKeyPair;
import cinvestav.android.pki.cryptography.key.RSAKeyPair;
import cinvestav.android.pki.cryptography.utils.AsymmetricCryptoUtils;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;
import cinvestav.android.pki.cryptography.utils.DigestCryptoUtils;
import cinvestav.android.pki.cryptography.utils.X509Utils;
import cinvestav.android.pki.cryptography.utils.X509UtilsDictionary;
import cinvestav.android.pki.db.controller.PersonalKeyController;
import cinvestav.android.pki.db.controller.SubjectController;
import cinvestav.android.pki.db.dao.PersonalKeyDAO;
import cinvestav.android.pki.db.dao.SubjectDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;
import cinvestav.pki.android.trustednetwork.selection.SelectKeyActivity;
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
public class AddNewKeyActivity extends SherlockFragmentActivity {

	/**
	 * The {@link android.support.v4.view.PagerAdapter} that will provide
	 * fragments representing each object in a collection. We use a
	 * {@link android.support.v4.app.FragmentStatePagerAdapter} derivative,
	 * which will destroy and re-create fragments as needed, saving and
	 * restoring their state in the process. This is important to conserve
	 * memory and is a best practice when allowing navigation between objects in
	 * a potentially large collection.
	 */
	NewKeyCollectionPagerAdapter mCollectionPagerAdapter;

	/**
	 * The {@link android.support.v4.view.ViewPager} that will display the
	 * object collection.
	 */
	ViewPager mViewPager;
	AsymmetricCryptoUtils asymmetricCryptoUtils;
	DigestCryptoUtils digestCryptoUtils;
	private X509Utils _X509Utils;

	static final int MENU_ACCEPT = 0;
	static final int MENU_CANCEL = 1;

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
	// SubjectDAO subject;
	Integer subjectID;

	/**
	 * Comment for that key pair
	 */
	String comment;

	/**
	 * Encoding for the key id
	 */
	String encoding;

	/**
	 * Digest function name for the key id
	 */
	String digest;

	/**
	 * Asynchronous task for creating RSA keys
	 */
	CreateRSAKeyTask createRSAKeyTask;

	/**
	 * Asynchronous task for creating EC keys
	 */
	CreateECKeyTask createECKeyTask;

	FragmentActivity keyAuxActivity;

	Boolean isPkcs;
	private int current_option;

	static PersonalKeyController personalKeyController;
	static SubjectController subjectController;

	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		personalKeyController = new PersonalKeyController(
				getApplicationContext());
		subjectController = new SubjectController(getApplicationContext());

		// This has to be called before setContentView and you must use the
		// class in com.actionbarsherlock.view and NOT android.view
		requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

		setContentView(R.layout.detail_collection);
		setSupportProgressBarIndeterminateVisibility(false);

		// Set up action bar.
		final ActionBar actionBar = getSupportActionBar();

		// Specify that the Home button should show an "Up" caret, indicating
		// that touching the
		// button will take the user one step up in the application's hierarchy.
		actionBar.setDisplayHomeAsUpEnabled(true);
		actionBar.setSubtitle(R.string.subtitle_keys_new);

		// Create an adapter that when requested, will return a fragment
		// representing an object in
		// the collection.
		//
		// ViewPager and its adapters use support library fragments, so we must
		// use
		// getSupportFragmentManager.
		mCollectionPagerAdapter = new NewKeyCollectionPagerAdapter(
				getSupportFragmentManager());

		// Set up the ViewPager, attaching the adapter.
		mViewPager = (ViewPager) findViewById(R.id.pager);
		mViewPager.setAdapter(mCollectionPagerAdapter);

		asymmetricCryptoUtils = new AsymmetricCryptoUtils();
		digestCryptoUtils = new DigestCryptoUtils();
		try {
			_X509Utils = new X509Utils();
		} catch (CryptoUtilsException e) {
			e.printStackTrace();
		}

		// Get Selected subject ID
		subjectID = getIntent().getIntExtra(
				SelectOwnerActivity.EXTRA_SELECTED_OWNER_ID, 0);

		current_option = this.getIntent().getExtras()
				.getInt(PKITrustNetworkActivity.CURRENT_OPTION);

	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Place an action bar item for create the new Key.
		MenuItem itemAdd_key = menu.add(0, MENU_ACCEPT, 0, R.string.menu_add);
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
			createKey();
			return true;
		case MENU_CANCEL:
			returnHome(MENU_CANCEL);
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}

	/**
	 * This is called when the user selects the create button, here is were the
	 * key is inserted in the data base
	 */
	public void createKey() {
		// Get the activity of the key fragment
		keyAuxActivity = mCollectionPagerAdapter.getFragmentKey().getActivity();
		/*
		 * subject = certificateCollectionPagerAdapter.getFragmentOwner()
		 * .getSelectedSubject();
		 */

		// Get the password and password confirm fields
		password = ((EditText) keyAuxActivity.findViewById(R.id.txtPassword))
				.getText().toString();
		// If the password field is empty show a error message and return
		if (password.isEmpty()) {
			Toast.makeText(this, R.string.error_empty_password_key,
					Toast.LENGTH_SHORT).show();
			return;
		}

		String passwordConfirm = ((EditText) keyAuxActivity
				.findViewById(R.id.txtPasswordConfirm)).getText().toString();

		// Check if both passwords are equals and not empty
		if (password.equals(passwordConfirm)) {

			// Get the selected key type from the key fragment
			String spinnerKeyType = (String) ((Spinner) keyAuxActivity
					.findViewById(R.id.spinnerKeyType)).getSelectedItem();

			comment = ((EditText) keyAuxActivity
					.findViewById(R.id.txtKeyComment)).getText().toString();

			digest = (String) ((Spinner) keyAuxActivity
					.findViewById(R.id.spinnerDigest)).getSelectedItem();
			digest = digest.replace("(*)", "");
			digest = digest.trim();

			encoding = ((String) ((Spinner) keyAuxActivity
					.findViewById(R.id.spinnerIDEncoding)).getSelectedItem())
					.equalsIgnoreCase("Base64") ? CryptoUtils.ENCODER_BASE64
					: CryptoUtils.ENCODER_HEX;
			encoding = encoding.replace("(*)", "");
			encoding = encoding.trim();

			isPkcs = ((CheckBox) keyAuxActivity
					.findViewById(R.id.chkSaveAsPKCS12)).isChecked();

			if (isPkcs) {
				// Get the password and password confirm fields
				passwordPKCS = ((EditText) keyAuxActivity
						.findViewById(R.id.txtPasswordPKCS)).getText()
						.toString();
				// If the password field is empty show a error message and
				// return
				if (passwordPKCS.isEmpty()) {
					Toast.makeText(this, R.string.error_empty_password_pkcs,
							Toast.LENGTH_SHORT).show();
					return;
				}

				String passwordConfirmPKCS = ((EditText) keyAuxActivity
						.findViewById(R.id.txtPasswordConfirmPKCS)).getText()
						.toString();

				// Check if both passwords are equals and not empty
				if (!passwordPKCS.equals(passwordConfirmPKCS)) {
					Toast.makeText(this, R.string.error_notmatch_password_pkcs,
							Toast.LENGTH_SHORT).show();
					return;
				}

			}

			// If RSA is selected as key type
			if (spinnerKeyType.equals("RSA")) {
				// Get the key size
				String keySize = ((EditText) keyAuxActivity
						.findViewById(R.id.txtSize)).getText().toString();
				if (keySize.isEmpty()) {
					Toast.makeText(this, R.string.error_empty_keySize,
							Toast.LENGTH_SHORT).show();
					return;
				}

				Integer keySizeInt = Integer.parseInt(keySize);
				// Check if the key size is at least of 1024 bits
				if (keySizeInt < 1024) {
					Toast.makeText(this, R.string.error_keySizeToShort,
							Toast.LENGTH_SHORT).show();
					return;
				}

				createRSAKeyTask = new CreateRSAKeyTask();
				createRSAKeyTask.execute(keySizeInt);
				Log.i(PKITrustNetworkActivity.TAG,
						"KEY: " + spinnerKeyType.toString() + ", Size: "
								+ keySize);
			} else {
				// If EC is selected as key type

				// Get the selected EC Field
				/*
				 * String spinnerECField = (String) ((Spinner) keyAuxActivity
				 * .findViewById(R.id.spinnerECField)).getSelectedItem();
				 */

				// Get the selected EC Curve
				String spinnerECCurve = (String) ((Spinner) keyAuxActivity
						.findViewById(R.id.spinnerECCurve)).getSelectedItem();

				createECKeyTask = new CreateECKeyTask();
				createECKeyTask.execute(spinnerECCurve);

				Log.i(PKITrustNetworkActivity.TAG,
						"KEY: " + spinnerKeyType.toString() + " Curve: "
								+ spinnerECCurve);
			}
		} else {
			Toast.makeText(this, R.string.error_notmatch_password_key,
					Toast.LENGTH_SHORT).show();
			return;
		}

	}

	/**
	 * This is called to return home in the application navigation scheme
	 */
	private void returnHome(Integer option) {

		if (createECKeyTask != null)
			createECKeyTask.cancel(true);
		if (createRSAKeyTask != null)
			createRSAKeyTask.cancel(true);

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
	 * A {@link android.support.v4.app.FragmentStatePagerAdapter} that returns a
	 * fragment pager that will contains two pages, one for basic key
	 * information and the other for advanced key information.
	 */
	public class NewKeyCollectionPagerAdapter extends FragmentStatePagerAdapter {

		AddNewKeyInformationFragment fragmentKey;
		AddNewKeyAdvancedInformationFragment fragmentAdvanced;
		private final FragmentManager mFragmentManager;

		private static final int KEY_PAGE = 0;
		private static final int ADVANCED_PAGE = 1;

		public NewKeyCollectionPagerAdapter(FragmentManager fm) {
			super(fm);
			mFragmentManager = fm;
		}

		/**
		 * @return the fragmentCertificateInformation
		 */
		public AddNewKeyInformationFragment getFragmentKey() {
			return fragmentKey;
		}

		/**
		 * @return the fragmentHolder
		 */
		public AddNewKeyAdvancedInformationFragment getFragmentAdvanced() {
			return fragmentAdvanced;
		}

		@Override
		public Fragment getItem(int i) {
			Log.i(PKITrustNetworkActivity.TAG, "GET ITEM " + i);
			// Chose between the two availably: Owner or key
			switch (i) {
			case KEY_PAGE:
				Log.i(PKITrustNetworkActivity.TAG, "NEW KEY");
				if (fragmentKey == null) {
					fragmentKey = new AddNewKeyInformationFragment();
				}
				return fragmentKey;

			case ADVANCED_PAGE:
				Log.i(PKITrustNetworkActivity.TAG, "NEW ADVANCED");
				if (fragmentAdvanced == null) {
					fragmentAdvanced = new AddNewKeyAdvancedInformationFragment();
				}
				return fragmentAdvanced;

			}

			return new AddNewKeyInformationFragment();
		}

		@Override
		public int getCount() {
			// Get the count of personal Keys
			return 2;
		}

		@Override
		public CharSequence getPageTitle(int position) {
			switch (position) {
			case KEY_PAGE:
				return getResources().getString(R.string.detail_title_key);
			case ADVANCED_PAGE:
				return getResources().getString(R.string.detail_title_advanced);
			default:
				return "";
			}

		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * android.support.v4.view.PagerAdapter#getItemPosition(java.lang.Object
		 * )
		 */
		@Override
		public int getItemPosition(Object object) {
			// ViewPager uses the getItemPosition() abstract method to check
			// which pages should be destroyed and which should be kept. The
			// default implementation of this function always returns
			// POSITION_UNCHANGED, which causes ViewPager to keep all current
			// pages, and consequently not attaching your new page. Thus, to
			// make fragment replacement work, getItemPosition() needs to be
			// overridden in your adapter and must return POSITION_NONE when
			// called with an old, to be hidden, fragment as argument.
			Log.i(PKITrustNetworkActivity.TAG, "GET ITEM POS " + object);

			return POSITION_UNCHANGED;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * android.support.v4.app.FragmentStatePagerAdapter#restoreState(android
		 * .os.Parcelable, java.lang.ClassLoader)
		 */
		@Override
		public void restoreState(Parcelable state, ClassLoader loader) {
			super.restoreState(state, loader);
			if (state != null) {
				Bundle bundle = (Bundle) state;
				Iterable<String> keys = bundle.keySet();
				for (String key : keys) {
					if (key.startsWith("f")) {
						Fragment f = mFragmentManager.getFragment(bundle, key);
						if (f instanceof AddNewKeyInformationFragment) {
							fragmentKey = (AddNewKeyInformationFragment) f;
						} else if (f instanceof AddNewKeyAdvancedInformationFragment) {
							fragmentAdvanced = (AddNewKeyAdvancedInformationFragment) f;
						}

					}
				}
			}
		}

	}

	/**
	 * Inner class that create an asynchronous task in which a
	 * {@link RSAKeyPair} is created
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class CreateRSAKeyTask extends
			AsyncTask<Integer, Void, PersonalKeyDAO> {

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
		protected PersonalKeyDAO doInBackground(Integer... params) {

			try {
				RSAKeyPair rsaKeyPair = asymmetricCryptoUtils
						.generateKeys(params[0]);

				PersonalKeyDAO key = new PersonalKeyDAO();
				String keyID = "";
				String encodedKeyStr = "";
				// If the PKCS check box is not enabled insert the private and
				// public key in separate rows

				if (!isPkcs) {

					// ADD RSA Public key
					key.setKeyType(PersonalKeyDAO.PUBLIC_RSA);
					encodedKeyStr = new String(rsaKeyPair.getPublicKey()
							.encode());
					key.setKeyStr(encodedKeyStr);
					keyID = digestCryptoUtils.getDigest(encodedKeyStr, digest,
							encoding);
					key.setKeyID(keyID);
					key.setComment(comment);
					personalKeyController.insert(key, subjectID);

					// ADD RSA Private key
					key = new PersonalKeyDAO();

					key.setKeyType(PersonalKeyDAO.PRIVATE_RSA);
					encodedKeyStr = new String(rsaKeyPair.getPrivateKey()
							.encode(password));
					keyID = digestCryptoUtils.getDigest(encodedKeyStr, digest,
							encoding);
					key.setKeyStr(encodedKeyStr);
					key.setKeyID(keyID);
					key.setComment(comment);
					personalKeyController.insert(key, subjectID);
					Integer id = personalKeyController.insert(key, subjectID);
					key.setId(id);
				} else {
					SubjectDAO subject = subjectController.getById(subjectID);
					// Create one PKCS#12 file and insert it to the data base
					// ADD RSA PKCS12
					key = new PersonalKeyDAO();
					key.setKeyType(PersonalKeyDAO.PKCS12_RSA);

					Date notBefore = new Date(System.currentTimeMillis());
					Date notAfter = new Date(System.currentTimeMillis() + 1000L
							* 60 * 60 * 24 * 256);

					// Creates Root CA self signed certificate
					X509Certificate[] chain = new X509Certificate[1];

					HashMap<String, String> subjectCertificateInformationMap = new HashMap<String, String>();
					subjectCertificateInformationMap.put(
							CertificateInformationKeys.FRIENDLY_NAME,
							subject.getName());
					subjectCertificateInformationMap.put(
							CertificateInformationKeys.FULL_COMMON_NAME,
							subject.getName());
					subjectCertificateInformationMap.put(
							CertificateInformationKeys.DEVICE_ID,
							PKITrustNetworkActivity.ANDROID_ID);

					Boolean certSign = ((CheckBox) keyAuxActivity
							.findViewById(R.id.chkKeyUsageCertSign))
							.isChecked();
					Boolean crlSign = ((CheckBox) keyAuxActivity
							.findViewById(R.id.chkKeyUsageCRLSign)).isChecked();
					Boolean dataCipher = ((CheckBox) keyAuxActivity
							.findViewById(R.id.chkKeyUsageDataCipher))
							.isChecked();
					Boolean dataSign = ((CheckBox) keyAuxActivity
							.findViewById(R.id.chkKeyUsageDataSign))
							.isChecked();
					Boolean keyCipher = ((CheckBox) keyAuxActivity
							.findViewById(R.id.chkKeyUsageKeyCipher))
							.isChecked();

					List<Integer> keyUsageList = new LinkedList<Integer>();
					if (crlSign)
						keyUsageList
								.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
					if (dataCipher)
						keyUsageList
								.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
					if (dataSign)
						keyUsageList
								.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
					if (certSign)
						keyUsageList
								.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
					if (keyCipher)
						keyUsageList
								.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);

					chain[0] = _X509Utils
							.createV3Cert(
									rsaKeyPair.getPublicKey(),
									rsaKeyPair.getPrivateKey(),
									BigInteger.valueOf(1),
									notBefore,
									notAfter,
									subjectCertificateInformationMap,
									keyUsageList,
									X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA,
									X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_SHA1withRSA);
					encodedKeyStr = new String(rsaKeyPair.encodePKCS12(
							passwordPKCS, password, chain));
					key.setKeyStr(encodedKeyStr);
					key.setKeyID(digestCryptoUtils.getDigest(encodedKeyStr,
							digest, encoding));
					key.setComment(comment);
					Integer id = personalKeyController.insert(key, subjectID);
					key.setId(id);
				}

				return key;

			} catch (CryptoUtilsException e) {
				e.printStackTrace();
			} catch (DBException e) {
				e.printStackTrace();
			} catch (CryptoUtilsX509ExtensionException e) {
				e.printStackTrace();
			}

			return null;

		}

		@Override
		protected void onPostExecute(PersonalKeyDAO keyPair) {
			if (keyPair != null) {
				Toast.makeText(getApplicationContext(), R.string.msgAddKeyOK,
						Toast.LENGTH_LONG).show();
				if (current_option == PKITrustNetworkActivity.KEY) {
					returnHome(android.R.id.home);
				} else if (current_option == PKITrustNetworkActivity.CERTIFICATE) {
					// Select key activity
					// Show create new key fragment
					Intent intent = new Intent(getApplicationContext(),
							AddNewCertificateActivity.class);
					intent.putExtra(
							SelectOwnerActivity.EXTRA_SELECTED_OWNER_ID,
							subjectID);
					intent.putExtra(
							SelectKeyActivity.EXTRA_SELECTED_PERSONAL_KEY_ID,
							keyPair.getId());

					startActivity(intent);
				}
			} else {
				Toast.makeText(getApplicationContext(),
						R.string.error_key_creation, Toast.LENGTH_LONG).show();
			}
			// Disable the indeterminate progress icon on the action bar
			setSupportProgressBarIndeterminateVisibility(false);
		}
	}

	/**
	 * Inner class that create an asynchronous task in which a {@link ECKeyPair}
	 * is created
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class CreateECKeyTask extends
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
				ECKeyPair ecKeyPair = asymmetricCryptoUtils
						.generateKeys(params[0]);

				PersonalKeyDAO key = new PersonalKeyDAO();
				String keyID = "";
				String encodedKeyStr = "";
				// If the PKCS check box is not enabled insert the private and
				// public key in separate rows

				if (!isPkcs) {
					// ADD EC Public key
					key.setKeyType(PersonalKeyDAO.PUBLIC_EC);
					encodedKeyStr = new String(ecKeyPair.getPublicKey()
							.encode());
					key.setKeyStr(encodedKeyStr);
					keyID = digestCryptoUtils.getDigest(encodedKeyStr, digest,
							encoding);
					key.setKeyID(keyID);
					key.setComment(comment);
					personalKeyController.insert(key, subjectID);

					// ADD EC Private key
					key = new PersonalKeyDAO();

					key.setKeyType(PersonalKeyDAO.PRIVATE_EC);
					encodedKeyStr = new String(ecKeyPair.getPrivateKey()
							.encode(password));
					key.setKeyStr(encodedKeyStr);
					keyID = digestCryptoUtils.getDigest(encodedKeyStr, digest,
							encoding);
					key.setKeyID(keyID);
					key.setComment(comment);
					Integer id = personalKeyController.insert(key, subjectID);
					key.setId(id);
				} else {
					SubjectDAO subject = subjectController.getById(subjectID);
					// Create one PKCS#12 file and insert it to the data base
					// ADD RSA PKCS12
					key = new PersonalKeyDAO();
					key.setKeyType(PersonalKeyDAO.PKCS12_EC);

					Date notBefore = new Date(System.currentTimeMillis());
					Date notAfter = new Date(System.currentTimeMillis() + 1000L
							* 60 * 60 * 24 * 256);

					// Creates Root CA self signed certificate
					X509Certificate[] chain = new X509Certificate[1];

					HashMap<String, String> subjectCertificateInformationMap = new HashMap<String, String>();
					subjectCertificateInformationMap.put(
							CertificateInformationKeys.FRIENDLY_NAME,
							subject.getName());
					subjectCertificateInformationMap.put(
							CertificateInformationKeys.FULL_COMMON_NAME,
							subject.getName());
					subjectCertificateInformationMap.put(
							CertificateInformationKeys.DEVICE_ID,
							PKITrustNetworkActivity.ANDROID_ID);

					Boolean certSign = ((CheckBox) keyAuxActivity
							.findViewById(R.id.chkKeyUsageCertSign))
							.isChecked();
					Boolean crlSign = ((CheckBox) keyAuxActivity
							.findViewById(R.id.chkKeyUsageCRLSign)).isChecked();
					Boolean dataCipher = ((CheckBox) keyAuxActivity
							.findViewById(R.id.chkKeyUsageDataCipher))
							.isChecked();
					Boolean dataSign = ((CheckBox) keyAuxActivity
							.findViewById(R.id.chkKeyUsageDataSign))
							.isChecked();
					Boolean keyCipher = ((CheckBox) keyAuxActivity
							.findViewById(R.id.chkKeyUsageKeyCipher))
							.isChecked();

					List<Integer> keyUsageList = new LinkedList<Integer>();
					if (crlSign)
						keyUsageList
								.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
					if (dataCipher)
						keyUsageList
								.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
					if (dataSign)
						keyUsageList
								.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
					if (certSign)
						keyUsageList
								.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
					if (keyCipher)
						keyUsageList
								.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);

					chain[0] = _X509Utils
							.createV3Cert(
									ecKeyPair.getPublicKey(),
									ecKeyPair.getPrivateKey(),
									BigInteger.valueOf(1),
									notBefore,
									notAfter,
									subjectCertificateInformationMap,
									keyUsageList,
									X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA,
									X509UtilsDictionary.EC_X509_SIGN_ALGORITHM_SHA1withECDSA);
					encodedKeyStr = new String(ecKeyPair.encodePKCS12(
							passwordPKCS, password, chain));
					key.setKeyStr(encodedKeyStr);
					key.setKeyID(digestCryptoUtils.getDigest(encodedKeyStr,
							digest, encoding));
					key.setComment(comment);
					Integer id = personalKeyController.insert(key, subjectID);
					key.setId(id);
				}
				return key;

			} catch (CryptoUtilsException e) {
				e.printStackTrace();
			} catch (DBException e) {
				e.printStackTrace();
			} catch (CryptoUtilsX509ExtensionException e) {
				e.printStackTrace();
			}

			return null;

		}

		@Override
		protected void onPostExecute(PersonalKeyDAO keyPair) {
			if (keyPair != null) {
				Toast.makeText(getApplicationContext(), R.string.msgAddKeyOK,
						Toast.LENGTH_LONG).show();
				if (current_option == PKITrustNetworkActivity.KEY) {
					returnHome(android.R.id.home);
				} else if (current_option == PKITrustNetworkActivity.CERTIFICATE) {
					// Select key activity
					// Show create new key fragment
					Intent intent = new Intent(getApplicationContext(),
							AddNewCertificateActivity.class);
					intent.putExtra(
							SelectOwnerActivity.EXTRA_SELECTED_OWNER_ID,
							subjectID);
					intent.putExtra(
							SelectKeyActivity.EXTRA_SELECTED_PERSONAL_KEY_ID,
							keyPair.getId());

					startActivity(intent);
				}
			} else {
				Toast.makeText(getApplicationContext(),
						R.string.error_key_creation, Toast.LENGTH_LONG).show();
			}
			// Disable the indeterminate progress icon on the action bar
			setSupportProgressBarIndeterminateVisibility(false);
		}
	}
}
