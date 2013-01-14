/**
 *  Created on  : 03/10/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	This activity contains a ViewPager with two pages, one for certificates list
 * and the other for key list, so the user could select the corresponding
 * certificate and private key, at the end both elements will be verified to
 * each other in order to see if they march, a match means that the private key
 * selected is the key pair to the one stored in the certificate
 */
package cinvestav.pki.android.trustednetwork.selection;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Parcelable;
import android.support.v4.app.DialogFragment;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentStatePagerAdapter;
import android.support.v4.app.NavUtils;
import android.support.v4.app.TaskStackBuilder;
import android.support.v4.view.ViewPager;
import android.util.Log;
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
import cinvestav.android.pki.cryptography.utils.X509Utils;
import cinvestav.android.pki.db.controller.CertificateController;
import cinvestav.android.pki.db.controller.PersonalKeyController;
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.android.pki.db.dao.PersonalKeyDAO;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.add.SignCertificateActivity;
import cinvestav.pki.android.trustednetwork.common.MyPasswordDialogFragment;
import cinvestav.pki.android.trustednetwork.common.MyPasswordDialogFragment.OnPositiveButtonClickListener;
import cinvestav.pki.android.trustednetwork.common.MyPasswordPKCSDialogFragment;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

import com.actionbarsherlock.app.ActionBar;
import com.actionbarsherlock.app.SherlockFragmentActivity;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuItem;
import com.actionbarsherlock.view.Window;

/**
 * This activity contains a ViewPager with two pages, one for certificates list
 * and the other for key list, so the user could select the corresponding
 * certificate and private key, at the end both elements will be verified to
 * each other in order to see if they match, a match means that the private key
 * selected is the key pair to the one stored in the certificate
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 03/10/2012
 * @version 1.0
 */
public class SelectCAElementsActivity extends SherlockFragmentActivity {

	/**
	 * The {@link android.support.v4.view.PagerAdapter} that will provide
	 * fragments representing each object in a collection. We use a
	 * {@link android.support.v4.app.FragmentStatePagerAdapter} derivative,
	 * which will destroy and re-create fragments as needed, saving and
	 * restoring their state in the process. This is important to conserve
	 * memory and is a best practice when allowing navigation between objects in
	 * a potentially large collection.
	 */
	SelectCAElementsCollectionPagerAdapter mCollectionPagerAdapter;

	/**
	 * The {@link android.support.v4.view.ViewPager} that will display the
	 * object collection.
	 */
	ViewPager mViewPager;

	private X509Utils _X509Utils;
	private AsymmetricCryptoUtils asymmetricCryptoUtils;

	static final int MENU_NEXT = 0;

	static PersonalKeyController personalKeyController;
	static CertificateController certificateController;

	private int current_option;

	/**
	 * Owner of the key
	 */
	Integer subjectId;

	/**
	 * CA PrivateKey Password
	 */
	private String caPrivateKeyPassword;

	/**
	 * CA PrivateKey Password PKCS
	 */
	private String caPrivateKeyPasswordPKCS;

	VerifyCertificateECKeyTask verifyCertificateECKeyTask;
	VerifyCertificateRSAKeyTask verifyCertificateRSAKeyTask;

	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		if (personalKeyController == null) {
			personalKeyController = new PersonalKeyController(
					getApplicationContext());
		}
		if (certificateController == null) {
			certificateController = new CertificateController(
					getApplicationContext());
		}

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
		actionBar.setSubtitle(R.string.subtitle_cert_ca_elements);

		// Create an adapter that when requested, will return a fragment
		// representing an object in
		// the collection.
		//
		// ViewPager and its adapters use support library fragments, so we must
		// use
		// getSupportFragmentManager.
		mCollectionPagerAdapter = new SelectCAElementsCollectionPagerAdapter(
				getSupportFragmentManager());

		// Set up the ViewPager, attaching the adapter.
		mViewPager = (ViewPager) findViewById(R.id.pager);
		mViewPager.setAdapter(mCollectionPagerAdapter);

		asymmetricCryptoUtils = new AsymmetricCryptoUtils();
		try {
			_X509Utils = new X509Utils();
		} catch (CryptoUtilsException e) {
			e.printStackTrace();
		}

		// Get Selected subject ID
		subjectId = getIntent().getIntExtra(
				SelectCAHolderActivity.EXTRA_SELECTED_CA_ID, 0);

		current_option = this.getIntent().getExtras()
				.getInt(PKITrustNetworkActivity.CURRENT_OPTION);

	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Place an action bar item for "next" menu option.
		MenuItem itemAdd_key = menu.add(0, MENU_NEXT, 0, R.string.menu_next);
		itemAdd_key.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

		return super.onCreateOptionsMenu(menu);
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		switch (item.getItemId()) {
		case android.R.id.home:
			returnHome();
			return true;
		case MENU_NEXT:
			verifySelectedElements();
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}

	/**
	 * This is called to return home in the application navigation scheme
	 */
	private void returnHome() {

		if (verifyCertificateECKeyTask != null) {
			verifyCertificateECKeyTask.cancel(true);
		}
		if (verifyCertificateRSAKeyTask != null) {
			verifyCertificateRSAKeyTask.cancel(true);
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
	 * Verify that the selected private key and certificate match, means that
	 * the private key corresponds to the public key stored into the
	 * certificate, to do so its necessary to decode the private key (using a
	 * password inserted by the user into a prompted dialog) and verify the
	 * certificate using the decoded key
	 */
	private void verifySelectedElements() {
		// Verify that a private key is selected

		int selectedCAKey = mCollectionPagerAdapter.getFragmentKey()
				.getSelectedKeyId();
		if (selectedCAKey == 0) {
			Toast.makeText(this, R.string.error_empty_key, Toast.LENGTH_SHORT)
					.show();
			return;
		}

		int selectedCACert = mCollectionPagerAdapter.getFragmentCertificate()
				.getSelectedCertificateId();
		if (selectedCACert == 0) {
			Toast.makeText(this, R.string.error_empty_cert, Toast.LENGTH_SHORT)
					.show();
			return;
		}

		// If both elements are selected decode the key prompting a dialog box
		// for its password
		PersonalKeyDAO caKey = mCollectionPagerAdapter.getFragmentKey()
				.getSelectedKey();

		Integer keyType = caKey.getKeyType();

		// Determine the key type and decode it
		if (keyType.equals(PersonalKeyDAO.PRIVATE_RSA)) {
			// If is a RSAPrivateKey ask for the password
			DialogFragment newFragment = MyPasswordDialogFragment.newInstance(
					R.string.alert_dialog_key_update_private_title, caKey,
					new OnPositiveButtonClickListenerVerifyCACertificateImp());
			newFragment.show(getSupportFragmentManager(), "password");
		} else if (keyType.equals(PersonalKeyDAO.PKCS12_RSA)) {
			// If is a PKCS_RSA file, ask for the password
			DialogFragment newFragment = MyPasswordPKCSDialogFragment
					.newInstance(
							R.string.alert_dialog_key_update_private_title,
							caKey,
							new OnPositiveButtonClickListenerVerifyCACertificateImp());
			newFragment.show(getSupportFragmentManager(), "password");
		} else if (keyType.equals(PersonalKeyDAO.PRIVATE_EC)) {
			// If is a ECPrivateKey ask for the password
			DialogFragment newFragment = MyPasswordDialogFragment.newInstance(
					R.string.alert_dialog_key_update_private_title, caKey,
					new OnPositiveButtonClickListenerVerifyCACertificateImp());
			newFragment.show(getSupportFragmentManager(), "password");
		} else if (keyType.equals(PersonalKeyDAO.PKCS12_EC)) {
			// If is a PKCS_RC file, ask for the password
			DialogFragment newFragment = MyPasswordPKCSDialogFragment
					.newInstance(
							R.string.alert_dialog_key_update_private_title,
							caKey,
							new OnPositiveButtonClickListenerVerifyCACertificateImp());
			newFragment.show(getSupportFragmentManager(), "password");
		}
	}

	protected void verifySelectedElements(ECPrivateKey caPrivateKey) {
		CertificateDAO selectedCert = mCollectionPagerAdapter
				.getFragmentCertificate().getSelectedCertificate();

		if (verifyCertificateECKeyTask == null
				|| !verifyCertificateECKeyTask.getStatus().equals(
						AsyncTask.Status.RUNNING)) {
			verifyCertificateECKeyTask = new VerifyCertificateECKeyTask();
			verifyCertificateECKeyTask.execute(selectedCert, caPrivateKey);

		} else {
			Toast.makeText(this, R.string.msgWorking, Toast.LENGTH_SHORT)
					.show();
		}
	}

	protected void verifySelectedElements(RSAPrivateKey caPrivateKey) {
		CertificateDAO selectedCert = mCollectionPagerAdapter
				.getFragmentCertificate().getSelectedCertificate();

		if (verifyCertificateRSAKeyTask == null
				|| !verifyCertificateRSAKeyTask.getStatus().equals(
						AsyncTask.Status.RUNNING)) {
			verifyCertificateRSAKeyTask = new VerifyCertificateRSAKeyTask();
			verifyCertificateRSAKeyTask.execute(selectedCert, caPrivateKey);

		} else {
			Toast.makeText(this, R.string.msgWorking, Toast.LENGTH_SHORT)
					.show();
		}
	}

	/**
	 * A {@link android.support.v4.app.FragmentStatePagerAdapter} that returns a
	 * fragment pager that will contains two pages,one for certificates list and
	 * the other for key list
	 */
	public class SelectCAElementsCollectionPagerAdapter extends
			FragmentStatePagerAdapter {

		SelectKeyFragment fragmentKey;
		SelectCertificateFragment fragmentCertificate;
		private final FragmentManager mFragmentManager;

		private static final int KEY_PAGE = 0;
		private static final int CERT_PAGE = 1;

		public SelectCAElementsCollectionPagerAdapter(FragmentManager fm) {
			super(fm);
			mFragmentManager = fm;
		}

		/**
		 * @return the fragmentCertificateInformation
		 */
		public SelectKeyFragment getFragmentKey() {
			return fragmentKey;
		}

		/**
		 * @return the certificate list fragment
		 */
		public SelectCertificateFragment getFragmentCertificate() {
			return fragmentCertificate;
		}

		@Override
		public Fragment getItem(int i) {
			Log.i(PKITrustNetworkActivity.TAG, "GET ITEM " + i);
			// Chose between the two availably: Owner or key
			switch (i) {
			case KEY_PAGE:
				Log.i(PKITrustNetworkActivity.TAG, "NEW KEY");
				if (fragmentKey == null) {
					fragmentKey = SelectKeyFragment.newInstance(
							personalKeyController, subjectId);
				}
				return fragmentKey;

			case CERT_PAGE:
				Log.i(PKITrustNetworkActivity.TAG, "NEW CERT");
				if (fragmentCertificate == null) {
					fragmentCertificate = SelectCertificateFragment
							.newInstance(certificateController, subjectId);
				}
				return fragmentCertificate;

			}

			return new SelectKeyFragment();
		}

		@Override
		public int getCount() {
			// Total of pages
			return 2;
		}

		@Override
		public CharSequence getPageTitle(int position) {
			switch (position) {
			case KEY_PAGE:
				return getResources().getString(
						R.string.detail_title_private_key);
			case CERT_PAGE:
				return getResources().getString(
						R.string.detail_title_certificate);
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
						if (f instanceof SelectKeyFragment) {
							fragmentKey = (SelectKeyFragment) f;
						} else if (f instanceof SelectCertificateFragment) {
							fragmentCertificate = (SelectCertificateFragment) f;
						}

					}
				}
			}

		}

	}

	/**
	 * Implements the OnPositiveButtonClickListener for CA private key and
	 * certificate verification
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 14/09/2012
	 * @version 1.0
	 */
	public class OnPositiveButtonClickListenerVerifyCACertificateImp implements
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

					SelectCAElementsActivity.this.caPrivateKeyPassword = passwordKey;
					verifySelectedElements(privKey);

				} else {
					// If the key is a Private RSA key

					RSAPrivateKey privKey = RSAPrivateKey.decode(key
							.getKeyStr().getBytes(), passwordKey);
					SelectCAElementsActivity.this.caPrivateKeyPassword = passwordKey;
					verifySelectedElements(privKey);

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
					ECKeyPair keyPair = (ECKeyPair) decodedECKeyPair[0];
					SelectCAElementsActivity.this.caPrivateKeyPassword = passwordKey;
					SelectCAElementsActivity.this.caPrivateKeyPasswordPKCS = passwordPKCS;
					verifySelectedElements(keyPair.getPrivateKey());

				} else {
					// If the key is a PKCS RSA key
					Object[] decodedRSAKeyPair = RSAKeyPair.decodePKCS12(key
							.getKeyStr().getBytes(), passwordPKCS, passwordKey);

					RSAKeyPair keyPair = (RSAKeyPair) decodedRSAKeyPair[0];

					SelectCAElementsActivity.this.caPrivateKeyPassword = passwordKey;
					SelectCAElementsActivity.this.caPrivateKeyPasswordPKCS = passwordPKCS;
					verifySelectedElements(keyPair.getPrivateKey());
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
	 * Inner class that create an asynchronous task which checks if a EC private
	 * key correspond to a public key stored into a X509Certificate, in order to
	 * do this a random message will be signed with the selected private key and
	 * then the certificates public key will be used for verify the signature
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class VerifyCertificateECKeyTask extends
			AsyncTask<Object, Void, Boolean> {

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
			try {
				X509Certificate cert = _X509Utils
						.decode(((CertificateDAO) params[0])
								.getCertificateStr().getBytes());

				ECPrivateKey privKey = ((ECPrivateKey) params[1]);

				ECPublicKey publicKey = ECPublicKey.parse(cert.getPublicKey());

				byte[] testBytes = new byte[256];
				CryptoUtils.secureRandom.nextBytes(testBytes);

				BigInteger[] sign = asymmetricCryptoUtils.sign(testBytes,
						privKey);

				return asymmetricCryptoUtils.verify(testBytes, sign, publicKey);
			} catch (CryptoUtilsException e) {
				e.printStackTrace();
			}
			return Boolean.FALSE;

		}

		@Override
		protected void onPostExecute(Boolean res) {
			if (res) {
				Intent intent = new Intent(getApplicationContext(),
						SignCertificateActivity.class);

				intent.putExtra(
						SignCertificateActivity.EXTRA_CERTIFICATE_ID,
						getIntent()
								.getIntExtra(
										SignCertificateActivity.EXTRA_CERTIFICATE_ID,
										0));
				intent.putExtra(
						SignCertificateActivity.EXTRA_CA_CERTIFICATE_ID,
						mCollectionPagerAdapter.getFragmentCertificate()
								.getSelectedCertificateId());
				intent.putExtra(
						SignCertificateActivity.EXTRA_CA_PRIVATE_KEY_ID,
						mCollectionPagerAdapter.getFragmentKey()
								.getSelectedKeyId());

				intent.putExtra(
						SignCertificateActivity.EXTRA_CA_PRIVATE_KEY_PASSWORD,
						caPrivateKeyPassword);
				intent.putExtra(
						SignCertificateActivity.EXTRA_CA_PRIVATE_KEY_PASSWORD_PKCS,
						caPrivateKeyPasswordPKCS);

				startActivity(intent);

			} else {
				Toast.makeText(getApplicationContext(),
						R.string.error_cert_parameters_match, Toast.LENGTH_LONG)
						.show();
			}
			// Disable the indeterminate progress icon on the action bar
			setSupportProgressBarIndeterminateVisibility(false);
		}
	}

	/**
	 * Inner class that create an asynchronous task which checks if a RSA
	 * private key correspond to a public key stored into a X509Certificate, in
	 * order to do this a random message will be signed with the selected
	 * private key and then the certificates public key will be used for verify
	 * the signature
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class VerifyCertificateRSAKeyTask extends
			AsyncTask<Object, Void, Boolean> {

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
			try {
				X509Certificate cert = _X509Utils
						.decode(((CertificateDAO) params[0])
								.getCertificateStr().getBytes());

				RSAPrivateKey privKey = ((RSAPrivateKey) params[1]);
				RSAPublicKey publicKey = RSAPublicKey
						.parse(cert.getPublicKey());

				byte[] testBytes = new byte[256];
				CryptoUtils.secureRandom.nextBytes(testBytes);

				byte[] sign = asymmetricCryptoUtils.sign(testBytes, privKey);

				return asymmetricCryptoUtils.verify(testBytes, sign, publicKey);
			} catch (CryptoUtilsException e) {
				e.printStackTrace();
			}
			return Boolean.FALSE;

		}

		@Override
		protected void onPostExecute(Boolean res) {
			if (res) {
				Intent intent = new Intent(getApplicationContext(),
						SignCertificateActivity.class);

				intent.putExtra(
						SignCertificateActivity.EXTRA_CERTIFICATE_ID,
						getIntent()
								.getIntExtra(
										SignCertificateActivity.EXTRA_CERTIFICATE_ID,
										0));
				intent.putExtra(
						SignCertificateActivity.EXTRA_CA_CERTIFICATE_ID,
						mCollectionPagerAdapter.getFragmentCertificate()
								.getSelectedCertificateId());
				intent.putExtra(
						SignCertificateActivity.EXTRA_CA_PRIVATE_KEY_ID,
						mCollectionPagerAdapter.getFragmentKey()
								.getSelectedKeyId());

				intent.putExtra(
						SignCertificateActivity.EXTRA_CA_PRIVATE_KEY_PASSWORD,
						caPrivateKeyPassword);
				intent.putExtra(
						SignCertificateActivity.EXTRA_CA_PRIVATE_KEY_PASSWORD_PKCS,
						caPrivateKeyPasswordPKCS);

				startActivity(intent);
			} else {
				Toast.makeText(getApplicationContext(),
						R.string.error_cert_parameters_match, Toast.LENGTH_LONG)
						.show();
			}
			// Disable the indeterminate progress icon on the action bar
			setSupportProgressBarIndeterminateVisibility(false);
		}
	}

}
