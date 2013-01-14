/**
 *  Created on  : 04/10/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Fragment Activity for editing the certificate to be signed by a CA
 */
package cinvestav.pki.android.trustednetwork.add;

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map.Entry;

import org.spongycastle.util.encoders.Base64;

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
import android.text.format.DateFormat;
import android.util.Log;
import android.util.SparseArray;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import cinvestav.android.pki.cryptography.cert.CertificateInformationKeys;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsX509ExtensionException;
import cinvestav.android.pki.cryptography.key.ECKeyPair;
import cinvestav.android.pki.cryptography.key.ECPrivateKey;
import cinvestav.android.pki.cryptography.key.ECPublicKey;
import cinvestav.android.pki.cryptography.key.RSAKeyPair;
import cinvestav.android.pki.cryptography.key.RSAPrivateKey;
import cinvestav.android.pki.cryptography.key.RSAPublicKey;
import cinvestav.android.pki.cryptography.utils.X509Utils;
import cinvestav.android.pki.cryptography.utils.X509UtilsDictionary;
import cinvestav.android.pki.db.controller.CertificateController;
import cinvestav.android.pki.db.controller.PersonalKeyController;
import cinvestav.android.pki.db.controller.SubjectController;
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.android.pki.db.dao.PersonalKeyDAO;
import cinvestav.android.pki.db.dao.SubjectDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.details.CertificateDetailsActivity;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

import com.actionbarsherlock.app.ActionBar;
import com.actionbarsherlock.app.SherlockFragmentActivity;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuItem;
import com.actionbarsherlock.view.Window;

/**
 * Fragment Activity for editing the certificate to be signed by a CA
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 04/10/2012
 * @version 1.0
 */
public class SignCertificateActivity extends SherlockFragmentActivity {

	public static final String EXTRA_CERTIFICATE_ID = "EXTRA_SELECTED_CERTIFICATE_ID";
	public static final String EXTRA_CA_CERTIFICATE_ID = "EXTRA_CA_CERTIFICATE_ID";
	public static final String EXTRA_CA_PRIVATE_KEY_ID = "EXTRA_CA_PRIVATE_KEY_ID";
	public static final String EXTRA_CA_PRIVATE_KEY_PASSWORD = "EXTRA_CA_PRIVATE_KEY_PASSWORD";
	public static final String EXTRA_CA_PRIVATE_KEY_PASSWORD_PKCS = "EXTRA_CA_PRIVATE_KEY_PASSWORD_PKCS";

	/**
	 * The {@link android.support.v4.view.PagerAdapter} that will provide
	 * fragments representing each object in a collection. We use a
	 * {@link android.support.v4.app.FragmentStatePagerAdapter} derivative,
	 * which will destroy and re-create fragments as needed, saving and
	 * restoring their state in the process. This is important to conserve
	 * memory and is a best practice when allowing navigation between objects in
	 * a potentially large collection.
	 */
	private SignCertificateCollectionPagerAdapter mCollectionPagerAdapter;

	/**
	 * The {@link android.support.v4.view.ViewPager} that will display the
	 * object collection.
	 */
	private ViewPager mViewPager;
	private X509Utils _X509Utils;

	private static final int MENU_SIGN = 0;
	private static final int MENU_CANCEL = 1;

	/**
	 * selected certificate id
	 */
	private Integer certificateId;

	/**
	 * Holder of the selected certificate
	 */
	private SubjectDAO holder;

	/**
	 * Decoded selected certificate
	 */
	private X509Certificate x509Certificate;

	/**
	 * CA Certificate id
	 */
	private Integer caCertificateId;

	/**
	 * CA Private Key
	 */
	private Integer caPrivateKeyId;

	/**
	 * CA PrivateKey Password
	 */
	private String caPrivateKeyPassword;

	/**
	 * CA PrivateKey Password PKCS
	 */
	private String caPrivateKeyPasswordPKCS;

	/**
	 * Personal key corresponding to the selected CA Private Key
	 */
	private PersonalKeyDAO caKey;

	private FragmentActivity certificateAuxActivity;

	/**
	 * Not after validity certificate date
	 */
	private Date notAfter;

	/**
	 * Not before validity certificate date
	 */
	private Date notBefore;

	/**
	 * Map filled out with the certificate information using the Field key (
	 * {@link cinvestav.android.pki.cryptography.cert.CertificateInformationKeys}
	 * Supported Keys) and the field value
	 */
	private HashMap<String, String> certificateInformationMap;

	/**
	 * Key usage list
	 */
	private List<Integer> keyUsageList;

	private java.text.DateFormat df;

	PersonalKeyController personalKeyController;
	SubjectController subjectController;
	CertificateController certificateController;

	SignPublicKeyCertificateTask signPublicKeyCertificateTask;

	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		df = DateFormat.getDateFormat(getApplicationContext());

		personalKeyController = new PersonalKeyController(
				getApplicationContext());
		subjectController = new SubjectController(getApplicationContext());
		certificateController = new CertificateController(
				getApplicationContext());

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
		actionBar.setSubtitle(R.string.subtitle_cert_add);

		// Create an adapter that when requested, will return a fragment
		// representing an object in
		// the collection.
		//
		// ViewPager and its adapters use support library fragments, so we must
		// use
		// getSupportFragmentManager.
		mCollectionPagerAdapter = new SignCertificateCollectionPagerAdapter(
				getSupportFragmentManager());

		// Set up the ViewPager, attaching the adapter.
		mViewPager = (ViewPager) findViewById(R.id.pager);
		mViewPager.setAdapter(mCollectionPagerAdapter);

		try {
			_X509Utils = new X509Utils();
		} catch (CryptoUtilsException e) {
			e.printStackTrace();
		}

		// Get Selected certificate ID
		certificateId = getIntent().getIntExtra(EXTRA_CERTIFICATE_ID, 0);

		// Get Selected CA certificate ID
		caCertificateId = getIntent().getIntExtra(EXTRA_CA_CERTIFICATE_ID, 0);

		// Get Selected CA PrivateKey ID
		caPrivateKeyId = getIntent().getIntExtra(EXTRA_CA_PRIVATE_KEY_ID, 0);

		// Get Selected CA PrivateKey Password
		caPrivateKeyPassword = getIntent().getStringExtra(
				EXTRA_CA_PRIVATE_KEY_PASSWORD);

		// Get Selected CA PrivateKey Password for PKCS file
		caPrivateKeyPasswordPKCS = getIntent().getStringExtra(
				EXTRA_CA_PRIVATE_KEY_PASSWORD_PKCS);

		Boolean missingParameter = certificateId == 0 & caCertificateId == 0
				& caPrivateKeyId == 0;

		// Check if all the necessary parameters are present
		if (missingParameter) {
			Toast.makeText(getApplicationContext(),
					R.string.error_cert_sign_parameters, Toast.LENGTH_LONG)
					.show();
			returnHome();
		}

		try {
			// Load CA Private Key from data base
			caKey = personalKeyController.getById(caPrivateKeyId);
			CertificateDAO certificate = certificateController
					.getById(certificateId);
			certificateController.getCertificateDetails(certificate);
			holder = certificate.getOwner();

			x509Certificate = _X509Utils.decode(certificate.getCertificateStr()
					.getBytes());

			notAfter = x509Certificate.getNotAfter();
			notBefore = x509Certificate.getNotBefore();

			keyUsageList = _X509Utils.getKeyUsageList(x509Certificate);
			certificateInformationMap = _X509Utils
					.getCertificateInformationMap(x509Certificate);

		} catch (DBException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
			e.printStackTrace();
			Toast.makeText(this, R.string.error_db_load_key, Toast.LENGTH_LONG)
					.show();
			returnHome();
		} catch (CryptoUtilsException e) {
			Toast.makeText(this, R.string.error_cert_decode, Toast.LENGTH_LONG)
					.show();
			returnHome();
		}

		mViewPager
				.setCurrentItem(SignCertificateCollectionPagerAdapter.CERT_PAGE);
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Place an action bar item for sign the certificate.
		MenuItem itemAdd_key = menu.add(0, MENU_SIGN, 0, R.string.menu_sign);
		itemAdd_key.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

		// Place an action bar item for cancel the signing of the certificate.
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
		case MENU_SIGN:
			signCertificate();
			return true;
		case MENU_CANCEL:
			returnHome();
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.actionbarsherlock.app.SherlockFragmentActivity#onDestroy()
	 */
	@Override
	protected void onDestroy() {
		super.onDestroy();
	}

	/**
	 * This is called to return home in the application navigation scheme
	 */
	private void returnHome() {

		if (signPublicKeyCertificateTask != null) {
			signPublicKeyCertificateTask.cancel(true);
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

	/**
	 * A {@link android.support.v4.app.FragmentStatePagerAdapter} that returns a
	 * fragment pager that will contains two pages, one for certificate basic
	 * information and the other for owner referent information.
	 */
	private class SignCertificateCollectionPagerAdapter extends
			FragmentStatePagerAdapter {

		AddNewCertificateInformationFragment fragmentCertificateInformation;
		AddNewCertificateHolderFragment fragmentHolder;
		AddNewCertificateCustomInformationFragment fragmentCertificateCustomInformation;
		private final FragmentManager mFragmentManager;

		private static final int CUSTOM_PAGE = 0;
		private static final int CERT_PAGE = 1;
		private static final int HOLDER_PAGE = 2;

		public SignCertificateCollectionPagerAdapter(FragmentManager fm) {
			super(fm);
			mFragmentManager = fm;
		}

		/**
		 * @return the fragmentCertificateInformation
		 */
		public AddNewCertificateInformationFragment getFragmentCertificateInformation() {
			return fragmentCertificateInformation;
		}

		/**
		 * @return the fragmentHolder
		 */
		public AddNewCertificateHolderFragment getFragmentHolder() {
			return fragmentHolder;
		}

		/**
		 * @return the fragmentCertificateCustomInformation
		 */
		public AddNewCertificateCustomInformationFragment getFragmentCertificateCustomInformation() {
			return fragmentCertificateCustomInformation;
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
						if (f instanceof AddNewCertificateInformationFragment) {
							fragmentCertificateInformation = (AddNewCertificateInformationFragment) f;
						} else if (f instanceof AddNewCertificateHolderFragment) {
							fragmentHolder = (AddNewCertificateHolderFragment) f;
						} else if (f instanceof AddNewCertificateCustomInformationFragment) {
							fragmentCertificateCustomInformation = (AddNewCertificateCustomInformationFragment) f;
						}
					}
				}
			}
		}

		@Override
		public Fragment getItem(int i) {
			// Chose between the two availably: Owner or key
			switch (i) {
			case CERT_PAGE:
				if (fragmentCertificateInformation == null) {
					fragmentCertificateInformation = AddNewCertificateInformationFragment
							.newInstance(caKey.getKeyType(), notAfter,
									notBefore, keyUsageList);
				}
				return fragmentCertificateInformation;

			case HOLDER_PAGE:
				if (fragmentHolder == null) {
					fragmentHolder = AddNewCertificateHolderFragment
							.newInstance(certificateInformationMap);
				}
				return fragmentHolder;
			case CUSTOM_PAGE:
				if (fragmentCertificateCustomInformation == null) {
					fragmentCertificateCustomInformation = AddNewCertificateCustomInformationFragment
							.newInstance(
									_X509Utils
											.getExtensionUserId(x509Certificate),
									_X509Utils
											.getExtensionUserPermissionId(x509Certificate),
									_X509Utils
											.getExtensionIdentificationDocument(x509Certificate));
				}
				return fragmentCertificateCustomInformation;
			}

			return new AddNewCertificateInformationFragment();
		}

		@Override
		public int getCount() {
			// Get the count of personal Keys
			return 3;
		}

		@Override
		public CharSequence getPageTitle(int position) {
			switch (position) {
			case CERT_PAGE:
				return getResources().getString(
						R.string.detail_title_certificate);
			case HOLDER_PAGE:
				return getResources().getString(R.string.detail_title_holder);
			case CUSTOM_PAGE:
				return getResources().getString(
						R.string.detail_title_extension_specific);
			default:
				return "";
			}

		}
	}

	/**
	 * This is called when the user selects the create button, here is were the
	 * certificate is created and inserted into the data base
	 */
	private void signCertificate() {

		// Check if the signing task is null and if its not running
		if (signPublicKeyCertificateTask == null
				|| !signPublicKeyCertificateTask.getStatus().equals(
						AsyncTask.Status.RUNNING)) {
			// If the sign task is null and is not running, validate the
			// necessary fields and init the task

			Calendar date = Calendar.getInstance();
			date.setTime(new Date());

			// Get the activity of the certificate information fragment
			certificateAuxActivity = mCollectionPagerAdapter
					.getFragmentCertificateInformation().getActivity();

			// Get the dates fields and check if are valid (not before todays
			// date)
			try {
				notAfter = df.parse(((TextView) certificateAuxActivity
						.findViewById(R.id.txtCertificateValidityNotAfter))
						.getText().toString());

				notBefore = df.parse(((TextView) certificateAuxActivity
						.findViewById(R.id.txtCertificateValidityNotBefore))
						.getText().toString());

				// Check if the notAfter date is before todays' date
				if (notAfter.before(date.getTime())) {
					Toast.makeText(this, R.string.error_cert_not_after,
							Toast.LENGTH_LONG).show();
					return;
				}

				// Check if the notAfter date is before notBefore date
				if (notAfter.before(notBefore)) {
					Toast.makeText(this, R.string.error_cert_not_after_before,
							Toast.LENGTH_LONG).show();
					return;
				}
			} catch (ParseException e) {
				Toast.makeText(this, R.string.error_cert_date_format,
						Toast.LENGTH_LONG).show();
				return;
			} catch (NullPointerException e) {
				Toast.makeText(this, R.string.error_cert_date_format,
						Toast.LENGTH_LONG).show();
				return;
			}

			// Get all the key usage CheckBox values
			SparseArray<Boolean> keyUsageValues = new SparseArray<Boolean>();

			keyUsageValues.put(
					X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE,
					((CheckBox) certificateAuxActivity
							.findViewById(R.id.chkKeyUsageDigitalSignature))
							.isChecked());
			keyUsageValues.put(
					X509UtilsDictionary.X509_KEYUSAGE_NONREPUDIATION,
					((CheckBox) certificateAuxActivity
							.findViewById(R.id.chkKeyUsageNonRepudiation))
							.isChecked());
			keyUsageValues.put(
					X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT,
					((CheckBox) certificateAuxActivity
							.findViewById(R.id.chkKeyUsageKeyCipher))
							.isChecked());
			keyUsageValues.put(
					X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT,
					((CheckBox) certificateAuxActivity
							.findViewById(R.id.chkKeyUsageDataCipher))
							.isChecked());
			keyUsageValues.put(X509UtilsDictionary.X509_KEYUSAGE_KEY_AGREEMENT,
					((CheckBox) certificateAuxActivity
							.findViewById(R.id.chkKeyUsageKeyAgreement))
							.isChecked());
			keyUsageValues.put(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN,
					((CheckBox) certificateAuxActivity
							.findViewById(R.id.chkKeyUsageKeyCertSign))
							.isChecked());
			keyUsageValues
					.put(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN,
							((CheckBox) certificateAuxActivity
									.findViewById(R.id.chkKeyUsageCRLSign))
									.isChecked());
			keyUsageValues.put(X509UtilsDictionary.X509_KEYUSAGE_ENCIPHER_ONLY,
					((CheckBox) certificateAuxActivity
							.findViewById(R.id.chkKeyUsageEncipherOnly))
							.isChecked());
			keyUsageValues.put(X509UtilsDictionary.X509_KEYUSAGE_DECIPHER_ONLY,
					((CheckBox) certificateAuxActivity
							.findViewById(R.id.chkKeyUsageDecipherOnly))
							.isChecked());

			// Create the key usageList adding the selected key usages
			keyUsageList = new LinkedList<Integer>();
			int key = 0;
			int keyUsageSize = keyUsageValues.size();
			for (int i = 0; i < keyUsageSize; i++) {
				key = keyUsageValues.keyAt(i);
				Boolean keyUsageSelected = keyUsageValues.valueAt(i);
				if (keyUsageSelected) {
					keyUsageList.add(key);
				}
			}

			// Check that keyUsage List is not empty
			if (keyUsageList.size() <= 0) {
				Toast.makeText(this, R.string.error_cert_empty_key_usage,
						Toast.LENGTH_LONG).show();
				return;
			}

			// Get the activity of the holder information fragment

			/*
			 * LinearLayout layout = (LinearLayout) holderAuxActivity
			 * .findViewById(R.id.layoutHolderFields); int childCount =
			 * layout.getChildCount(); // Check that keyUsage List is not empty
			 * if (childCount < 8) { Toast.makeText(this,
			 * R.string.error_cert_holder_fields_count,
			 * Toast.LENGTH_LONG).show(); return; }
			 */

			// Create the certificateInformationMap for the certificate, using
			// the
			// added holder fields
			certificateInformationMap = new HashMap<String, String>();
			HashMap<String, EditText> certificateInformationMapFragment = mCollectionPagerAdapter
					.getFragmentHolder().getCertificateInformationMap();
			Iterator<Entry<String, EditText>> i = certificateInformationMapFragment
					.entrySet().iterator();
			while (i.hasNext()) {
				Entry<String, EditText> entry = i.next();

				String fieldValue = entry.getValue().getText().toString();
				if (!fieldValue.isEmpty()) {
					// Add the inserted value to the certicateInformationMap,
					// the
					// key for the entry is gotten
					// using the KEY_CODE_LOOK_UP and the label of the field as
					// key
					// for this map
					certificateInformationMap.put(
							CertificateInformationKeys.KEY_CODE_LOOK_UP
									.get(entry.getKey().toLowerCase()),
							fieldValue);
				}
			}

			Log.i(PKITrustNetworkActivity.TAG, "certificateInformationMap: "
					+ certificateInformationMap);

			if (certificateInformationMap.size() < 4) {
				Toast.makeText(this,
						R.string.error_cert_holder_fields_not_empty,
						Toast.LENGTH_LONG).show();
				return;
			}

			// Add custom extensions to the certificateInformationMap

			// Creation Device Id
			certificateInformationMap.put(CertificateInformationKeys.DEVICE_ID,
					_X509Utils.getExtensionDeviceId(x509Certificate));

			// Sign Device Id
			certificateInformationMap.put(
					CertificateInformationKeys.SIGN_DEVICE_ID,
					PKITrustNetworkActivity.ANDROID_ID);

			// Set the creation location GPS Position
			certificateInformationMap
					.put(CertificateInformationKeys.CREATION_POSITION_LATITUDE,
							_X509Utils
									.getExtensionCreationPositionLatitude(x509Certificate));
			certificateInformationMap
					.put(CertificateInformationKeys.CREATION_POSITION_LONGITUDE,
							_X509Utils
									.getExtensionCreationPositionLongitude(x509Certificate));

			Log.i(PKITrustNetworkActivity.TAG,
					"CUSTOM: "
							+ mCollectionPagerAdapter
									.getFragmentCertificateCustomInformation());
			String txtCertificateUserId = mCollectionPagerAdapter
					.getFragmentCertificateCustomInformation()
					.getTxtCertificateUserId().getText().toString();
			String txtCertificateUserPermission = mCollectionPagerAdapter
					.getFragmentCertificateCustomInformation()
					.getTxtCertificateUserPermission().getText().toString();
			String txtCertificateIdentificationDocument = mCollectionPagerAdapter
					.getFragmentCertificateCustomInformation()
					.getTxtCertificateIdentificationDocument().getText()
					.toString();

			if (!txtCertificateUserId.isEmpty()) {
				// User id - if a value was inserted
				certificateInformationMap.put(
						CertificateInformationKeys.USER_ID,
						txtCertificateUserId);
			}

			if (!txtCertificateUserPermission.isEmpty()) {
				// User permission id - if a value was inserted
				certificateInformationMap.put(
						CertificateInformationKeys.USER_PERMISSION_ID,
						txtCertificateUserPermission);
			}

			if (!txtCertificateIdentificationDocument.isEmpty()) {
				// identification document - if a value was inserted
				certificateInformationMap.put(
						CertificateInformationKeys.IDENTIFICATION_DOCUMENT,
						txtCertificateIdentificationDocument);
			}

			// If every things its fine, create the task for sign the
			// certificate
			signPublicKeyCertificateTask = new SignPublicKeyCertificateTask();
			// In order to parse the certificates public key we must try both
			// ECPublicKey of RSAPublicKey because at this point we have not a
			// better way to do it
			try {
				// First try with ECPublic key parse, if returns an error, try
				// with RSAPublicKey parser
				ECPublicKey pubKey = ECPublicKey.parse(x509Certificate
						.getPublicKey());

				signPublicKeyCertificateTask.execute(pubKey);
			} catch (CryptoUtilsException e) {
				RSAPublicKey pubKey;
				try {
					pubKey = RSAPublicKey.parse(x509Certificate.getPublicKey());
					signPublicKeyCertificateTask.execute(pubKey);
				} catch (CryptoUtilsException e1) {
					// If the key could not be parsed neither by ECPublicKey nor
					// RSAPublicKey show an error message
					Toast.makeText(this, R.string.error_cert_key_decode,
							Toast.LENGTH_LONG).show();
				}

			}

		} else {
			// If the task is not null and its running make user aware of this
			Toast.makeText(this, R.string.msgWorking, Toast.LENGTH_LONG).show();
		}

	}

	/**
	 * Inner class that create an asynchronous task in which a signed X509
	 * certificate for an public key, is created using a CAs PrivateKey for
	 * signing it
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class SignPublicKeyCertificateTask extends
			AsyncTask<Object, Void, CertificateDAO> {

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
		protected CertificateDAO doInBackground(Object... params) {

			String spinnerSignAlgorithmName = ((String) mCollectionPagerAdapter
					.getFragmentCertificateInformation()
					.getSpinnerSignAlgorithmName().getSelectedItem()).replace(
					"(*)", "").trim();
			Integer spinnerCertificateType = mCollectionPagerAdapter
					.getFragmentCertificateInformation()
					.getSpinnerCertificateType().getSelectedItemPosition();

			String certType = "";
			// Select certificateType
			switch (spinnerCertificateType) {
			case 0:
				certType = X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA;
				break;
			case 1:
				certType = X509UtilsDictionary.CERTIFICATE_TYPE_INTERMEDIATE_CA;
				break;
			case 2:
				certType = X509UtilsDictionary.CERTIFICATE_TYPE_FINAL_CA;
				break;
			case 3:
				certType = X509UtilsDictionary.CERTIFICATE_TYPE_END_OWNER;
				break;
			default:
				break;
			}
			try {

				// Load the CAs' certificate from data base
				CertificateDAO caCertificate = certificateController
						.getById(caCertificateId);
				certificateController.getCertificateDetails(caCertificate);

				// Decode CA certificate
				X509Certificate x509CACertificate = _X509Utils
						.decode(caCertificate.getCertificateStr().getBytes());

				// Getting the serial number in base of the CA current
				// certificate serial number
				Integer currentSerialNumber = certificateController
						.getCurrentSerialNumberForCA(caCertificate.getOwner()
								.getId()) + 1;
				BigInteger serialNumber = new BigInteger(currentSerialNumber
						+ "");

				// Create the certificate
				X509Certificate newCertificate;
				if (params[0] instanceof ECPublicKey) {
					newCertificate = createCertificate((ECPublicKey) params[0],
							x509CACertificate, serialNumber, certType,
							spinnerSignAlgorithmName);
					// Once the certificate is created, add it to the data base
					return addToDataBase(currentSerialNumber, newCertificate,
							caCertificate);
				} else if (params[0] instanceof RSAPublicKey) {
					newCertificate = createCertificate(
							(RSAPublicKey) params[0], x509CACertificate,
							serialNumber, certType, spinnerSignAlgorithmName);
					// Once the certificate is created, add it to the data base
					return addToDataBase(currentSerialNumber, newCertificate,
							caCertificate);
				}

			} catch (CryptoUtilsException e) {
				e.printStackTrace();
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
			} catch (CryptoUtilsX509ExtensionException e) {
				e.printStackTrace();
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
			} catch (DBException e) {
				e.printStackTrace();
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
			} catch (CertificateEncodingException e) {
				e.printStackTrace();
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
			}
			return null;
		}

		@Override
		protected void onPostExecute(CertificateDAO res) {
			if (res != null) {
				Toast.makeText(getApplicationContext(),
						R.string.msgAddCertificateOK, Toast.LENGTH_LONG).show();

				Intent upIntent = new Intent(getApplicationContext(),
						CertificateDetailsActivity.class);
				upIntent.putExtra(CertificateDetailsActivity.EXTRA_OWNER_ID,
						holder.getId());
				upIntent.putExtra(
						CertificateDetailsActivity.EXTRA_CURRENT_CERTIFICATE_ID,
						certificateId);
				startActivity(upIntent);

			} else {
				Toast.makeText(getApplicationContext(),
						R.string.error_db_add_certificate, Toast.LENGTH_LONG)
						.show();
			}
			// Disable the indeterminate progress icon on the action bar
			setSupportProgressBarIndeterminateVisibility(false);
		}
	}

	/**
	 * 
	 * 
	 * @param currentSerialNumber
	 *            Serial Number of the certificate
	 * @param certificate
	 *            X509Certificate object to be inserted
	 * @return A inserted CertificateDAO object
	 * @throws CertificateEncodingException
	 *             When the certificate could not be encoded
	 * @throws DBException
	 *             If an error occurs during insertion
	 */
	/**
	 * Add the X509 certificate to the data base using the specified
	 * currentSerialNumber
	 * 
	 * @param currentSerialNumber
	 *            Serial Number of the certificate
	 * @param certificate
	 *            X509Certificate object to be inserted
	 * @param caCertificateDAO
	 *            CertificateDAO object of the signing CA
	 * @return A inserted CertificateDAO object
	 * @throws CertificateEncodingException
	 *             When the certificate could not be encoded
	 * @throws DBException
	 *             If an error occurs during insertion
	 */
	private CertificateDAO addToDataBase(Integer currentSerialNumber,
			X509Certificate certificate, CertificateDAO caCertificateDAO)
			throws CertificateEncodingException, DBException {
		// Get the holder information

		CertificateDAO certificateDAO = new CertificateDAO();

		// As this is a Self Signed certificate, the CA its the holder,
		// so the id should be set in advance or the CA id will be
		// empty
		certificateDAO.setId(certificateController.getCurrentId() + 1);
		// Set the holder of the certificate
		certificateDAO.setOwner(holder);
		// Set the serial number
		certificateDAO.setSerialNumber(currentSerialNumber);
		certificateDAO
				.setStatus(X509UtilsDictionary.X509_CERTIFICATE_STATUS_VALID);
		certificateDAO.setCaCertificate(caCertificateDAO);

		certificateDAO.setCertificateStr(new String(Base64.encode(certificate
				.getEncoded())));
		certificateDAO.setSignDeviceId(PKITrustNetworkActivity.ANDROID_ID);

		byte[] subKeyId = _X509Utils.getSubjectKeyIdentifier(certificate);

		certificateDAO.setSubjectKeyId(new String(Base64.encode(subKeyId)));
		Integer id = certificateController.insert(certificateDAO);
		certificateDAO.setId(id);
		return certificateDAO;
	}

	/**
	 * Creates a certificate for a EC Public key using the selected parameters
	 * 
	 * @param holderPublicKey
	 *            Public key to be certified by the CA
	 * @param x509CACertificate
	 *            CA certificate that will issue the certificate
	 * @param serialNumber
	 *            Serial number for the new certificate
	 * @param certType
	 *            Certificate Type
	 * @param spinnerSignAlgorithmName
	 *            Signature Algorithm to be used for sign the certificate
	 * @return A new X509Certificate signed by the CA using its corresponding
	 *         private key
	 * @throws CryptoUtilsException
	 * @throws CryptoUtilsX509ExtensionException
	 */
	private X509Certificate createCertificate(ECPublicKey holderPublicKey,
			X509Certificate x509CACertificate, BigInteger serialNumber,
			String certType, String spinnerSignAlgorithmName)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException {
		Integer keyType = caKey.getKeyType();
		// Determine the key type and decode it using the password saved in this
		// class
		if (keyType.equals(PersonalKeyDAO.PRIVATE_RSA)) {

			// Decode the key using the caPrivateKeyPassword
			RSAPrivateKey caPrivateKey = RSAPrivateKey.decode(caKey.getKeyStr()
					.getBytes(), caPrivateKeyPassword);

			// Create the certificate
			return _X509Utils.createV3Cert(holderPublicKey, caPrivateKey,
					serialNumber, notBefore, notAfter, x509CACertificate,
					certificateInformationMap, keyUsageList, certType,
					spinnerSignAlgorithmName);
		} else if (keyType.equals(PersonalKeyDAO.PKCS12_RSA)) {
			// Decode the key using the caPrivateKeyPassword and the ca PKCS
			// password
			Object[] caKeyPair = RSAKeyPair
					.decodePKCS12(caKey.getKeyStr().getBytes(),
							caPrivateKeyPasswordPKCS, caPrivateKeyPassword);

			// Create the certificate
			return _X509Utils.createV3Cert(holderPublicKey,
					((RSAKeyPair) caKeyPair[0]).getPrivateKey(), serialNumber,
					notBefore, notAfter, x509CACertificate,
					certificateInformationMap, keyUsageList, certType,
					spinnerSignAlgorithmName);

		} else if (keyType.equals(PersonalKeyDAO.PRIVATE_EC)) {

			// Decode the key using the caPrivateKeyPassword
			ECPrivateKey caPrivateKey = ECPrivateKey.decode(caKey.getKeyStr()
					.getBytes(), caPrivateKeyPassword);

			// Create the certificate
			return _X509Utils.createV3Cert(holderPublicKey, caPrivateKey,
					serialNumber, notBefore, notAfter, x509CACertificate,
					certificateInformationMap, keyUsageList, certType,
					spinnerSignAlgorithmName);

		} else if (keyType.equals(PersonalKeyDAO.PKCS12_EC)) {
			// Decode the key using the caPrivateKeyPassword and the ca PKCS
			// password
			Object[] caKeyPair = ECKeyPair
					.decodePKCS12(caKey.getKeyStr().getBytes(),
							caPrivateKeyPasswordPKCS, caPrivateKeyPassword);

			// Create the certificate
			return _X509Utils.createV3Cert(holderPublicKey,
					((ECKeyPair) caKeyPair[0]).getPrivateKey(), serialNumber,
					notBefore, notAfter, x509CACertificate,
					certificateInformationMap, keyUsageList, certType,
					spinnerSignAlgorithmName);
		}
		return null;
	}

	/**
	 * Creates a certificate for a RSA Public key using the selected parameters
	 * 
	 * @param holderPublicKey
	 *            Public key to be certified by the CA
	 * @param x509CACertificate
	 *            CA certificate that will issue the certificate
	 * @param serialNumber
	 *            Serial number for the new certificate
	 * @param certType
	 *            Certificate Type
	 * @param spinnerSignAlgorithmName
	 *            Signature Algorithm to be used for sign the certificate
	 * @return A new X509Certificate signed by the CA using its corresponding
	 *         private key
	 * @throws CryptoUtilsException
	 * @throws CryptoUtilsX509ExtensionException
	 */
	private X509Certificate createCertificate(RSAPublicKey holderPublicKey,
			X509Certificate x509CACertificate, BigInteger serialNumber,
			String certType, String spinnerSignAlgorithmName)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException {
		Integer keyType = caKey.getKeyType();
		// Determine the key type and decode it using the password saved in this
		// class
		if (keyType.equals(PersonalKeyDAO.PRIVATE_RSA)) {

			// Decode the key using the caPrivateKeyPassword
			RSAPrivateKey caPrivateKey = RSAPrivateKey.decode(caKey.getKeyStr()
					.getBytes(), caPrivateKeyPassword);

			// Create the certificate
			return _X509Utils.createV3Cert(holderPublicKey, caPrivateKey,
					serialNumber, notBefore, notAfter, x509CACertificate,
					certificateInformationMap, keyUsageList, certType,
					spinnerSignAlgorithmName);
		} else if (keyType.equals(PersonalKeyDAO.PKCS12_RSA)) {
			// Decode the key using the caPrivateKeyPassword and the ca PKCS
			// password
			Object[] caKeyPair = RSAKeyPair
					.decodePKCS12(caKey.getKeyStr().getBytes(),
							caPrivateKeyPasswordPKCS, caPrivateKeyPassword);

			// Create the certificate
			return _X509Utils.createV3Cert(holderPublicKey,
					((RSAKeyPair) caKeyPair[0]).getPrivateKey(), serialNumber,
					notBefore, notAfter, x509CACertificate,
					certificateInformationMap, keyUsageList, certType,
					spinnerSignAlgorithmName);

		} else if (keyType.equals(PersonalKeyDAO.PRIVATE_EC)) {

			// Decode the key using the caPrivateKeyPassword
			ECPrivateKey caPrivateKey = ECPrivateKey.decode(caKey.getKeyStr()
					.getBytes(), caPrivateKeyPassword);

			// Create the certificate
			return _X509Utils.createV3Cert(holderPublicKey, caPrivateKey,
					serialNumber, notBefore, notAfter, x509CACertificate,
					certificateInformationMap, keyUsageList, certType,
					spinnerSignAlgorithmName);

		} else if (keyType.equals(PersonalKeyDAO.PKCS12_EC)) {
			// Decode the key using the caPrivateKeyPassword and the ca PKCS
			// password
			Object[] caKeyPair = ECKeyPair
					.decodePKCS12(caKey.getKeyStr().getBytes(),
							caPrivateKeyPasswordPKCS, caPrivateKeyPassword);

			// Create the certificate
			return _X509Utils.createV3Cert(holderPublicKey,
					((ECKeyPair) caKeyPair[0]).getPrivateKey(), serialNumber,
					notBefore, notAfter, x509CACertificate,
					certificateInformationMap, keyUsageList, certType,
					spinnerSignAlgorithmName);
		}
		return null;
	}
}
