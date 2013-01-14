/**
 *  Created on  : 28/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Fragment Activity for creating a new self signed certificate
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

import android.content.Context;
import android.content.Intent;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Parcelable;
import android.support.v4.app.DialogFragment;
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
import cinvestav.android.pki.cryptography.ec.ECDomainParameters;
import cinvestav.android.pki.cryptography.ec.ECPointFp;
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
import cinvestav.pki.android.trustednetwork.common.MyPasswordDialogFragment;
import cinvestav.pki.android.trustednetwork.common.MyPasswordDialogFragment.OnPositiveButtonClickListener;
import cinvestav.pki.android.trustednetwork.common.MyPasswordPKCSDialogFragment;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;
import cinvestav.pki.android.trustednetwork.selection.SelectKeyActivity;
import cinvestav.pki.android.trustednetwork.selection.SelectOwnerActivity;

import com.actionbarsherlock.app.ActionBar;
import com.actionbarsherlock.app.SherlockFragmentActivity;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuItem;
import com.actionbarsherlock.view.Window;

/**
 * Fragment Activity for creating a new self signed certificate
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 28/09/2012
 * @version 1.0
 */
public class AddNewCertificateActivity extends SherlockFragmentActivity
		implements LocationListener {

	/**
	 * The {@link android.support.v4.view.PagerAdapter} that will provide
	 * fragments representing each object in a collection. We use a
	 * {@link android.support.v4.app.FragmentStatePagerAdapter} derivative,
	 * which will destroy and re-create fragments as needed, saving and
	 * restoring their state in the process. This is important to conserve
	 * memory and is a best practice when allowing navigation between objects in
	 * a potentially large collection.
	 */
	private NewCertificateCollectionPagerAdapter mCollectionPagerAdapter;

	/**
	 * The {@link android.support.v4.view.ViewPager} that will display the
	 * object collection.
	 */
	private ViewPager mViewPager;
	private X509Utils _X509Utils;

	private static final int MENU_ACCEPT = 0;
	private static final int MENU_CANCEL = 1;

	/**
	 * Holder of the certificate
	 */
	private Integer holderId;

	/**
	 * Certificate key id
	 */
	private Integer privateKeyId;

	private PersonalKeyDAO personalKey;

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

	static PersonalKeyController personalKeyController;
	static SubjectController subjectController;
	static CertificateController certificateController;

	LocationManager locationManager;
	private static final int TWO_MINUTES = 1000 * 60 * 2;
	Location currentBestLocation;

	CreateCertificateECKeyPairTask createCertificateECKeyPairTask;
	CreateCertificateRSAKeyPairTask createCertificateRSAKeyPairTask;

	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		// Acquire a reference to the system Location Manager
		locationManager = (LocationManager) this
				.getSystemService(Context.LOCATION_SERVICE);

		// Register the listener with the Location Manager to receive location
		// updates
		locationManager.requestLocationUpdates(
				LocationManager.NETWORK_PROVIDER, 500, 50, this);

		locationManager.requestLocationUpdates(LocationManager.GPS_PROVIDER,
				500, 50, this);

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
		mCollectionPagerAdapter = new NewCertificateCollectionPagerAdapter(
				getSupportFragmentManager());

		// Set up the ViewPager, attaching the adapter.
		mViewPager = (ViewPager) findViewById(R.id.pager);
		mViewPager.setAdapter(mCollectionPagerAdapter);

		try {
			_X509Utils = new X509Utils();
		} catch (CryptoUtilsException e) {
			e.printStackTrace();
		}

		// Get Selected subject ID
		holderId = getIntent().getIntExtra(
				SelectOwnerActivity.EXTRA_SELECTED_OWNER_ID, 0);

		// Get certificate private key id
		privateKeyId = getIntent().getIntExtra(
				SelectKeyActivity.EXTRA_SELECTED_PERSONAL_KEY_ID, 0);

		try {
			personalKey = personalKeyController.getById(privateKeyId);
		} catch (DBException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
			e.printStackTrace();
			Toast.makeText(this, R.string.error_db_load_key, Toast.LENGTH_LONG)
					.show();
			returnHome();
		}

		Log.i(PKITrustNetworkActivity.TAG, "CREATE NEW CERTIFICATE: "
				+ holderId + " " + privateKeyId);

		mViewPager
				.setCurrentItem(NewCertificateCollectionPagerAdapter.CERT_PAGE);
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
			returnHome();
			return true;
		case MENU_ACCEPT:
			createCertificate();
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
		// Remove the listener you previously added
		locationManager.removeUpdates(this);
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
		Intent upIntent;
		upIntent = new Intent(this, PKITrustNetworkActivity.class);
		upIntent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
				PKITrustNetworkActivity.CERTIFICATE);

		// Remove the listener you previously added
		locationManager.removeUpdates(this);

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
	public class NewCertificateCollectionPagerAdapter extends
			FragmentStatePagerAdapter {

		AddNewCertificateInformationFragment fragmentCertificateInformation;
		AddNewCertificateHolderFragment fragmentHolder;
		AddNewCertificateCustomInformationFragment fragmentCertificateCustomInformation;
		private final FragmentManager mFragmentManager;

		private static final int CUSTOM_PAGE = 0;
		private static final int CERT_PAGE = 1;
		private static final int HOLDER_PAGE = 2;

		public NewCertificateCollectionPagerAdapter(FragmentManager fm) {
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
			Log.i(PKITrustNetworkActivity.TAG, "RESTORE STATE");
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
							.newInstance(personalKey.getKeyType());
				}
				return fragmentCertificateInformation;

			case HOLDER_PAGE:
				if (fragmentHolder == null) {
					fragmentHolder = AddNewCertificateHolderFragment
							.newInstance();
				}
				return fragmentHolder;
			case CUSTOM_PAGE:
				if (fragmentCertificateCustomInformation == null) {
					fragmentCertificateCustomInformation = AddNewCertificateCustomInformationFragment
							.newInstance();
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
	public void createCertificate() {
		Calendar date = Calendar.getInstance();
		date.setTime(new Date());

		// Get the activity of the certificate information fragment
		certificateAuxActivity = mCollectionPagerAdapter
				.getFragmentCertificateInformation().getActivity();

		// Get the dates fields and check if are valid (not before todays date)
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
						Toast.LENGTH_SHORT).show();
				return;
			}

			// Check if the notAfter date is before notBefore date
			if (notAfter.before(notBefore)) {
				Toast.makeText(this, R.string.error_cert_not_after_before,
						Toast.LENGTH_SHORT).show();
				return;
			}

		} catch (ParseException e) {
			Toast.makeText(this, R.string.error_cert_date_format,
					Toast.LENGTH_SHORT).show();
			return;
		} catch (NullPointerException e) {
			Toast.makeText(this, R.string.error_cert_date_format,
					Toast.LENGTH_SHORT).show();
			return;
		}

		// Get all the key usage CheckBox values
		SparseArray<Boolean> keyUsageValues = new SparseArray<Boolean>();

		keyUsageValues.put(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE,
				((CheckBox) certificateAuxActivity
						.findViewById(R.id.chkKeyUsageDigitalSignature))
						.isChecked());
		keyUsageValues.put(X509UtilsDictionary.X509_KEYUSAGE_NONREPUDIATION,
				((CheckBox) certificateAuxActivity
						.findViewById(R.id.chkKeyUsageNonRepudiation))
						.isChecked());
		keyUsageValues.put(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT,
				((CheckBox) certificateAuxActivity
						.findViewById(R.id.chkKeyUsageKeyCipher)).isChecked());
		keyUsageValues.put(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT,
				((CheckBox) certificateAuxActivity
						.findViewById(R.id.chkKeyUsageDataCipher)).isChecked());
		keyUsageValues.put(X509UtilsDictionary.X509_KEYUSAGE_KEY_AGREEMENT,
				((CheckBox) certificateAuxActivity
						.findViewById(R.id.chkKeyUsageKeyAgreement))
						.isChecked());
		keyUsageValues
				.put(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN,
						((CheckBox) certificateAuxActivity
								.findViewById(R.id.chkKeyUsageKeyCertSign))
								.isChecked());
		keyUsageValues.put(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN,
				((CheckBox) certificateAuxActivity
						.findViewById(R.id.chkKeyUsageCRLSign)).isChecked());
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
					Toast.LENGTH_SHORT).show();
			return;
		}

		// Get the activity of the holder information fragment

		/*
		 * LinearLayout layout = (LinearLayout) holderAuxActivity
		 * .findViewById(R.id.layoutHolderFields); int childCount =
		 * layout.getChildCount(); // Check that keyUsage List is not empty if
		 * (childCount < 8) { Toast.makeText(this,
		 * R.string.error_cert_holder_fields_count, Toast.LENGTH_SHORT).show();
		 * return; }
		 */

		// Create the certificateInformationMap for the certificate, using the
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
				// Add the inserted value to the certicateInformationMap, the
				// key for the entry is gotten
				// using the KEY_CODE_LOOK_UP and the label of the field as key
				// for this map
				certificateInformationMap.put(
						CertificateInformationKeys.KEY_CODE_LOOK_UP.get(entry
								.getKey().toLowerCase()), fieldValue);
			}
		}

		Log.i(PKITrustNetworkActivity.TAG, "certificateInformationMap: "
				+ certificateInformationMap);

		if (certificateInformationMap.size() < 4) {
			Toast.makeText(this, R.string.error_cert_holder_fields_not_empty,
					Toast.LENGTH_SHORT).show();
			return;
		}

		// Add custom extensions to the certificateInformationMap

		// Creation Device Id
		certificateInformationMap.put(CertificateInformationKeys.DEVICE_ID,
				PKITrustNetworkActivity.ANDROID_ID);

		// Sign Device Id
		certificateInformationMap.put(
				CertificateInformationKeys.SIGN_DEVICE_ID,
				PKITrustNetworkActivity.ANDROID_ID);

		// Get the last registered location of device
		Location loc = getLastLocation();
		Log.i(PKITrustNetworkActivity.TAG, "CREATION LOCATION: " + loc);
		if (loc != null) {
			// If the location is not null, add the corresponding extensions
			certificateInformationMap.put(
					CertificateInformationKeys.CREATION_POSITION_LATITUDE,
					loc.getLatitude() + "");
			certificateInformationMap.put(
					CertificateInformationKeys.CREATION_POSITION_LONGITUDE,
					loc.getLongitude() + "");
		}

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
				.getTxtCertificateIdentificationDocument().getText().toString();

		if (!txtCertificateUserId.isEmpty()) {
			// User id - if a value was inserted
			certificateInformationMap.put(CertificateInformationKeys.USER_ID,
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

		// If all the information is correct, open the password dialog for the
		// private key
		Integer keyType = personalKey.getKeyType();

		// Determine the key type and decode it
		if (keyType.equals(PersonalKeyDAO.PRIVATE_RSA)) {
			// If is a RSAPrivateKey ask for the password
			DialogFragment newFragment = MyPasswordDialogFragment.newInstance(
					R.string.alert_dialog_key_update_private_title,
					personalKey,
					new OnPositiveButtonClickListenerCreateCertificateImp());
			newFragment.show(getSupportFragmentManager(), "password");
		} else if (keyType.equals(PersonalKeyDAO.PKCS12_RSA)) {
			// If is a PKCS_RSA file, ask for the password
			DialogFragment newFragment = MyPasswordPKCSDialogFragment
					.newInstance(
							R.string.alert_dialog_key_update_private_title,
							personalKey,
							new OnPositiveButtonClickListenerCreateCertificateImp());
			newFragment.show(getSupportFragmentManager(), "password");
		} else if (keyType.equals(PersonalKeyDAO.PRIVATE_EC)) {
			// If is a ECPrivateKey ask for the password
			DialogFragment newFragment = MyPasswordDialogFragment.newInstance(
					R.string.alert_dialog_key_update_private_title,
					personalKey,
					new OnPositiveButtonClickListenerCreateCertificateImp());
			newFragment.show(getSupportFragmentManager(), "password");
		} else if (keyType.equals(PersonalKeyDAO.PKCS12_EC)) {
			// If is a PKCS_RC file, ask for the password
			DialogFragment newFragment = MyPasswordPKCSDialogFragment
					.newInstance(
							R.string.alert_dialog_key_update_private_title,
							personalKey,
							new OnPositiveButtonClickListenerCreateCertificateImp());
			newFragment.show(getSupportFragmentManager(), "password");
		}

	}

	/**
	 * This function is called after the user insert the password for a
	 * {@link ECPrivateKey}, in this function a certificate creation task is
	 * created and executed.
	 * 
	 * @param key
	 *            ECKeyPair to be used for create and sign the certificate
	 */
	public void createCertificate(ECKeyPair key) {
		// If the task is not null, its running so make the user aware of it
		if (createCertificateECKeyPairTask == null
				|| !createCertificateECKeyPairTask.getStatus().equals(
						AsyncTask.Status.RUNNING)) {
			createCertificateECKeyPairTask = new CreateCertificateECKeyPairTask();
			createCertificateECKeyPairTask.execute(key);

		} else {
			Toast.makeText(this, R.string.msgWorking, Toast.LENGTH_SHORT)
					.show();
		}
	}

	/**
	 * This function is called after the user insert the password for a
	 * {@link RSAPrivateKey}, in this function a certificate creation task is
	 * created and executed.
	 * 
	 * @param Key
	 *            RSAKeyPair to be used for create and sign the certicate
	 */
	public void createCertificate(RSAKeyPair key) {
		// If the task is not null, its running so make the user aware of it
		if (createCertificateRSAKeyPairTask == null
				|| !createCertificateRSAKeyPairTask.getStatus().equals(
						AsyncTask.Status.RUNNING)) {
			createCertificateRSAKeyPairTask = new CreateCertificateRSAKeyPairTask();
			createCertificateRSAKeyPairTask.execute(key);

		} else {
			Toast.makeText(this, R.string.msgWorking, Toast.LENGTH_SHORT)
					.show();
		}
	}

	/**
	 * Implements the OnPositiveButtonClickListener for export operation, after
	 * the password dialog is shown, this function is called
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 14/09/2012
	 * @version 1.0
	 */
	public class OnPositiveButtonClickListenerCreateCertificateImp implements
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

					// Compute publicKey
					ECDomainParameters params = privKey.getParams();
					ECPointFp point = ECPointFp.parse(params.getG().multiply(
							privKey.getD()));
					ECPublicKey publicKey = new ECPublicKey(params, point);

					createCertificate(new ECKeyPair(privKey, publicKey));

				} else {
					// If the key is a Private RSA key

					RSAPrivateKey privKey = RSAPrivateKey.decode(key
							.getKeyStr().getBytes(), passwordKey);
					RSAPublicKey pubKey = new RSAPublicKey(
							privKey.getModulus(), privKey.getPublicExponent());
					createCertificate(new RSAKeyPair(privKey, pubKey));

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

					createCertificate(keyPair);

				} else {
					// If the key is a PKCS RSA key
					Object[] decodedRSAKeyPair = RSAKeyPair.decodePKCS12(key
							.getKeyStr().getBytes(), passwordPKCS, passwordKey);

					RSAKeyPair keyPair = (RSAKeyPair) decodedRSAKeyPair[0];
					createCertificate(keyPair);
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
	 * Inner class that create an asynchronous task in which a self signed X509
	 * certificate is created using a ECKeyPair for signing it
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class CreateCertificateECKeyPairTask extends
			AsyncTask<ECKeyPair, Void, CertificateDAO> {

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
		protected CertificateDAO doInBackground(ECKeyPair... params) {

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
				Integer currentSerialNumber = certificateController
						.getCurrentSerialNumberForCA(holderId) + 1;
				BigInteger serialNumber = new BigInteger(currentSerialNumber
						+ "");

				// Create the certificate
				X509Certificate certificate = _X509Utils.createV3Cert(
						params[0].getPublicKey(), params[0].getPrivateKey(),
						serialNumber, notBefore, notAfter,
						certificateInformationMap, keyUsageList, certType,
						spinnerSignAlgorithmName);

				// Once the certificate is created, add it to the data base

				return addToDataBase(currentSerialNumber, certificate);
			} catch (CryptoUtilsException e) {
				e.printStackTrace();
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
				return null;
			} catch (CryptoUtilsX509ExtensionException e) {
				e.printStackTrace();
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
				return null;
			} catch (DBException e) {
				e.printStackTrace();
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
				return null;
			} catch (CertificateEncodingException e) {
				e.printStackTrace();
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
				return null;
			}
		}

		@Override
		protected void onPostExecute(CertificateDAO res) {
			if (res != null) {
				Toast.makeText(getApplicationContext(),
						R.string.msgAddCertificateOK, Toast.LENGTH_LONG).show();
				returnHome();
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
	 * Inner class that create an asynchronous task in which a self signed X509
	 * certificate is created using a RSAKeyPair for signing it
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class CreateCertificateRSAKeyPairTask extends
			AsyncTask<RSAKeyPair, Void, CertificateDAO> {

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
		protected CertificateDAO doInBackground(RSAKeyPair... params) {

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
				Integer currentSerialNumber = certificateController
						.getCurrentSerialNumberForCA(holderId) + 1;
				BigInteger serialNumber = new BigInteger(currentSerialNumber
						+ "");

				// Create the certificate
				X509Certificate certificate = _X509Utils.createV3Cert(
						params[0].getPublicKey(), params[0].getPrivateKey(),
						serialNumber, notBefore, notAfter,
						certificateInformationMap, keyUsageList, certType,
						spinnerSignAlgorithmName);

				// Once the certificate is created, add it to the data base
				return addToDataBase(currentSerialNumber, certificate);
			} catch (CryptoUtilsException e) {
				e.printStackTrace();
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
				return null;
			} catch (CryptoUtilsX509ExtensionException e) {
				e.printStackTrace();
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
				return null;
			} catch (DBException e) {
				e.printStackTrace();
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
				return null;
			} catch (CertificateEncodingException e) {
				e.printStackTrace();
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);
				return null;
			}
		}

		@Override
		protected void onPostExecute(CertificateDAO res) {
			if (res != null) {
				Toast.makeText(getApplicationContext(),
						R.string.msgAddCertificateOK, Toast.LENGTH_LONG).show();
				returnHome();
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
	 * Gets the last known location using NETWORK and GPS providers
	 * 
	 * @return a location object or null if no location is available
	 */
	private Location getLastLocation() {
		if (currentBestLocation == null) {
			// Gets the last location of the network provider
			Location location = locationManager
					.getLastKnownLocation(LocationManager.NETWORK_PROVIDER);
			// if the location is null (the providers does not get any location)
			if (location == null) {
				// Get the last location of the GPS provider
				location = locationManager
						.getLastKnownLocation(LocationManager.GPS_PROVIDER);
			}
			return location;
		}
		return currentBestLocation;

	}

	/**
	 * Add the X509 certificate to the data base using the specified
	 * currentSerialNumber
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
	protected CertificateDAO addToDataBase(Integer currentSerialNumber,
			X509Certificate certificate) throws CertificateEncodingException,
			DBException {
		// Get the holder information
		SubjectDAO holder = subjectController.getById(holderId);
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
		certificateDAO.setCaCertificate(certificateDAO);

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
	 * Determines whether one Location reading is better than the current
	 * Location fix
	 * 
	 * @param location
	 *            The new Location that you want to evaluate
	 * @param currentBestLocation
	 *            The current Location fix, to which you want to compare the new
	 *            one
	 */
	private boolean isBetterLocation(Location location,
			Location currentBestLocation) {
		if (currentBestLocation == null) {
			// A new location is always better than no location
			return true;
		}

		// Check whether the new location fix is newer or older
		long timeDelta = location.getTime() - currentBestLocation.getTime();
		boolean isSignificantlyNewer = timeDelta > TWO_MINUTES;
		boolean isSignificantlyOlder = timeDelta < -TWO_MINUTES;
		boolean isNewer = timeDelta > 0;

		// If it's been more than two minutes since the current location, use
		// the new location
		// because the user has likely moved
		if (isSignificantlyNewer) {
			return true;
			// If the new location is more than two minutes older, it must be
			// worse
		} else if (isSignificantlyOlder) {
			return false;
		}

		// Check whether the new location fix is more or less accurate
		int accuracyDelta = (int) (location.getAccuracy() - currentBestLocation
				.getAccuracy());
		boolean isLessAccurate = accuracyDelta > 0;
		boolean isMoreAccurate = accuracyDelta < 0;
		boolean isSignificantlyLessAccurate = accuracyDelta > 200;

		// Check if the old and new location are from the same provider
		boolean isFromSameProvider = isSameProvider(location.getProvider(),
				currentBestLocation.getProvider());

		// Determine location quality using a combination of timeliness and
		// accuracy
		if (isMoreAccurate) {
			return true;
		} else if (isNewer && !isLessAccurate) {
			return true;
		} else if (isNewer && !isSignificantlyLessAccurate
				&& isFromSameProvider) {
			return true;
		}
		return false;
	}

	/** Checks whether two providers are the same */
	private boolean isSameProvider(String provider1, String provider2) {
		if (provider1 == null) {
			return provider2 == null;
		}
		return provider1.equals(provider2);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * android.location.LocationListener#onLocationChanged(android.location.
	 * Location)
	 */
	@Override
	public void onLocationChanged(Location location) {
		// Each time the location change, its registered in the log
		Log.d(PKITrustNetworkActivity.TAG, "LOCATION CHANGE: " + location);
		if (location != null) {
			double lat = location.getLatitude();
			double lng = location.getLongitude();
			String text = "location= " + "Lat = " + lat + "Long = " + lng
					+ " Provider: " + location.getProvider();
			Log.d(PKITrustNetworkActivity.TAG, text);
			// Toast.makeText(getApplicationContext(), text, Toast.LENGTH_LONG)
			// .show();
			if (isBetterLocation(location, currentBestLocation)) {
				Log.d(PKITrustNetworkActivity.TAG,
						"UPDATE CURRENT BEST LOCATION");
				currentBestLocation = location;
			}
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.location.LocationListener#onStatusChanged(java.lang.String,
	 * int, android.os.Bundle)
	 */
	@Override
	public void onStatusChanged(String provider, int status, Bundle extras) {
		// TODO Auto-generated method stub

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * android.location.LocationListener#onProviderEnabled(java.lang.String)
	 */
	@Override
	public void onProviderEnabled(String provider) {
		// TODO Auto-generated method stub

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * android.location.LocationListener#onProviderDisabled(java.lang.String)
	 */
	@Override
	public void onProviderDisabled(String provider) {
		// TODO Auto-generated method stub

	}
}
