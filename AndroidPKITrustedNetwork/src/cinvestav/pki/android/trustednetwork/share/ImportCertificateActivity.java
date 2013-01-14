/**
 *  Created on  : 07/10/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Fragment Activity for importing a certificate, will contain a fragment for
 * selecting the file to be imported and a spinner for selecting the certificate
 * encoding
 */
package cinvestav.pki.android.trustednetwork.share;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.spongycastle.util.encoders.Base64;

import android.content.Intent;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v4.app.FragmentTransaction;
import android.support.v4.app.NavUtils;
import android.support.v4.app.TaskStackBuilder;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.Toast;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.utils.AsymmetricCryptoUtils;
import cinvestav.android.pki.cryptography.utils.DigestCryptoUtils;
import cinvestav.android.pki.cryptography.utils.X509Utils;
import cinvestav.android.pki.cryptography.utils.X509UtilsDictionary;
import cinvestav.android.pki.db.controller.CertificateController;
import cinvestav.android.pki.db.controller.SubjectController;
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.android.pki.db.dao.SubjectDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.android.pki.utils.DataBaseDictionary;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.adapter.CertificatesSelectableListAdapter;
import cinvestav.pki.android.trustednetwork.common.SelectFileDialogFragment;
import cinvestav.pki.android.trustednetwork.details.CertificateDetailsActivity;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;
import cinvestav.pki.android.trustednetwork.selection.SelectOwnerActivity;

import com.actionbarsherlock.app.ActionBar;
import com.actionbarsherlock.app.SherlockFragmentActivity;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuItem;
import com.actionbarsherlock.view.Window;

/**
 * Fragment Activity for importing a certificate, will contain a fragment for
 * selecting the file to be imported and a spinner for selecting the certificate
 * encoding
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 07/10/2012
 * @version 1.0
 */
public class ImportCertificateActivity extends SherlockFragmentActivity {

	static final int MENU_ACCEPT = 0;
	static final int MENU_CANCEL = 1;
	
	public static final int REQUEST_OPEN_FILE_ID = 1;

	/**
	 * Holder of the certificate
	 */
	Integer holderId;

	/**
	 * Asynchronous task for importing X509 Certificates into the data baseF
	 */
	ImportX509CertificateTask importX509CertificateTask;

	/**
	 * Asynchronous task for searching the possible CA Certificates and fill out
	 * the list
	 */
	FindPossibleCACertificatesTask findPossibleCACertificatesTask;

	// String fileName = "";

	SelectFileDialogFragment selectFileFragment;

	AsymmetricCryptoUtils asymmetricCryptoUtils;
	DigestCryptoUtils digestCryptoUtils;
	X509Utils _X509Utils;

	static CertificateController certificateController;
	static SubjectController subjectController;

	ListView possibleCACertificatesListView;

	X509Certificate certificate;

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

		if (subjectController == null) {
			subjectController = new SubjectController(getApplicationContext());
		}
		int message = R.string.lblMessageImportFile;
		selectFileFragment = SelectFileDialogFragment.newInstance(
				R.string.dialog_select_file_title, message, "", "", REQUEST_OPEN_FILE_ID);
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

		setContentView(R.layout.import_cert);
		setSupportProgressBarIndeterminateVisibility(false);

		// Set up action bar.
		final ActionBar actionBar = getSupportActionBar();

		// Specify that the Home button should show an "Up" caret, indicating
		// that touching the
		// button will take the user one step up in the application's hierarchy.
		actionBar.setDisplayHomeAsUpEnabled(true);
		actionBar.setSubtitle(R.string.subtitle_cert_import);

		// Get Selected holder ID
		holderId = getIntent().getIntExtra(
				SelectOwnerActivity.EXTRA_SELECTED_OWNER_ID, 0);

		asymmetricCryptoUtils = new AsymmetricCryptoUtils();
		digestCryptoUtils = new DigestCryptoUtils();

		possibleCACertificatesListView = (ListView) findViewById(R.id.listCACertificates);
		possibleCACertificatesListView
				.setOnItemClickListener(new AdapterView.OnItemClickListener() {

					@Override
					public void onItemClick(AdapterView<?> parent, View view,
							int position, long id) {
						((CertificatesSelectableListAdapter) possibleCACertificatesListView
								.getAdapter()).setSelectedId((int) id);

					}

				});
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
			importCertificate();
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

		if (findPossibleCACertificatesTask != null) {
			findPossibleCACertificatesTask.cancel(true);
		}
		if (importX509CertificateTask != null) {
			importX509CertificateTask.cancel(true);
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

					do {
						if (findPossibleCACertificatesTask == null
								|| !findPossibleCACertificatesTask.getStatus()
										.equals(AsyncTask.Status.RUNNING)) {
							findPossibleCACertificatesTask = new FindPossibleCACertificatesTask();
							findPossibleCACertificatesTask.execute(filename);
							break;
						} else {
							findPossibleCACertificatesTask.cancel(true);
						}
					} while (true);
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
	 * Makes the validation that the certificate file has been selected and its
	 * correct and if the CA certificate has been selected, the the import task
	 * is created
	 */
	public void importCertificate() {
		// Check if a file has been selected and that this file correspond to a
		// X509Certificate
		if (findPossibleCACertificatesTask == null || certificate == null) {
			Toast.makeText(getApplicationContext(),
					R.string.msgSelectCertificateFile, Toast.LENGTH_SHORT)
					.show();
			return;
		}

		// Check if the CA certificate list has been loaded correctly
		if (findPossibleCACertificatesTask.getStatus().equals(
				AsyncTask.Status.RUNNING)) {
			Toast.makeText(getApplicationContext(),
					R.string.msgLoadingCACertificateList, Toast.LENGTH_SHORT)
					.show();
			return;
		}

		Integer position = ((CertificatesSelectableListAdapter) possibleCACertificatesListView
				.getAdapter()).getSelectedPosition();
		// If the CA certificate has been selected
		if (position >= 0) {
			// If a importing task is already running, show a message to the
			// user
			if (importX509CertificateTask == null
					|| !importX509CertificateTask.getStatus().equals(
							AsyncTask.Status.RUNNING)) {
				importX509CertificateTask = new ImportX509CertificateTask();
				importX509CertificateTask
						.execute((CertificateDAO) ((CertificatesSelectableListAdapter) possibleCACertificatesListView
								.getAdapter()).getItem(position));
			} else {
				Toast.makeText(getApplicationContext(), R.string.msgWorking,
						Toast.LENGTH_SHORT).show();
			}
		} else {
			Toast.makeText(getApplicationContext(),
					R.string.error_cert_select_ca, Toast.LENGTH_SHORT).show();
		}

	}

	/**
	 * Inner class that create an asynchronous task in which possible CA
	 * certificates are searched and finally showed to the user in a list so it
	 * could select the better one
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 08/10/2012
	 * @version 1.0
	 */
	private class FindPossibleCACertificatesTask extends
			AsyncTask<String, Void, List<CertificateDAO>> {

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
		protected List<CertificateDAO> doInBackground(String... params) {

			try {
				certificate = _X509Utils.loadCertificate(params[0]);

				List<CertificateDAO> possibleCACertificates = findCAinDataBase(certificate);

				return possibleCACertificates;
			} catch (CryptoUtilsException e) {
				e.printStackTrace();
				return null;
			} catch (DBException e) {
				e.printStackTrace();
				return null;
			} catch (Exception e) {
				e.printStackTrace();
				return null;
			}

		}

		@Override
		protected void onPostExecute(List<CertificateDAO> possibleCACertificates) {
			if (possibleCACertificates != null) {
				if (possibleCACertificates.isEmpty()) {
					possibleCACertificates.add(new CertificateDAO());
				}
				CertificatesSelectableListAdapter adapter = new CertificatesSelectableListAdapter(
						ImportCertificateActivity.this, possibleCACertificates,
						certificateController);
				possibleCACertificatesListView.setAdapter(adapter);
			} else {
				Toast.makeText(getApplicationContext(),
						R.string.error_cert_load_possible_ca, Toast.LENGTH_LONG)
						.show();
			}
			// Disable the indeterminate progress icon on the action bar
			setSupportProgressBarIndeterminateVisibility(false);
		}

	}

	/**
	 * Inner class that create an asynchronous task in which a X509Certificate
	 * is imported, the parameter is the CA certificate, and the certificate to
	 * be imported is a class attribute
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class ImportX509CertificateTask extends
			AsyncTask<CertificateDAO, Void, CertificateDAO> {

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
		protected CertificateDAO doInBackground(CertificateDAO... params) {

			try {

				// Ones the certificate is loaded, insert it into the data base
				CertificateDAO certificateDAO = new CertificateDAO();

				// Find certificate holder
				SubjectDAO holder = subjectController.getById(holderId);
				// TODO add CA certificate
				certificateDAO.setCaCertificate(params[0]);
				certificateDAO.setCertificateStr(new String(Base64
						.encode(certificate.getEncoded())));
				certificateDAO.setOwner(holder);
				certificateDAO.setSerialNumber(certificate.getSerialNumber()
						.intValue());
				certificateDAO.setSignDeviceId(_X509Utils
						.getExtensionSignDeviceId(certificate));
				certificateDAO
						.setStatus(X509UtilsDictionary.X509_CERTIFICATE_STATUS_VALID);

				byte[] subKeyId = _X509Utils
						.getSubjectKeyIdentifier(certificate);

				certificateDAO.setSubjectKeyId(new String(Base64
						.encode(subKeyId)));

				Log.i(PKITrustNetworkActivity.TAG, "Certificate imported: "
						+ certificateDAO);
				Integer id = certificateController.insert(certificateDAO);
				certificateDAO.setId(id);
				return certificateDAO;

			} catch (DBException e) {
				e.printStackTrace();
			} catch (CertificateEncodingException e) {
				e.printStackTrace();
			}

			return null;

		}

		@Override
		protected void onPostExecute(CertificateDAO certificate) {
			if (certificate != null) {
				Toast.makeText(getApplicationContext(),
						R.string.msgImportCertificateOK, Toast.LENGTH_LONG)
						.show();
				// Disable the indeterminate progress icon on the action bar
				setSupportProgressBarIndeterminateVisibility(false);

				// Show the imported certificate details
				Intent intent = new Intent(getApplicationContext(),
						CertificateDetailsActivity.class);
				intent.putExtra(CertificateDetailsActivity.EXTRA_OWNER_ID,
						holderId);
				intent.putExtra(
						CertificateDetailsActivity.EXTRA_CURRENT_CERTIFICATE_ID,
						certificate.getId());

				startActivity(intent);

			} else {
				Toast.makeText(getApplicationContext(),
						R.string.error_cert_import, Toast.LENGTH_LONG).show();
				// Disable the indeterminate progress icon on the action bar
				setSupportProgressBarIndeterminateVisibility(false);

			}
		}
	}

	/**
	 * Finds a list of POSSIBLE CAs (saved in the device data base) that could
	 * have sign the certificate to be imported, its important to mention that
	 * the returned list is a list of POSSIBLE CA certificates and for must
	 * cases this list should be very accurate but there are two cases that the
	 * list could contain inaccurate results:
	 * <ul>
	 * <li>If external X509 Certificates are stored in the data base: The list
	 * could contain results that are not 100% accurate, cause the external
	 * fields doesn't have the necessary fields for making a proper search
	 * <li>If the imported certificate is a external X509 Certificate: The list
	 * will contain all the certificates that have at least one match on the
	 * certificate comparison fields, so this list could not be very accurate
	 * <ul>
	 * 
	 * In these cases this function will return an empty list so the CA
	 * certificate will be marked as Unknown in order to prevent following
	 * errors during verification or other processes
	 * 
	 * External X509 certificates are certificates created with other
	 * applications and do not contain the necessary fields:
	 * <ul>
	 * <li>AuthorityKeyID - Standard X509 v3 extension
	 * <li>Issuer DN - Standard X509 v3 extension
	 * <li>CA Certificate Serial Number - Custom extension
	 * <li>CA Certificate Sign Device Id - Custom extension
	 * <li>CA Certificate Authority Key Id - Custom extension
	 * </ul>
	 * 
	 * @param importedCertificate
	 *            X509Certificate to be imported
	 * @return A list of POSSIBLE CA Certificate that could have sign the
	 *         certificate to be imported. If no coincidence was found an empty
	 *         list will be returned.
	 * @throws DBException
	 *             If an error has occur while searching the CA certificates
	 *             using the Authority Key ID as filter
	 */
	private List<CertificateDAO> findCAinDataBase(
			X509Certificate importedCertificate) throws DBException {

		byte[] authKeyId = _X509Utils
				.getAuthorityKeyIdentifier(importedCertificate);

		// If the AuthorityKeyId is not present return an empty list, cause
		// there's no
		// way to identify the CA that signs the certificate
		if (authKeyId == null)
			return new LinkedList<CertificateDAO>();

		// Get all the certificates with the subject key id as filter,

		// Create an special filter
		/*
		 * Filter map where: Key = Tag of the filter to be used, should be
		 * define in "DataBaseDictionary" Class, this tags must be written as a
		 * SQL WHERE clause using a PreparedStament form for example: 'DBfield =
		 * ?' or 'DBfield LIKE ?' Value = Must be a string array of 3 positions
		 * where: [0] = Value to be searched in the data base [1] = Data type,
		 * according to this, the PreparedStatemen will be constructed, the
		 * valid DataTypes are defined in the "DataBaseDictionary" Class
		 */
		Map<String, String[]> filterMap = new HashMap<String, String[]>();
		String[] value = new String[3];

		/*
		 * Establish filter properties
		 */
		// Filter value
		value[0] = new String(Base64.encode(authKeyId));
		// Filter type
		value[1] = DataBaseDictionary.FILTER_TYPE_CERTIFICATE_SUBJECT_KEY_ID;
		filterMap.put(DataBaseDictionary.FILTER_CERTIFICATE_SUBJECT_KEY_ID,
				value);

		// Get the certificates using the first CA certificate search filter:
		// Subject Key Unique Id
		List<CertificateDAO> listPossibleCACerts = certificateController
				.getByAdvancedFilter(filterMap);

		// If the list of possible CA certificates is empty, return it and
		// finish the search
		if (listPossibleCACerts.isEmpty()) {
			return listPossibleCACerts;
		}

		// Go over the list of possible CA Certificates and use the following
		// filters: 1. Certificate AuthorityKey Id; 2. Certificate Issuer DN; 3.
		// Certificate CA Serial Number Extension (If Present);4. Certificate CA
		// Sign Device ID (If Present) ;3. Certificate CA Authority Key Id (If
		// Present) ,
		// in order to identity if the signing CA certificate is saved in the
		// data base

		// First get the filter values for the Imported certificate
		X500Principal certIssuerPrincipal = importedCertificate
				.getIssuerX500Principal();
		String caCertificateSerialNumber = _X509Utils
				.getExtensionCACertificateSerialNumber(importedCertificate);

		String caCertificateSignDevice = _X509Utils
				.getExtensionCACertificateSignDeviceId(importedCertificate);

		String caCertificateAuthKeyId = _X509Utils
				.getExtensionCACertificateAuthorityKeyId(importedCertificate);

		// Determine what filters are present in the imported certificate, if a
		// filter is not present, it will not be used for validating the CA
		// Certificate
		Boolean checkSerialNumber = caCertificateSerialNumber != null;
		Boolean checkSignDevice = caCertificateSignDevice != null;
		Boolean checkAuthKeyId = caCertificateAuthKeyId != null;

		// If the imported certificate Issuer Principal is null, return an empty
		// list because there's no way to identify the CA correctly
		if (certIssuerPrincipal == null) {
			return new LinkedList<CertificateDAO>();
		}

		Iterator<CertificateDAO> i = listPossibleCACerts.iterator();
		while (i.hasNext()) {
			CertificateDAO possibleCACert = i.next();
			// Decode the certificate
			try {
				X509Certificate possibleX509CACert = _X509Utils
						.decode(possibleCACert.getCertificateStr().getBytes());

				X500Principal caCertSubjectPrincipal = possibleX509CACert
						.getSubjectX500Principal();

				// The second filter is the Issuer DN

				// If the issuserPrincipal is present, or its equals to the one
				// stored in the list of certificate continue with the next
				// filter, otherwise remove the certificate from the possible CA
				// Certificates list
				if (caCertSubjectPrincipal == null
						|| !X509Utils.comparePrincipal(certIssuerPrincipal,
								caCertSubjectPrincipal)) {
					listPossibleCACerts.remove(possibleCACert);
					continue;
				}

				// The third filter is the CA certificate serial number

				String possibleCertSerialNumber = possibleX509CACert
						.getSerialNumber().toString();

				// If the CA certificate serial number should be checked (means
				// this field is present) and the CA Certificate Serial Number
				// is different to the possible CA certificate serial number,
				// remove it from the list, otherwise continue with the next
				// filter
				if (checkSerialNumber
						&& (possibleCertSerialNumber == null || !caCertificateSerialNumber
								.equals(possibleCertSerialNumber))) {
					listPossibleCACerts.remove(possibleCACert);
					continue;
				}

				// The Fourth filter is the CA certificate sign device
				// id

				String possibleCertSignDeviceId = _X509Utils
						.getExtensionSignDeviceId(possibleX509CACert);

				// If the CA certificate sign device id should be checked (means
				// this field is present) and the CA Certificate sign device id
				// is different to the possible CA certificate value,
				// remove it from the list, otherwise continue with the next
				// filter
				if (checkSignDevice
						&& (possibleCertSignDeviceId == null || !caCertificateSignDevice
								.equals(possibleCertSignDeviceId))) {
					listPossibleCACerts.remove(possibleCACert);
					continue;
				}

				// Finally compares the CA certificate Sign
				// Authority key id in order to be sure that the
				// possible CA certificate is the one that was used
				// for sign the imported certificate

				byte[] possibleCertAuthKeyId = _X509Utils
						.getAuthorityKeyIdentifier(possibleX509CACert);

				// As the previews filters, first is checked if the
				// AuthorityKeyId value should be checked, and if the value of
				// this fields is different in both the imported certificate and
				// the possible certificate, remove it from the list, otherwise
				// continue to the next possible certificate
				if (checkAuthKeyId
						&& (possibleCertAuthKeyId == null || !Arrays.equals(
								caCertificateAuthKeyId.getBytes(),
								possibleCertAuthKeyId))) {
					listPossibleCACerts.remove(possibleCACert);
					continue;
				}

			} catch (CryptoUtilsException e) {
				// If the certificate could not be decoded, go to the next
				// possible certificate
				continue;
			}
		}

		// Return the list of all possible CA certificates, so the user could
		// select the better one
		return listPossibleCACerts;

	}
}
