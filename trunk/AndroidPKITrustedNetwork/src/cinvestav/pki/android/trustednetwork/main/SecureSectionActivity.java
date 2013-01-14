/**
 *  Created on  : 24/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	This Fragment includes all the Secure operations, like: 
 *  <ul> 
 * <li> Encrypt/Decrypt files and messages
 * <li> Sign/Verify files and messages
 * <li> Save Messages
 * <li> See messages and encrypted files details
 * <li> Send Messages or files
 *  </ul>
 */
package cinvestav.pki.android.trustednetwork.main;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.List;

import org.spongycastle.util.encoders.Base64;

import android.annotation.SuppressLint;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Parcelable;
import android.provider.MediaStore;
import android.support.v4.app.DialogFragment;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentStatePagerAdapter;
import android.support.v4.app.NavUtils;
import android.support.v4.app.TaskStackBuilder;
import android.support.v4.view.ViewPager;
import android.util.Log;
import android.view.View;
import android.widget.CheckBox;
import android.widget.EditText;
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
import cinvestav.android.pki.cryptography.utils.AsymmetricCryptoUtils;
import cinvestav.android.pki.cryptography.utils.X509Utils;
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
import cinvestav.pki.android.trustednetwork.crypto.SecureOperationFileFragment;
import cinvestav.pki.android.trustednetwork.crypto.SecureOperationMessageFragment;
import cinvestav.pki.android.trustednetwork.crypto.SecureOperationOptionsFragment.OnClickSearchElementsListener;
import cinvestav.pki.android.trustednetwork.selection.SelectHolderWithCertificateActivity;
import cinvestav.pki.android.trustednetwork.selection.SelectHolderWithKeysActivity;

import com.actionbarsherlock.app.ActionBar;
import com.actionbarsherlock.app.SherlockFragmentActivity;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuItem;
import com.actionbarsherlock.view.Window;

/**
 * This Fragment includes all the Secure operations, like:
 * <ul>
 * <li>Encrypt/Decrypt files and messages
 * <li>Sign/Verify files and messages
 * <li>Save Messages
 * <li>See messages and encrypted files details
 * <li>Send Messages or files
 * </ul>
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 24/08/2012
 * @version 1.0
 */
@SuppressLint("NewApi")
public class SecureSectionActivity extends SherlockFragmentActivity implements
		OnClickSearchElementsListener {

	/**
	 * The {@link android.support.v4.view.PagerAdapter} that will provide
	 * fragments representing each object in a collection. We use a
	 * {@link android.support.v4.app.FragmentStatePagerAdapter} derivative,
	 * which will destroy and re-create fragments as needed, saving and
	 * restoring their state in the process. This is important to conserve
	 * memory and is a best practice when allowing navigation between objects in
	 * a potentially large collection.
	 */
	private SecureOperationCollectionPagerAdapter mCollectionPagerAdapter;

	/**
	 * The {@link android.support.v4.view.ViewPager} that will display the
	 * object collection.
	 */
	private ViewPager mViewPager;
	private AsymmetricCryptoUtils asymmetricCryptoUtils;
	// private DigestCryptoUtils digestCryptoUtils;
	private X509Utils x509Utils;

	// static final int MENU_CANCEL = 1;

	private int currentOption;
	private int selectedOperation;
	private int selectedInput;
	private int selectedPrivateKeySign;
	private int selectedPrivateKeyDecipher;
	private int selectedCertificateVerify;
	private int selectedCertificateCipher;

	public static final String SELECTED_PRIVATE_KEY_SIGN = "SELECTED_PRIVATE_KEY_SIGN";
	public static final String SELECTED_PRIVATE_KEY_DECIPHER = "SELECTED_PRIVATE_KEY_DECIPHER";

	public static final String SELECTED_CERTIFICATE_VERIFY = "SELECTED_CERTIFICATE_VERIFY";
	public static final String SELECTED_CERTIFICATE_CIPHER = "SELECTED_CERTIFICATE_CIPHER";
	public static final String SELECTED_OPERATION = "SELECTED_OPERATION";
	public static final String SELECTED_INPUT = "SELECTED_INPUT";
	public static final String EXISTING_INPUT = "EXISTING_INPUT";
	public static final String EXISTING_OUTPUT_FILE = "EXISTING_OUTPUT_FILE";
	public static final int FILE = 0;
	public static final int MESSAGE = 1;

	private PersonalKeyController personalKeyController;
	private CertificateController certificateController;
	private SubjectController subjectController;

	private PersonalKeyDAO privateKeySign;
	private PersonalKeyDAO privateKeyDecipher;

	private CertificateDAO certificateVerify;
	private CertificateDAO certificateCipher;

	private String selectedPrivateKeySignTxt;
	private String selectedPrivateKeyDecipherTxt;
	private String selectedCertificateVerifyTxt;
	private String selectedCertificateCipherTxt;
	private String existingInput;
	private String existingOutputFile;

	private EncryptSignEncryptTask encryptSignEncryptTask;
	private DecryptVerifyDecryptTask decryptVerifyDecryptTask;

	private TextView txtMessage;
	private TextView txtFileName;
	private TextView txtOutputFileName;

	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		// This has to be called before setContentView and you must use the
		// class in com.actionbarsherlock.view and NOT android.view
		requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

		setContentView(R.layout.main_secure);
		setSupportProgressBarIndeterminateVisibility(false);

		// Set up action bar.
		final ActionBar actionBar = getSupportActionBar();

		// Specify that the Home button should show an "Up" caret, indicating
		// that touching the
		// button will take the user one step up in the application's hierarchy.
		actionBar.setDisplayHomeAsUpEnabled(true);
		actionBar.setSubtitle(R.string.subtitle_secure);

		// Create an adapter that when requested, will return a fragment
		// representing an object in
		// the collection.
		//
		// ViewPager and its adapters use support library fragments, so we must
		// use
		// getSupportFragmentManager.
		mCollectionPagerAdapter = new SecureOperationCollectionPagerAdapter(
				getSupportFragmentManager());

		// Set up the ViewPager, attaching the adapter.
		mViewPager = (ViewPager) findViewById(R.id.pager);
		mViewPager.setAdapter(mCollectionPagerAdapter);

		asymmetricCryptoUtils = new AsymmetricCryptoUtils();
		// digestCryptoUtils = new DigestCryptoUtils();

		currentOption = this.getIntent().getExtras()
				.getInt(PKITrustNetworkActivity.CURRENT_OPTION);
		selectedOperation = this.getIntent().getExtras()
				.getInt(SELECTED_OPERATION);

		selectedInput = this.getIntent().getExtras().getInt(SELECTED_INPUT);

		existingInput = getIntent().getExtras().getString(EXISTING_INPUT);
		existingOutputFile = getIntent().getExtras().getString(
				EXISTING_OUTPUT_FILE);

		mViewPager.setCurrentItem(selectedInput);

		selectedPrivateKeySign = this.getIntent().getExtras()
				.getInt(SELECTED_PRIVATE_KEY_SIGN);

		selectedPrivateKeyDecipher = this.getIntent().getExtras()
				.getInt(SELECTED_PRIVATE_KEY_DECIPHER);

		selectedCertificateCipher = this.getIntent().getExtras()
				.getInt(SELECTED_CERTIFICATE_CIPHER);

		selectedCertificateVerify = this.getIntent().getExtras()
				.getInt(SELECTED_CERTIFICATE_VERIFY);

		if (personalKeyController == null) {
			personalKeyController = new PersonalKeyController(
					getApplicationContext());
		}

		if (certificateController == null) {
			certificateController = new CertificateController(
					getApplicationContext());
		}

		if (subjectController == null) {
			subjectController = new SubjectController(getApplicationContext());
		}

		selectedPrivateKeySignTxt = "";
		selectedPrivateKeyDecipherTxt = "";
		selectedCertificateCipherTxt = "";
		selectedCertificateVerifyTxt = "";

		if (selectedPrivateKeySign != 0) {
			try {
				privateKeySign = personalKeyController
						.getById(selectedPrivateKeySign);
				SubjectDAO sub = subjectController.getById(privateKeySign
						.getSubjectId());
				selectedPrivateKeySignTxt = sub.getName()
						+ "\n"
						+ privateKeySign.getId()
						+ " - "
						+ privateKeySign
								.getKeyTypeStr(PKITrustNetworkActivity.LAN);

			} catch (DBException e) {
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
				e.printStackTrace();
				Toast.makeText(
						this,
						R.string.error_db_load_secure_parameters_privatekey_sign,
						Toast.LENGTH_LONG).show();
			}
		}

		if (selectedPrivateKeyDecipher != 0) {
			try {
				privateKeyDecipher = personalKeyController
						.getById(selectedPrivateKeyDecipher);
				SubjectDAO sub = subjectController.getById(privateKeyDecipher
						.getSubjectId());
				selectedPrivateKeyDecipherTxt = sub.getName()
						+ "\n"
						+ privateKeyDecipher.getId()
						+ " - "
						+ privateKeyDecipher
								.getKeyTypeStr(PKITrustNetworkActivity.LAN);

			} catch (DBException e) {
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
				e.printStackTrace();
				Toast.makeText(
						this,
						R.string.error_db_load_secure_parameters_privatekey_decipher,
						Toast.LENGTH_LONG).show();
			}
		}

		if (selectedCertificateCipher != 0) {
			try {
				certificateCipher = certificateController
						.getById(selectedCertificateCipher);
				certificateController.getCertificateDetails(certificateCipher);
				SubjectDAO sub = subjectController.getById(certificateCipher
						.getOwner().getId());
				selectedCertificateCipherTxt = sub.getName() + "\n"
						+ getString(R.string.lblCertificateSerialNumber) + ": "
						+ certificateCipher.getSerialNumber();

			} catch (DBException e) {
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
				e.printStackTrace();
				Toast.makeText(
						this,
						R.string.error_db_load_secure_parameters_certificate_cipher,
						Toast.LENGTH_LONG).show();
			}
		}

		if (selectedCertificateVerify != 0) {
			try {
				certificateVerify = certificateController
						.getById(selectedCertificateVerify);
				certificateController.getCertificateDetails(certificateVerify);
				SubjectDAO sub = subjectController.getById(certificateVerify
						.getOwner().getId());
				selectedCertificateVerifyTxt = sub.getName() + "\n"
						+ getString(R.string.lblCertificateSerialNumber) + ": "
						+ certificateVerify.getSerialNumber();

			} catch (DBException e) {
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
				e.printStackTrace();
				Toast.makeText(
						this,
						R.string.error_db_load_secure_parameters_certificate_verify,
						Toast.LENGTH_LONG).show();
			}
		}

		try {
			x509Utils = new X509Utils();
		} catch (CryptoUtilsException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e);

		}

	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Place an action bar item for cipher and signing
		getSupportMenuInflater().inflate(R.menu.secure_menu, menu);

		return super.onCreateOptionsMenu(menu);
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		switch (item.getItemId()) {
		case android.R.id.home:
			returnHome(android.R.id.home);
			return true;
		case R.id.menu_secure_continue:
			performOperation();
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}

	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data) {

		switch (requestCode) {
		case SecureOperationFileFragment.REQUEST_OPEN_FILE_ID: {

			if (resultCode == RESULT_OK && data != null) {
				String filename = data.getDataString();

				if (filename != null) {
					// Get rid of URI prefix:
					if (filename.startsWith("file://")) {
						filename = filename.substring(7);
					} else if (filename.startsWith("content://")) {
						filename = getRealPathFromURI(Uri.parse(filename));
					}
					// replace %20 and so on
					filename = Uri.decode(filename);

					((EditText) mCollectionPagerAdapter.getFragmentFile()
							.getSelectFileFragment().getView()
							.findViewById(R.id.txtFileName)).setText(filename);

					int operation = ((Spinner) mCollectionPagerAdapter
							.getFragmentFile()
							.getSecureOperationOptionsFragment().getView()
							.findViewById(R.id.spinnerOperation))
							.getSelectedItemPosition();
					if (operation == 0) {
						// Cipher add .atn extention
						((EditText) mCollectionPagerAdapter.getFragmentFile()
								.getSelectOutputFileFragment().getView()
								.findViewById(R.id.txtFileName))
								.setText(filename + ".atn");
					} else {
						// Decipher... remove the extension
						filename = filename.replaceFirst(".atn", "");

						((EditText) mCollectionPagerAdapter.getFragmentFile()
								.getSelectOutputFileFragment().getView()
								.findViewById(R.id.txtFileName))
								.setText(filename);
					}

					// fileName = filename;

				}
			}
			return;
		}
		case SecureOperationFileFragment.REQUEST_OPEN_OUTPUT_FILE_ID: {

			if (resultCode == RESULT_OK && data != null) {
				String filename = data.getDataString();

				if (filename != null) {
					// Get rid of URI prefix:
					if (filename.startsWith("file://")) {
						filename = filename.substring(7);
					} else if (filename.startsWith("content://")) {
						filename = getRealPathFromURI(Uri.parse(filename));
					}
					// replace %20 and so on
					filename = Uri.decode(filename);

					((EditText) mCollectionPagerAdapter.getFragmentFile()
							.getSelectOutputFileFragment().getView()
							.findViewById(R.id.txtFileName)).setText(filename);
					// fileName = filename;

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

	// And to convert the image URI to the direct file system path of the image
	// file
	public String getRealPathFromURI(Uri contentUri) {

		// can post image
		String[] proj = { MediaStore.Images.Media.DATA };
		Cursor cursor = getContentResolver().query(contentUri, proj, // Which
																		// columns
																		// to
																		// return
				null, // WHERE clause; which rows to return (all rows)
				null, // WHERE clause selection arguments (none)
				null); // Order-by clause (ascending by name)
		int column_index = cursor
				.getColumnIndexOrThrow(MediaStore.Images.Media.DATA);
		cursor.moveToFirst();

		return cursor.getString(column_index);
	}

	/**
	 * Perform the selected operation with the selected parameters
	 */
	private void performOperation() {
		long operation = 0;
		// Selected the resource to which the operation will be performed File
		// or message
		int selectedResorce = mViewPager.getCurrentItem();
		switch (selectedResorce) {
		case SecureOperationCollectionPagerAdapter.FILE_PAGE:
			txtFileName = (TextView) mCollectionPagerAdapter.getFragmentFile()
					.getSelectFileFragment().getView()
					.findViewById(R.id.txtFileName);

			txtOutputFileName = (TextView) mCollectionPagerAdapter
					.getFragmentFile().getSelectOutputFileFragment().getView()
					.findViewById(R.id.txtFileName);

			// Check if the user has selected a file
			if (txtFileName.getText() == null
					|| txtFileName.getText().toString().equals("")) {
				Toast.makeText(this, R.string.error_crypto_none_file,
						Toast.LENGTH_LONG).show();
				return;
			}

			// Check if the user has selected a file
			if (txtOutputFileName.getText() == null
					|| txtOutputFileName.getText().toString().equals("")) {
				Toast.makeText(this, R.string.error_crypto_none_output_file,
						Toast.LENGTH_LONG).show();
				return;
			}

			// Check if the file exists
			File f = new File(txtFileName.getText().toString());
			if (!f.exists()) {
				Toast.makeText(this, R.string.error_crypto_none_file_valid,
						Toast.LENGTH_LONG).show();
				return;
			}

			// Check if the user has selected the correct parameters depending
			// on the selected operations
			operation = ((Spinner) mCollectionPagerAdapter.getFragmentMessage()
					.getView().findViewById(R.id.spinnerOperation))
					.getSelectedItemId();
			// Cipher and Sign
			if (operation == 0) {
				Boolean chkCipher = ((CheckBox) mCollectionPagerAdapter
						.getFragmentFile().getView()
						.findViewById(R.id.chkCipher)).isChecked();
				Boolean chkSign = ((CheckBox) mCollectionPagerAdapter
						.getFragmentFile().getView().findViewById(R.id.chkSign))
						.isChecked();

				// If non of the cipher or sign checkbox are checked, show an
				// error message and finish
				if (!chkCipher && !chkSign) {
					Toast.makeText(this, R.string.error_crypto_none_operation,
							Toast.LENGTH_LONG).show();
					return;
				}

				// Check if the private key has been selected
				if (chkSign && selectedPrivateKeySign == 0) {
					Toast.makeText(this,
							R.string.error_crypto_none_sign_private_key,
							Toast.LENGTH_LONG).show();
					return;
				}

				if (chkCipher && selectedCertificateCipher == 0) {
					Toast.makeText(this,
							R.string.error_crypto_none_cipher_cert,
							Toast.LENGTH_LONG).show();
					return;
				}

				// If chkSign is selected ask for private key password
				if (chkSign) {
					// If the code reaches this point, the key is a private or
					// PKCS key
					// Check the key type
					if (privateKeySign.getKeyType().equals(
							PersonalKeyDAO.PRIVATE_RSA)
							|| privateKeySign.getKeyType().equals(
									PersonalKeyDAO.PRIVATE_EC)) {
						// If is a RSAPrivateKey or ECPrivateKey ask for the
						// password
						DialogFragment newFragment = MyPasswordDialogFragment
								.newInstance(
										R.string.alert_dialog_key_open_private_title,
										privateKeySign,
										new OnPositiveButtonClickListenerSignImp(
												chkCipher));
						newFragment.show(getSupportFragmentManager(),
								"password");
					} else if (privateKeySign.getKeyType().equals(
							PersonalKeyDAO.PKCS12_RSA)
							|| privateKeySign.getKeyType().equals(
									PersonalKeyDAO.PKCS12_EC)) {
						// If is a PKCS , ask for the password
						DialogFragment newFragment = MyPasswordPKCSDialogFragment
								.newInstance(
										R.string.alert_dialog_key_open_private_title,
										privateKeySign,
										new OnPositiveButtonClickListenerSignImp(
												chkCipher));
						newFragment.show(getSupportFragmentManager(),
								"password");

					}
				} else {
					// Cipher only
					encryptMessage();
				}

			} else {
				// Decipher and verify
				// Decipher and verify
				Boolean chkDecipher = ((CheckBox) mCollectionPagerAdapter
						.getFragmentFile().getView()
						.findViewById(R.id.chkDecipher)).isChecked();
				Boolean chkVerify = ((CheckBox) mCollectionPagerAdapter
						.getFragmentFile().getView()
						.findViewById(R.id.chkVerify)).isChecked();

				// If non of the cipher or sign checkbox are checked, show an
				// error message and finish
				if (!chkDecipher && !chkVerify) {
					Toast.makeText(this, R.string.error_crypto_none_operation,
							Toast.LENGTH_LONG).show();
					return;
				}

				// Check if the certificate has been selected
				if (chkVerify && selectedCertificateVerify == 0) {
					Toast.makeText(this,
							R.string.error_crypto_none_verify_cert,
							Toast.LENGTH_LONG).show();
					return;
				}

				// Check if the private key has been selected
				if (chkDecipher && selectedPrivateKeyDecipher == 0) {
					Toast.makeText(this,
							R.string.error_crypto_none_decipher_private_key,
							Toast.LENGTH_LONG).show();
					return;
				}

				// If chkDecipher is selected ask for private key password
				if (chkDecipher) {
					// If the code reaches this point, the key is a private or
					// PKCS key
					// Check the key type
					if (privateKeyDecipher.getKeyType().equals(
							PersonalKeyDAO.PRIVATE_RSA)
							|| privateKeyDecipher.getKeyType().equals(
									PersonalKeyDAO.PRIVATE_EC)) {
						// If is a PrivateKey ask for the password
						DialogFragment newFragment = MyPasswordDialogFragment
								.newInstance(
										R.string.alert_dialog_key_open_private_title,
										privateKeyDecipher,
										new OnPositiveButtonClickListenerDecipherImp(
												chkVerify));
						newFragment.show(getSupportFragmentManager(),
								"password");
					} else if (privateKeyDecipher.getKeyType().equals(
							PersonalKeyDAO.PKCS12_RSA)
							|| privateKeyDecipher.getKeyType().equals(
									PersonalKeyDAO.PKCS12_EC)) {
						// If is a PKCS file, ask for the password
						DialogFragment newFragment = MyPasswordPKCSDialogFragment
								.newInstance(
										R.string.alert_dialog_key_open_private_title,
										privateKeyDecipher,
										new OnPositiveButtonClickListenerDecipherImp(
												chkVerify));
						newFragment.show(getSupportFragmentManager(),
								"password");
					}
				}
			}

			break;
		case SecureOperationCollectionPagerAdapter.MESSAGE_PAGE:
			txtMessage = (TextView) mCollectionPagerAdapter
					.getFragmentMessage().getView()
					.findViewById(R.id.txtMessage);
			// Check if the user has selected the correct parameters depending
			// on the selected operations
			operation = ((Spinner) mCollectionPagerAdapter.getFragmentMessage()
					.getView().findViewById(R.id.spinnerOperation))
					.getSelectedItemId();
			// Cipher and Sign
			if (operation == 0) {
				Boolean chkCipher = ((CheckBox) mCollectionPagerAdapter
						.getFragmentMessage().getView()
						.findViewById(R.id.chkCipher)).isChecked();
				Boolean chkSign = ((CheckBox) mCollectionPagerAdapter
						.getFragmentMessage().getView()
						.findViewById(R.id.chkSign)).isChecked();

				// If non of the cipher or sign checkbox are checked, show an
				// error message and finish
				if (!chkCipher && !chkSign) {
					Toast.makeText(this, R.string.error_crypto_none_operation,
							Toast.LENGTH_LONG).show();
					return;
				}

				// Check if the private key has been selected
				if (chkSign && selectedPrivateKeySign == 0) {
					Toast.makeText(this,
							R.string.error_crypto_none_sign_private_key,
							Toast.LENGTH_LONG).show();
					return;
				}

				if (chkCipher && selectedCertificateCipher == 0) {
					Toast.makeText(this,
							R.string.error_crypto_none_cipher_cert,
							Toast.LENGTH_LONG).show();
					return;
				}

				// If chkSign is selected ask for private key password
				if (chkSign) {
					// If the code reaches this point, the key is a private or
					// PKCS key
					// Check the key type
					if (privateKeySign.getKeyType().equals(
							PersonalKeyDAO.PRIVATE_RSA)
							|| privateKeySign.getKeyType().equals(
									PersonalKeyDAO.PRIVATE_EC)) {
						// If is a RSAPrivateKey or ECPrivateKey ask for the
						// password
						DialogFragment newFragment = MyPasswordDialogFragment
								.newInstance(
										R.string.alert_dialog_key_open_private_title,
										privateKeySign,
										new OnPositiveButtonClickListenerSignImp(
												chkCipher));
						newFragment.show(getSupportFragmentManager(),
								"password");
					} else if (privateKeySign.getKeyType().equals(
							PersonalKeyDAO.PKCS12_RSA)
							|| privateKeySign.getKeyType().equals(
									PersonalKeyDAO.PKCS12_EC)) {
						// If is a PKCS , ask for the password
						DialogFragment newFragment = MyPasswordPKCSDialogFragment
								.newInstance(
										R.string.alert_dialog_key_open_private_title,
										privateKeySign,
										new OnPositiveButtonClickListenerSignImp(
												chkCipher));
						newFragment.show(getSupportFragmentManager(),
								"password");

					}
				} else {
					// Cipher only
					encryptMessage();
				}

				// CheckBox chkDeleteCipher;

			} else {
				// Decipher and verify
				Boolean chkDecipher = ((CheckBox) mCollectionPagerAdapter
						.getFragmentMessage().getView()
						.findViewById(R.id.chkDecipher)).isChecked();
				Boolean chkVerify = ((CheckBox) mCollectionPagerAdapter
						.getFragmentMessage().getView()
						.findViewById(R.id.chkVerify)).isChecked();

				// If non of the cipher or sign checkbox are checked, show an
				// error message and finish
				if (!chkDecipher && !chkVerify) {
					Toast.makeText(this, R.string.error_crypto_none_operation,
							Toast.LENGTH_LONG).show();
					return;
				}

				// Check if the certificate has been selected
				if (chkVerify && selectedCertificateVerify == 0) {
					Toast.makeText(this,
							R.string.error_crypto_none_verify_cert,
							Toast.LENGTH_LONG).show();
					return;
				}

				// Check if the private key has been selected
				if (chkDecipher && selectedPrivateKeyDecipher == 0) {
					Toast.makeText(this,
							R.string.error_crypto_none_decipher_private_key,
							Toast.LENGTH_LONG).show();
					return;
				}

				// If chkDecipher is selected ask for private key password
				if (chkDecipher) {
					// If the code reaches this point, the key is a private or
					// PKCS key
					// Check the key type
					if (privateKeyDecipher.getKeyType().equals(
							PersonalKeyDAO.PRIVATE_RSA)
							|| privateKeyDecipher.getKeyType().equals(
									PersonalKeyDAO.PRIVATE_EC)) {
						// If is a PrivateKey ask for the password
						DialogFragment newFragment = MyPasswordDialogFragment
								.newInstance(
										R.string.alert_dialog_key_open_private_title,
										privateKeyDecipher,
										new OnPositiveButtonClickListenerDecipherImp(
												chkVerify));
						newFragment.show(getSupportFragmentManager(),
								"password");
					} else if (privateKeyDecipher.getKeyType().equals(
							PersonalKeyDAO.PKCS12_RSA)
							|| privateKeyDecipher.getKeyType().equals(
									PersonalKeyDAO.PKCS12_EC)) {
						// If is a PKCS file, ask for the password
						DialogFragment newFragment = MyPasswordPKCSDialogFragment
								.newInstance(
										R.string.alert_dialog_key_open_private_title,
										privateKeyDecipher,
										new OnPositiveButtonClickListenerDecipherImp(
												chkVerify));
						newFragment.show(getSupportFragmentManager(),
								"password");
					}
				}
			}

			break;
		default:
			break;
		}

	}

	/**
	 * This is called to return home in the application navigation scheme
	 */
	private void returnHome(Integer option) {

		// if (encryptSignEncryptTask != null)
		// encryptSignEncryptTask.cancel(true);
		// if (createRSAKeyTask != null)
		// createRSAKeyTask.cancel(true);

		// This is called when the Home (Up) button is pressed in the action
		// bar.
		// Create a simple intent that starts the hierarchical parent
		// activity and
		// use NavUtils in the Support Package to ensure proper handling of
		// Up.
		Intent upIntent;
		upIntent = new Intent(this, PKITrustNetworkActivity.class);
		upIntent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION, currentOption);

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

	private void encryptMessage() {
		// Decode the certificate
		X509Certificate cert;

		try {
			cert = x509Utils.decode(certificateCipher.getCertificateStr()
					.getBytes());

			// In order to parse the certificates public key we
			// must try both
			// ECPublicKey of RSAPublicKey because at this point
			// we have not have a
			// better way to do it
			try {
				// First try with ECPublic key parse, if returns
				// an error, try
				// with RSAPublicKey parser
				ECPublicKey pubKey = ECPublicKey.parse(cert.getPublicKey());

				// If the public key is EC, ask for the EC private key of the
				// sender

				// Decode the key and encrypt

			} catch (CryptoUtilsException e) {
				try {
					// Try to parse the public key as RSAPublicKey
					RSAPublicKey pubKey = RSAPublicKey.parse(cert
							.getPublicKey());

					// Get the message and encrypt it
				} catch (CryptoUtilsException e2) {
					// If the key could no be decoded, show a toast and
					// return the previews activity
					Toast.makeText(getApplicationContext(),
							R.string.error_cert_key_decode, Toast.LENGTH_LONG)
							.show();

					return;

				}

			}

		} catch (CryptoUtilsException e1) {
			Toast.makeText(getApplicationContext(), R.string.error_cert_decode,
					Toast.LENGTH_LONG).show();
			return;
		}

	}

	/**
	 * A {@link android.support.v4.app.FragmentStatePagerAdapter} that returns a
	 * fragment pager that will contains two pages, one for basic key
	 * information and the other for advanced key information.
	 */
	protected class SecureOperationCollectionPagerAdapter extends
			FragmentStatePagerAdapter {

		SecureOperationFileFragment fragmentFile;
		SecureOperationMessageFragment fragmentMessage;
		Boolean update;
		private final FragmentManager mFragmentManager;

		protected static final int FILE_PAGE = 0;
		protected static final int MESSAGE_PAGE = 1;

		public SecureOperationCollectionPagerAdapter(FragmentManager fm) {
			super(fm);
			mFragmentManager = fm;
		}

		/**
		 * @return the fragmentFile
		 */
		public SecureOperationFileFragment getFragmentFile() {
			return fragmentFile;
		}

		/**
		 * @return the fragmentMessage
		 */
		public SecureOperationMessageFragment getFragmentMessage() {
			return fragmentMessage;
		}

		@Override
		public Fragment getItem(int i) {
			update = Boolean.FALSE;
			Log.i(PKITrustNetworkActivity.TAG, "GET ITEM [" + i + "]");
			String initialInput = existingInput;
			// Chose between the two availably: Owner or key
			switch (i) {
			case FILE_PAGE:

				if (fragmentFile == null) {
					if (selectedInput != FILE_PAGE) {
						initialInput = "";
					}
					fragmentFile = SecureOperationFileFragment.newInstance(
							FILE_PAGE, initialInput, existingOutputFile,
							selectedOperation, selectedPrivateKeySignTxt,
							selectedPrivateKeyDecipherTxt,
							selectedCertificateCipherTxt,
							selectedCertificateVerifyTxt);
				}
				return fragmentFile;

			case MESSAGE_PAGE:
				if (fragmentMessage == null) {
					if (selectedInput != MESSAGE_PAGE) {
						initialInput = "";
					}
					fragmentMessage = SecureOperationMessageFragment
							.newInstance(MESSAGE_PAGE, initialInput,
									selectedOperation,
									selectedPrivateKeySignTxt,
									selectedPrivateKeyDecipherTxt,
									selectedCertificateCipherTxt,
									selectedCertificateVerifyTxt);
				}
				return fragmentMessage;

			}

			return new SecureOperationFileFragment();
		}

		@Override
		public int getCount() {
			// Get the count of personal Keys
			return 2;
		}

		@Override
		public CharSequence getPageTitle(int position) {
			switch (position) {
			case FILE_PAGE:
				return getResources().getString(
						R.string.detail_title_secure_file);
			case MESSAGE_PAGE:
				return getResources().getString(
						R.string.detail_title_secure_message);
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

			if (update)
				return POSITION_NONE;
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
			update = Boolean.TRUE;

			if (state != null) {
				Bundle bundle = (Bundle) state;
				Iterable<String> keys = bundle.keySet();
				for (String key : keys) {
					if (key.startsWith("f")) {
						Fragment f = mFragmentManager.getFragment(bundle, key);
						if (f instanceof SecureOperationFileFragment) {
							fragmentFile = (SecureOperationFileFragment) f;
						} else if (f instanceof SecureOperationMessageFragment) {
							fragmentMessage = (SecureOperationMessageFragment) f;
						}

					}
				}
			}
			this.notifyDataSetChanged();
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.pki.android.trustednetwork.crypto.SecureOperationOptionsFragment
	 * .OnClickSearchElementsListener#onPrivateKeySignClick()
	 */
	@Override
	public void onPrivateKeySignClick() {

		// Select Holder intent
		Intent intent;
		intent = new Intent(this, SelectHolderWithKeysActivity.class);

		intent.putExtra(PKITrustNetworkActivity.EXTRA_NEXT_OPERATION,
				PKITrustNetworkActivity.SIGN);

		startActivityWithIntentExtras(intent);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.pki.android.trustednetwork.crypto.SecureOperationOptionsFragment
	 * .OnClickSearchElementsListener#onPrivateKeyDecipherClick()
	 */
	@Override
	public void onPrivateKeyDecipherClick() {
		// Select Holder intent
		Intent intent;
		intent = new Intent(this, SelectHolderWithKeysActivity.class);

		intent.putExtra(PKITrustNetworkActivity.EXTRA_NEXT_OPERATION,
				PKITrustNetworkActivity.DECIPHER);

		startActivityWithIntentExtras(intent);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.pki.android.trustednetwork.crypto.SecureOperationOptionsFragment
	 * .OnClickSearchElementsListener#onCertificateVerify()
	 */
	@Override
	public void onCertificateVerify() {
		// Select Holder intent
		Intent intent;
		intent = new Intent(this, SelectHolderWithCertificateActivity.class);

		intent.putExtra(PKITrustNetworkActivity.EXTRA_NEXT_OPERATION,
				PKITrustNetworkActivity.VERIFY);
		startActivityWithIntentExtras(intent);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.pki.android.trustednetwork.crypto.SecureOperationOptionsFragment
	 * .OnClickSearchElementsListener#onCertificateCipher()
	 */
	@Override
	public void onCertificateCipher() {
		// Select Holder intent
		Intent intent;
		intent = new Intent(this, SelectHolderWithCertificateActivity.class);

		intent.putExtra(PKITrustNetworkActivity.EXTRA_NEXT_OPERATION,
				PKITrustNetworkActivity.CIPHER);

		startActivityWithIntentExtras(intent);

	}

	/**
	 * Set common intent extras parameters and start the corresponding activity
	 * 
	 * @param intent
	 *            Intent containing the activity to be started and particular
	 *            intent extras
	 */
	protected void startActivityWithIntentExtras(Intent intent) {
		intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION, currentOption);
		intent.putExtra(SELECTED_CERTIFICATE_CIPHER, selectedCertificateCipher);
		intent.putExtra(SELECTED_CERTIFICATE_VERIFY, selectedCertificateVerify);
		intent.putExtra(SELECTED_PRIVATE_KEY_DECIPHER,
				selectedPrivateKeyDecipher);
		intent.putExtra(SELECTED_PRIVATE_KEY_SIGN, selectedPrivateKeySign);
		int currentView = mViewPager.getCurrentItem();
		intent.putExtra(SELECTED_INPUT, currentView);
		if (currentView == SecureOperationCollectionPagerAdapter.FILE_PAGE) {
			if (txtFileName == null) {
				txtFileName = (TextView) mCollectionPagerAdapter
						.getFragmentFile().getSelectFileFragment().getView()
						.findViewById(R.id.txtFileName);
			}

			if (txtOutputFileName == null) {
				txtOutputFileName = (TextView) mCollectionPagerAdapter
						.getFragmentFile().getSelectOutputFileFragment()
						.getView().findViewById(R.id.txtFileName);
			}
			intent.putExtra(EXISTING_INPUT, txtFileName.getText().toString());
			intent.putExtra(EXISTING_OUTPUT_FILE, txtOutputFileName.getText()
					.toString());
			intent.putExtra(SELECTED_OPERATION,
					((Spinner) mCollectionPagerAdapter.getFragmentFile()
							.getView().findViewById(R.id.spinnerOperation))
							.getSelectedItemPosition());
		} else {
			if (txtMessage == null) {
				txtMessage = (TextView) mCollectionPagerAdapter
						.getFragmentMessage().getView()
						.findViewById(R.id.txtMessage);
			}
			intent.putExtra(EXISTING_INPUT, txtMessage.getText().toString());
			intent.putExtra(SELECTED_OPERATION,
					((Spinner) mCollectionPagerAdapter.getFragmentMessage()
							.getView().findViewById(R.id.spinnerOperation))
							.getSelectedItemPosition());
		}

		intent.setFlags(Intent.FLAG_ACTIVITY_NO_HISTORY);
		startActivity(intent);

	}

	/**
	 * Implements the OnPositiveButtonClickListener for sign operation, after
	 * the password dialog is shown, this function is called
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 14/09/2012
	 * @version 1.0
	 */
	public class OnPositiveButtonClickListenerSignImp implements
			OnPositiveButtonClickListener {
		Boolean chkCipher;
		Boolean chkDelete;

		public OnPositiveButtonClickListenerSignImp(Boolean chkCipher) {
			this.chkCipher = chkCipher;
			// this.chkDelete = chkDelete;
		}

		/**
		 * @return the chkCipher
		 */
		public Boolean getChkCipher() {
			return chkCipher;
		}

		/**
		 * @param chkCipher
		 *            the chkCipher to set
		 */
		public void setChkCipher(Boolean chkCipher) {
			this.chkCipher = chkCipher;
		}

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
			// If the operation include sign, the private key should be decoded,
			// if no exception is thrown, it means that the inserted password
			// is OK, so the operation process should continue, if the password
			// is wrong cancel the operation
			if (encryptSignEncryptTask == null
					|| !encryptSignEncryptTask.getStatus().equals(
							AsyncTask.Status.RUNNING)) {
				encryptSignEncryptTask = new EncryptSignEncryptTask();

			} else {
				Toast.makeText(getApplicationContext(), R.string.msgWorking,
						Toast.LENGTH_SHORT).show();
				return;
			}

			try {
				int currentView = mViewPager.getCurrentItem();
				byte[] bytes = null;
				if (currentView == SecureOperationCollectionPagerAdapter.FILE_PAGE) {
					// Read the file and the its bytes
					File f = new File(txtFileName.getText().toString());
					FileInputStream fis = new FileInputStream(f);
					ByteArrayOutputStream bos = new ByteArrayOutputStream();
					byte[] b = new byte[1024];
					int bytesRead;
					while ((bytesRead = fis.read(b)) != -1) {
						bos.write(b, 0, bytesRead);
					}
					fis.close();
					bytes = bos.toByteArray();
				}

				// if both sign and cipher are selected perform
				// Encrypt/Sign/Encrypt
				if (chkCipher) {

					// Decode the certificate
					X509Certificate cert;

					cert = x509Utils.decode(certificateCipher
							.getCertificateStr().getBytes());

					// In order to parse the certificates public key we
					// must try both
					// ECPublicKey of RSAPublicKey because at this point
					// we have not have a
					// better way to do it
					try {
						// First try with ECPublic key parse, if returns
						// an error, try
						// with RSAPublicKey parser
						ECPublicKey pubKey = ECPublicKey.parse(cert
								.getPublicKey());

						// If the public key is EC, the private key must be a
						// private EC key
						if (!key.getKeyType().equals(PersonalKeyDAO.PRIVATE_EC)) {
							Toast.makeText(getApplicationContext(),
									R.string.error_crypto_cipher_ec,
									Toast.LENGTH_LONG).show();
							return;
						}

						try {
							// If the key is a private EC key
							ECPrivateKey privateKey = ECPrivateKey.decode(key
									.getKeyStr().getBytes(), passwordKey);

							// Check if we are at message or file page
							if (currentView == SecureOperationCollectionPagerAdapter.FILE_PAGE) {
								// File page
								// Encrypts the file bytes
								encryptSignEncryptTask.execute(bytes,
										privateKey, pubKey);
							} else {
								// Message Page
								encryptSignEncryptTask.execute(txtMessage
										.getText().toString(), privateKey,
										pubKey);
							}

						} catch (CryptoUtilsException e) {
							// If the key could no be decoded, show a toast and
							// return the previews activity
							Toast.makeText(getApplicationContext(),
									R.string.error_db_load_key_password,
									Toast.LENGTH_LONG).show();
							return;
						}

					} catch (CryptoUtilsException e) {
						try {
							// Try to parse the public key as RSAPublicKey
							RSAPublicKey pubKey = RSAPublicKey.parse(cert
									.getPublicKey());
							try {
								if (key.getKeyType().equals(
										PersonalKeyDAO.PRIVATE_EC)) {
									// If the key is a private EC key
									ECPrivateKey privateKey = ECPrivateKey
											.decode(key.getKeyStr().getBytes(),
													passwordKey);

									// Check if we are at message or file page
									if (currentView == SecureOperationCollectionPagerAdapter.FILE_PAGE) {
										// File page
										// Encrypts the file bytes
										encryptSignEncryptTask.execute(bytes,
												privateKey, pubKey);
									} else {
										// Message Page
										// Get the message and encrypt it
										encryptSignEncryptTask
												.execute(txtMessage.getText()
														.toString(),
														privateKey, pubKey);
									}
								} else {
									// If the key is a private RSA key
									RSAPrivateKey privateKey = RSAPrivateKey
											.decode(key.getKeyStr().getBytes(),
													passwordKey);

									// Check if we are at message or file page
									if (currentView == SecureOperationCollectionPagerAdapter.FILE_PAGE) {
										// File page
										// Encrypts the file bytes
										encryptSignEncryptTask.execute(bytes,
												privateKey, pubKey);
									} else {
										// Message Page
										// Get the message and encrypt it
										encryptSignEncryptTask
												.execute(txtMessage.getText()
														.toString(),
														privateKey, pubKey);
									}
								}
							} catch (CryptoUtilsException e2) {
								// If the key could no be decoded, show a toast
								// and
								// return the previews activity
								Toast.makeText(getApplicationContext(),
										R.string.error_db_load_key_password,
										Toast.LENGTH_LONG).show();
								return;
							}
						} catch (CryptoUtilsException e2) {
							// If the key could no be decoded, show a toast and
							// return the previews activity
							Toast.makeText(getApplicationContext(),
									R.string.error_cert_key_decode,
									Toast.LENGTH_LONG).show();

							return;

						}

					}

				} else {
					// If only sign is required... sign the message
				}

			} catch (CryptoUtilsException e1) {
				Toast.makeText(getApplicationContext(),
						R.string.error_cert_decode, Toast.LENGTH_LONG).show();
				return;
			} catch (FileNotFoundException e) {
				// The code will never reach this point because at
				// the beginning of the process we validate that the
				// file exists
				e.printStackTrace();
			} catch (IOException e) {
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e.getCause());
				Toast.makeText(getApplicationContext(),
						R.string.error_read_file, Toast.LENGTH_LONG).show();
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

			// If the operation include sign, the private key should be decoded,
			// if no exception is thrown, it means that the inserted password
			// is OK, so the operation process should continue, if the password
			// is wrong cancel the operation
			if (encryptSignEncryptTask == null
					|| !encryptSignEncryptTask.getStatus().equals(
							AsyncTask.Status.RUNNING)) {
				encryptSignEncryptTask = new EncryptSignEncryptTask();

			} else {
				Toast.makeText(getApplicationContext(), R.string.msgWorking,
						Toast.LENGTH_SHORT).show();
				return;
			}

			try {
				int currentView = mViewPager.getCurrentItem();
				byte[] bytes = null;
				if (currentView == SecureOperationCollectionPagerAdapter.FILE_PAGE) {
					// Read the file and the its bytes
					File f = new File(txtFileName.getText().toString());
					FileInputStream fis = new FileInputStream(f);
					ByteArrayOutputStream bos = new ByteArrayOutputStream();
					byte[] b = new byte[1024];
					int bytesRead;
					while ((bytesRead = fis.read(b)) != -1) {
						bos.write(b, 0, bytesRead);
					}
					fis.close();
					bytes = bos.toByteArray();
				}
				// if both sign and cipher are selected perform
				// Encrypt/Sign/Encrypt
				if (chkCipher) {

					// Decode the certificate
					X509Certificate cert;

					cert = x509Utils.decode(certificateCipher
							.getCertificateStr().getBytes());

					// In order to parse the certificates public key we
					// must try both
					// ECPublicKey of RSAPublicKey because at this point
					// we have not have a
					// better way to do it
					try {
						// First try with ECPublic key parse, if returns
						// an error, try
						// with RSAPublicKey parser
						ECPublicKey pubKey = ECPublicKey.parse(cert
								.getPublicKey());

						// If the public key is EC, the private key must be a
						// private EC key
						if (!key.getKeyType().equals(PersonalKeyDAO.PKCS12_EC)) {
							Toast.makeText(getApplicationContext(),
									R.string.error_crypto_cipher_ec,
									Toast.LENGTH_LONG).show();
							return;
						}

						try {
							// If the key is a PKCS EC key
							Object[] ecKeyPair = ECKeyPair.decodePKCS12(key
									.getKeyStr().getBytes(), passwordPKCS,
									passwordKey);

							// Check if we are at message or file page
							if (currentView == SecureOperationCollectionPagerAdapter.FILE_PAGE) {
								// File page
								// Encrypts the file bytes
								encryptSignEncryptTask.execute(bytes,
										((ECKeyPair) ecKeyPair[0])
												.getPrivateKey(), pubKey);
							} else {
								// Message Page
								// Get the message and encrypt it
								encryptSignEncryptTask.execute(txtMessage
										.getText().toString(),
										((ECKeyPair) ecKeyPair[0])
												.getPrivateKey(), pubKey);
							}
						} catch (CryptoUtilsException e) {
							// If the key could no be decoded, show a toast and
							// return the previews activity
							Toast.makeText(getApplicationContext(),
									R.string.error_db_load_key_password,
									Toast.LENGTH_LONG).show();
							return;
						}

					} catch (CryptoUtilsException e) {
						try {
							// Try to parse the public key as RSAPublicKey
							RSAPublicKey pubKey = RSAPublicKey.parse(cert
									.getPublicKey());
							try {
								if (key.getKeyType().equals(
										PersonalKeyDAO.PKCS12_EC)) {
									// If the key is a PKCS EC key
									Object[] ecKeyPair = ECKeyPair
											.decodePKCS12(key.getKeyStr()
													.getBytes(), passwordPKCS,
													passwordKey);

									// Check if we are at message or file page
									if (currentView == SecureOperationCollectionPagerAdapter.FILE_PAGE) {
										// File page
										// Encrypts the file bytes
										encryptSignEncryptTask.execute(bytes,
												((ECKeyPair) ecKeyPair[0])
														.getPrivateKey(),
												pubKey);
									} else {
										// Message Page
										// Get the message and encrypt it
										encryptSignEncryptTask
												.execute(
														txtMessage.getText()
																.toString(),
														((ECKeyPair) ecKeyPair[0])
																.getPrivateKey(),
														pubKey);
									}

								} else {
									// If the key is a PKCS RSA key
									Object[] rsaKeyPair = RSAKeyPair
											.decodePKCS12(key.getKeyStr()
													.getBytes(), passwordPKCS,
													passwordKey);

									// Check if we are at message or file page
									if (currentView == SecureOperationCollectionPagerAdapter.FILE_PAGE) {
										// File page
										// Encrypts the file bytes
										encryptSignEncryptTask.execute(bytes,
												((RSAKeyPair) rsaKeyPair[0])
														.getPrivateKey(),
												pubKey);
									} else {
										// Message Page
										// Get the message and encrypt it
										encryptSignEncryptTask
												.execute(
														txtMessage.getText()
																.toString(),
														((RSAKeyPair) rsaKeyPair[0])
																.getPrivateKey(),
														pubKey);
									}

								}
							} catch (CryptoUtilsException e2) {
								// If the key could no be decoded, show a toast
								// and
								// return the previews activity
								Toast.makeText(getApplicationContext(),
										R.string.error_db_load_key_password,
										Toast.LENGTH_LONG).show();
								return;
							}
						} catch (CryptoUtilsException e2) {
							// If the key could no be decoded, show a toast and
							// return the previews activity
							Toast.makeText(getApplicationContext(),
									R.string.error_cert_key_decode,
									Toast.LENGTH_LONG).show();

							return;

						}

					}

				} else {
					// If only sign is required... sign the message
				}

			} catch (CryptoUtilsException e1) {
				Toast.makeText(getApplicationContext(),
						R.string.error_cert_decode, Toast.LENGTH_LONG).show();
				return;
			} catch (FileNotFoundException e) {
				// The code will never reach this point because at
				// the beginning of the process we validate that the
				// file exists
				e.printStackTrace();
			} catch (IOException e) {
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e.getCause());
				Toast.makeText(getApplicationContext(),
						R.string.error_read_file, Toast.LENGTH_LONG).show();
				return;
			}

		}
	}

	/**
	 * Implements the OnPositiveButtonClickListener for verify operation, after
	 * the password dialog is shown, this function is called
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 14/09/2012
	 * @version 1.0
	 */
	public class OnPositiveButtonClickListenerDecipherImp implements
			OnPositiveButtonClickListener {
		Boolean chkVerify;
		Boolean chkDelete;

		public OnPositiveButtonClickListenerDecipherImp(Boolean chkVerify) {
			this.chkVerify = chkVerify;
			// this.chkDelete = chkDelete;
		}

		/**
		 * @return the chkVerify
		 */
		public Boolean getChkVerify() {
			return chkVerify;
		}

		/**
		 * @param chkVerify
		 *            the chkVerify to set
		 */
		public void setChkVerify(Boolean chkVerify) {
			this.chkVerify = chkVerify;
		}

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
			// If the operation include sign, the private key should be decoded,
			// if no exception is thrown, it means that the inserted password
			// is OK, so the operation process should continue, if the password
			// is wrong cancel the operation
			if (decryptVerifyDecryptTask == null
					|| !decryptVerifyDecryptTask.getStatus().equals(
							AsyncTask.Status.RUNNING)) {
				decryptVerifyDecryptTask = new DecryptVerifyDecryptTask();

			} else {
				Toast.makeText(getApplicationContext(), R.string.msgWorking,
						Toast.LENGTH_SHORT).show();
				return;
			}

			try {
				int currentView = mViewPager.getCurrentItem();
				byte[] bytes = null;
				if (currentView == SecureOperationCollectionPagerAdapter.FILE_PAGE) {
					// Read the file and the its bytes

					File f = new File(txtFileName.getText().toString());
					FileInputStream fis = new FileInputStream(f);

					ByteArrayOutputStream bos = new ByteArrayOutputStream();
					byte[] b = new byte[1024];
					int bytesRead;
					while ((bytesRead = fis.read(b)) != -1) {
						bos.write(b, 0, bytesRead);
					}
					fis.close();
					bytes = bos.toByteArray();

				}

				// if both Verify and decipher are selected perform
				// Decrypt/Verify/Decrypt
				if (chkVerify) {

					// Decode the certificate
					X509Certificate cert;

					cert = x509Utils.decode(certificateVerify
							.getCertificateStr().getBytes());

					// In order to parse the certificates public key we
					// must try both
					// ECPublicKey of RSAPublicKey because at this point
					// we have not have a
					// better way to do it
					try {
						// First try with ECPublic key parse, if returns
						// an error, try
						// with RSAPublicKey parser
						ECPublicKey pubKey = ECPublicKey.parse(cert
								.getPublicKey());

						try {
							if (key.getKeyType().equals(
									PersonalKeyDAO.PRIVATE_EC)) {
								// If the key is a private EC key
								ECPrivateKey privateKey = ECPrivateKey
										.decode(key.getKeyStr().getBytes(),
												passwordKey);

								// Check if we are at message or file page
								if (currentView == SecureOperationCollectionPagerAdapter.FILE_PAGE) {
									// File page
									// Encrypts the file bytes
									decryptVerifyDecryptTask.execute(bytes,
											privateKey, pubKey);
								} else {
									// Message Page
									// Get the message and decrypt it
									decryptVerifyDecryptTask.execute(txtMessage
											.getText().toString(), privateKey,
											pubKey);
								}

							} else {
								// If the key is a private RSA key
								RSAPrivateKey privateKey = RSAPrivateKey
										.decode(key.getKeyStr().getBytes(),
												passwordKey);

								// Check if we are at message or file page
								if (currentView == SecureOperationCollectionPagerAdapter.FILE_PAGE) {
									// File page
									// Encrypts the file bytes
									decryptVerifyDecryptTask.execute(bytes,
											privateKey, pubKey);
								} else {
									// Message Page
									// Get the message and decrypt it
									decryptVerifyDecryptTask.execute(txtMessage
											.getText().toString(), privateKey,
											pubKey);
								}

							}
						} catch (CryptoUtilsException e) {
							// If the key could no be decoded, show a toast and
							// return the previews activity
							Toast.makeText(getApplicationContext(),
									R.string.error_db_load_key_password,
									Toast.LENGTH_LONG).show();
							return;
						}

					} catch (CryptoUtilsException e) {
						try {
							// Try to parse the public key as RSAPublicKey
							RSAPublicKey pubKey = RSAPublicKey.parse(cert
									.getPublicKey());
							try {
								if (key.getKeyType().equals(
										PersonalKeyDAO.PRIVATE_EC)) {
									// If the private key is EC the public key
									// must be also for EC, if not show a
									// message
									Toast.makeText(getApplicationContext(),
											R.string.error_crypto_decipher_ec,
											Toast.LENGTH_LONG).show();
									return;

								} else {
									// If the key is a private RSA key
									RSAPrivateKey privateKey = RSAPrivateKey
											.decode(key.getKeyStr().getBytes(),
													passwordKey);

									// Check if we are at message or file page
									if (currentView == SecureOperationCollectionPagerAdapter.FILE_PAGE) {
										// File page
										// Encrypts the file bytes
										decryptVerifyDecryptTask.execute(bytes,
												privateKey, pubKey);
									} else {
										// Message Page
										// Get the message and decrypt it
										decryptVerifyDecryptTask
												.execute(txtMessage.getText()
														.toString(),
														privateKey, pubKey);
									}

								}
							} catch (CryptoUtilsException e2) {
								// If the key could no be decoded, show a toast
								// and
								// return the previews activity
								Toast.makeText(getApplicationContext(),
										R.string.error_db_load_key_password,
										Toast.LENGTH_LONG).show();
								return;
							}
						} catch (CryptoUtilsException e2) {
							// If the key could no be decoded, show a toast and
							// return the previews activity
							Toast.makeText(getApplicationContext(),
									R.string.error_cert_key_decode,
									Toast.LENGTH_LONG).show();

							return;

						}

					}

				} else {
					// If only decipher is required... decipher the message
				}

			} catch (CryptoUtilsException e1) {
				Toast.makeText(getApplicationContext(),
						R.string.error_cert_decode, Toast.LENGTH_LONG).show();
				return;
			} catch (FileNotFoundException e) {
				// The code will never reach this point because at
				// the beginning of the process we validate that the
				// file exists
				e.printStackTrace();
			} catch (IOException e) {
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e.getCause());
				Toast.makeText(getApplicationContext(),
						R.string.error_read_file, Toast.LENGTH_LONG).show();
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
			// If the operation include sign, the private key should be decoded,
			// if no exception is thrown, it means that the inserted password
			// is OK, so the operation process should continue, if the password
			// is wrong cancel the operation
			if (decryptVerifyDecryptTask == null
					|| !decryptVerifyDecryptTask.getStatus().equals(
							AsyncTask.Status.RUNNING)) {
				decryptVerifyDecryptTask = new DecryptVerifyDecryptTask();

			} else {
				Toast.makeText(getApplicationContext(), R.string.msgWorking,
						Toast.LENGTH_SHORT).show();
				return;
			}

			try {
				int currentView = mViewPager.getCurrentItem();

				byte[] bytes = null;
				if (currentView == SecureOperationCollectionPagerAdapter.FILE_PAGE) {
					// Read the file and the its bytes

					File f = new File(txtFileName.getText().toString());
					FileInputStream fis = new FileInputStream(f);

					ByteArrayOutputStream bos = new ByteArrayOutputStream();
					byte[] b = new byte[1024];
					int bytesRead;
					while ((bytesRead = fis.read(b)) != -1) {
						bos.write(b, 0, bytesRead);
					}
					fis.close();
					bytes = bos.toByteArray();

				}

				// if both Verify and decipher are selected perform
				// Decrypt/Verify/Decrypt
				if (chkVerify) {

					// Decode the certificate
					X509Certificate cert;

					cert = x509Utils.decode(certificateVerify
							.getCertificateStr().getBytes());

					// In order to parse the certificates public key we
					// must try both
					// ECPublicKey of RSAPublicKey because at this point
					// we have not have a
					// better way to do it
					try {
						// First try with ECPublic key parse, if returns
						// an error, try
						// with RSAPublicKey parser
						ECPublicKey pubKey = ECPublicKey.parse(cert
								.getPublicKey());

						try {
							if (key.getKeyType().equals(
									PersonalKeyDAO.PKCS12_EC)) {
								// If the key is a private EC key
								Object[] ecKeyPair = ECKeyPair.decodePKCS12(key
										.getKeyStr().getBytes(), passwordPKCS,
										passwordKey);

								// Check if we are at message or file page
								if (currentView == SecureOperationCollectionPagerAdapter.FILE_PAGE) {
									// File page
									// Encrypts the file bytes
									decryptVerifyDecryptTask.execute(bytes,
											((ECKeyPair) ecKeyPair[0])
													.getPrivateKey(), pubKey);
								} else {
									// Message Page
									// Get the message and decrypt it
									decryptVerifyDecryptTask.execute(txtMessage
											.getText().toString(),
											((ECKeyPair) ecKeyPair[0])
													.getPrivateKey(), pubKey);
								}

							} else {
								// If the key is a private RSA key
								Object[] rsaKeyPair = RSAKeyPair.decodePKCS12(
										key.getKeyStr().getBytes(),
										passwordPKCS, passwordKey);
								// Check if we are at message or file page
								if (currentView == SecureOperationCollectionPagerAdapter.FILE_PAGE) {
									// File page
									// Encrypts the file bytes
									decryptVerifyDecryptTask.execute(bytes,
											((RSAKeyPair) rsaKeyPair[0])
													.getPrivateKey(), pubKey);
								} else {
									// Message Page
									// Get the message and decrypt it
									decryptVerifyDecryptTask.execute(txtMessage
											.getText().toString(),
											((RSAKeyPair) rsaKeyPair[0])
													.getPrivateKey(), pubKey);
								}
							}
						} catch (CryptoUtilsException e) {
							// If the key could no be decoded, show a toast and
							// return the previews activity
							Toast.makeText(getApplicationContext(),
									R.string.error_db_load_key_password,
									Toast.LENGTH_LONG).show();
							return;
						}

					} catch (CryptoUtilsException e) {
						try {
							// Try to parse the public key as RSAPublicKey
							RSAPublicKey pubKey = RSAPublicKey.parse(cert
									.getPublicKey());
							try {
								if (key.getKeyType().equals(
										PersonalKeyDAO.PKCS12_EC)) {
									// If the private key is EC the public key
									// must be also for EC, if not show a
									// message
									Toast.makeText(getApplicationContext(),
											R.string.error_crypto_decipher_ec,
											Toast.LENGTH_LONG).show();
									return;

								} else {
									// If the key is a private RSA key
									Object[] rsaKeyPair = RSAKeyPair
											.decodePKCS12(key.getKeyStr()
													.getBytes(), passwordPKCS,
													passwordKey);
									// Check if we are at message or file page
									if (currentView == SecureOperationCollectionPagerAdapter.FILE_PAGE) {
										// File page
										// Encrypts the file bytes
										decryptVerifyDecryptTask.execute(bytes,
												((RSAKeyPair) rsaKeyPair[0])
														.getPrivateKey(),
												pubKey);
									} else {
										// Message Page
										// Get the message and decrypt it
										decryptVerifyDecryptTask
												.execute(
														txtMessage.getText()
																.toString(),
														((RSAKeyPair) rsaKeyPair[0])
																.getPrivateKey(),
														pubKey);
									}
								}
							} catch (CryptoUtilsException e2) {
								// If the key could no be decoded, show a toast
								// and
								// return the previews activity
								Toast.makeText(getApplicationContext(),
										R.string.error_db_load_key_password,
										Toast.LENGTH_LONG).show();
								return;
							}
						} catch (CryptoUtilsException e2) {
							// If the key could no be decoded, show a toast and
							// return the previews activity
							Toast.makeText(getApplicationContext(),
									R.string.error_cert_key_decode,
									Toast.LENGTH_LONG).show();

							return;

						}

					}

				} else {
					// If only decipher is required... decipher the message
				}

			} catch (CryptoUtilsException e1) {
				Toast.makeText(getApplicationContext(),
						R.string.error_cert_decode, Toast.LENGTH_LONG).show();
				return;
			} catch (FileNotFoundException e) {
				// The code will never reach this point because at
				// the beginning of the process we validate that the
				// file exists
				e.printStackTrace();
			} catch (IOException e) {
				Log.e(PKITrustNetworkActivity.TAG, e.getMessage(), e.getCause());
				Toast.makeText(getApplicationContext(),
						R.string.error_read_file, Toast.LENGTH_LONG).show();
				return;
			}

		}
	}

	/**
	 * Inner class that create an asynchronous task in which is performed the
	 * Encrypt/Sign/Encrypt operation using the selected parameters, for
	 * execution the parameters must be sent in the correct order: Message,
	 * PrivateKey, PublicKey
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class EncryptSignEncryptTask extends
			AsyncTask<Object, Void, List<String>> {

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
		protected List<String> doInBackground(Object... params) {

			if (params.length != 3) {
				return null;
			}

			// Check if the first parameter is a string a message or byte array
			if (!(params[0] instanceof String || params[0] instanceof byte[])) {
				return null;
			}

			// Check if the second parameter is a private key
			if (!(params[1] instanceof RSAPrivateKey
					|| params[1] instanceof ECPrivateKey
					|| params[1] instanceof RSAKeyPair || params[1] instanceof ECKeyPair)) {
				return null;
			}

			// Check if the third parameter is a public key
			if (!(params[2] instanceof RSAPublicKey || params[2] instanceof ECPublicKey)) {
				return null;
			}

			try {
				// If the message is a string or a byte array
				if (params[0] instanceof String) {
					String message = (String) params[0];
					// Check if the public key is RSA or EC
					if (params[2] instanceof RSAPublicKey) {
						RSAPublicKey publicKey = (RSAPublicKey) params[2];
						List<String> resEncrypt = asymmetricCryptoUtils
								.encrypt(message, publicKey);

						String sign = "";
						BigInteger ecSign[];
						// Verify the type of the Private key
						if (params[1] instanceof RSAPrivateKey) {
							RSAPrivateKey privateKey = (RSAPrivateKey) params[1];
							sign = asymmetricCryptoUtils.sign(message,
									privateKey);
						}

						if (params[1] instanceof ECPrivateKey) {

							ECPrivateKey privateKey = (ECPrivateKey) params[1];
							ecSign = asymmetricCryptoUtils.sign(message,
									privateKey);
							// Parse the EC sign to string using ',' as
							// separator
							sign = ecSign[0].toString(16) + ","
									+ ecSign[1].toString(16);
						}

						if (params[1] instanceof RSAKeyPair) {
							RSAKeyPair keyPair = (RSAKeyPair) params[1];
							sign = asymmetricCryptoUtils.sign(message,
									keyPair.getPrivateKey());
						}

						if (params[1] instanceof ECKeyPair) {
							ECKeyPair keyPair = (ECKeyPair) params[1];
							ecSign = asymmetricCryptoUtils.sign(message,
									keyPair.getPrivateKey());
							// Parse the EC sign to string using ',' as
							// separator
							sign = ecSign[0].toString(16) + ","
									+ ecSign[1].toString(16);
						}

						// Create a resEncrypt string using the encrypted
						// message and the session key
						String resEncryptStr = resEncrypt.get(0) + " , "
								+ resEncrypt.get(1);

						// Encrypts again the resulting message with the sign of
						// the message using ';' for separating the
						// encrypted message and the signature
						String finalMessage = resEncryptStr + " ; " + sign;
						return asymmetricCryptoUtils.encrypt(finalMessage,
								publicKey);

					}

					// For ECPublic key
					if (params[2] instanceof ECPublicKey) {
						ECPublicKey publicKey = (ECPublicKey) params[2];

						String sign = "";
						BigInteger ecSign[];
						List<String> resEncrypt;
						if (params[1] instanceof ECPrivateKey) {

							ECPrivateKey privateKey = (ECPrivateKey) params[1];

							resEncrypt = asymmetricCryptoUtils.encrypt(message,
									publicKey, privateKey);

							ecSign = asymmetricCryptoUtils.sign(message,
									privateKey);
							// Parse the EC sign to string using ',' as
							// separator
							sign = ecSign[0].toString(16) + ","
									+ ecSign[1].toString(16);

							// Create a resEncrypt string using the encrypted
							// message and the session key
							String resEncryptStr = resEncrypt.get(0) + " , "
									+ resEncrypt.get(1);

							// Encrypts again the resulting message with the
							// sign of
							// the message using ';' for separating the
							// encrypted message and the signature
							String finalMessage = resEncryptStr + " ; " + sign;
							return asymmetricCryptoUtils.encrypt(finalMessage,
									publicKey, privateKey);
						} else {
							ECKeyPair keyPair = (ECKeyPair) params[1];

							resEncrypt = asymmetricCryptoUtils.encrypt(message,
									publicKey, keyPair.getPrivateKey());

							ecSign = asymmetricCryptoUtils.sign(message,
									keyPair.getPrivateKey());
							// Parse the EC sign to string using ',' as
							// separator
							sign = ecSign[0].toString(16) + ","
									+ ecSign[1].toString(16);

							// Create a resEncrypt string using the encrypted
							// message and the session key
							String resEncryptStr = resEncrypt.get(0) + " , "
									+ resEncrypt.get(1);

							// Encrypts again the resulting message with the
							// sign of
							// the message using ';' for separating the
							// encrypted message and the signature
							String finalMessage = resEncryptStr + " ; " + sign;
							return asymmetricCryptoUtils.encrypt(finalMessage,
									publicKey, keyPair.getPrivateKey());
						}

					}

				} else {
					byte[] message = (byte[]) params[0];
					// Check if the public key is RSA or EC
					if (params[2] instanceof RSAPublicKey) {
						RSAPublicKey publicKey = (RSAPublicKey) params[2];
						List<byte[]> resEncrypt = asymmetricCryptoUtils
								.encrypt(message, publicKey);

						String sign = "";
						BigInteger ecSign[];
						// Verify the type of the Private key
						if (params[1] instanceof RSAPrivateKey) {
							RSAPrivateKey privateKey = (RSAPrivateKey) params[1];
							sign = new String(
									Base64.encode(asymmetricCryptoUtils.sign(
											message, privateKey)));
						}

						if (params[1] instanceof ECPrivateKey) {

							ECPrivateKey privateKey = (ECPrivateKey) params[1];
							ecSign = asymmetricCryptoUtils.sign(message,
									privateKey);
							// Parse the EC sign to string using ',' as
							// separator
							sign = ecSign[0].toString(16) + ","
									+ ecSign[1].toString(16);

						}

						if (params[1] instanceof RSAKeyPair) {
							RSAKeyPair keyPair = (RSAKeyPair) params[1];
							sign = new String(
									Base64.encode(asymmetricCryptoUtils.sign(
											message, keyPair.getPrivateKey())));
						}

						if (params[1] instanceof ECKeyPair) {
							ECKeyPair keyPair = (ECKeyPair) params[1];
							ecSign = asymmetricCryptoUtils.sign(message,
									keyPair.getPrivateKey());
							// Parse the EC sign to string using ',' as
							// separator
							sign = ecSign[0].toString(16) + ","
									+ ecSign[1].toString(16);
						}

						// Create a resEncrypt string using the encrypted
						// message and the session key
						String resEncryptStr = new String(
								Base64.encode(resEncrypt.get(0)))
								+ " , "
								+ new String(Base64.encode(resEncrypt.get(1)));

						// Encrypts again the resulting message with the sign of
						// the message using ';' for separating the
						// encrypted message and the signature
						String finalMessage = resEncryptStr + " ; " + sign;
						return asymmetricCryptoUtils.encrypt(finalMessage,
								publicKey);
					}

					// For ECPublic key
					if (params[2] instanceof ECPublicKey) {
						ECPublicKey publicKey = (ECPublicKey) params[2];

						String sign = "";
						BigInteger ecSign[];
						List<byte[]> resEncrypt;
						if (params[1] instanceof ECPrivateKey) {

							ECPrivateKey privateKey = (ECPrivateKey) params[1];

							resEncrypt = asymmetricCryptoUtils.encrypt(message,
									publicKey, privateKey);

							ecSign = asymmetricCryptoUtils.sign(message,
									privateKey);
							// Parse the EC sign to string using ',' as
							// separator
							sign = ecSign[0].toString(16) + ","
									+ ecSign[1].toString(16);

							// Create a resEncrypt string using the encrypted
							// message and the session key
							String resEncryptStr = new String(
									Base64.encode(resEncrypt.get(0)))
									+ " , "
									+ new String(Base64.encode(resEncrypt
											.get(1)));

							// Encrypts again the resulting message with the
							// sign of
							// the message using ';' for separating the
							// encrypted message and the signature
							String finalMessage = resEncryptStr + " ; " + sign;
							return asymmetricCryptoUtils.encrypt(finalMessage,
									publicKey, privateKey);
						} else {
							ECKeyPair keyPair = (ECKeyPair) params[1];

							resEncrypt = asymmetricCryptoUtils.encrypt(message,
									publicKey, keyPair.getPrivateKey());

							ecSign = asymmetricCryptoUtils.sign(message,
									keyPair.getPrivateKey());
							// Parse the EC sign to string using ',' as
							// separator
							sign = ecSign[0].toString(16) + ","
									+ ecSign[1].toString(16);

							// Create a resEncrypt string using the encrypted
							// message and the session key
							String resEncryptStr = new String(
									Base64.encode(resEncrypt.get(0)))
									+ " , "
									+ new String(Base64.encode(resEncrypt
											.get(1)));

							// Encrypts again the resulting message with the
							// sign of
							// the message using ';' for separating the
							// encrypted message and the signature
							String finalMessage = resEncryptStr + " ; " + sign;
							return asymmetricCryptoUtils.encrypt(finalMessage,
									publicKey, keyPair.getPrivateKey());
						}

					}
				}

				return null;
			} catch (CryptoUtilsException e) {
				e.printStackTrace();
				return null;
			}

		}

		@Override
		protected void onPostExecute(List<String> processResult) {
			if (processResult != null) {

				int currentView = mViewPager.getCurrentItem();
				// Check if we are at message or file page
				if (currentView == SecureOperationCollectionPagerAdapter.FILE_PAGE) {
					// For file page
					try {
						String fileName = txtOutputFileName.getText()
								.toString();
						if (!fileName.endsWith(".atn")) {
							fileName += ".atn";
						}
						File outputFile = new File(fileName);
						FileOutputStream fOut;

						fOut = new FileOutputStream(outputFile);
						OutputStreamWriter osw = new OutputStreamWriter(fOut);
						osw.write(processResult.get(0) + " , "
								+ processResult.get(1));
						osw.flush();
						osw.close();

						Log.i(PKITrustNetworkActivity.TAG, "OutputFile: "
								+ fileName);
						String message = getString(R.string.msgCryptoCipherSignOKFile);
						Toast.makeText(getApplicationContext(),
								message + " " + fileName, Toast.LENGTH_LONG)
								.show();
					} catch (FileNotFoundException e) {
						e.printStackTrace();
					} catch (IOException e) {
						Toast.makeText(getApplicationContext(),
								R.string.error_crypto_writing_resulting_file,
								Toast.LENGTH_LONG).show();
						e.printStackTrace();
					}

				} else {
					// For messages
					copyToClipBoard(processResult.get(0) + " , "
							+ processResult.get(1));
					Toast.makeText(getApplicationContext(),
							R.string.msgCryptoCipherSignOKMsg,
							Toast.LENGTH_LONG).show();
					TextView txtMessage = (TextView) findViewById(R.id.txtMessage);
					if (txtMessage != null) {
						txtMessage.setText(processResult.get(0) + " , "
								+ processResult.get(1));
					}
				}

			} else {
				Toast.makeText(getApplicationContext(),
						R.string.error_crypto_cipher_sign, Toast.LENGTH_LONG)
						.show();
			}
			// Disable the indeterminate progress icon on the action bar
			setSupportProgressBarIndeterminateVisibility(false);

		}
	}

	/**
	 * Inner class that create an asynchronous task in which is performed the
	 * Decrypt/Verify/Decrypt operation using the selected parameters, for
	 * execution the parameters must be sent in the correct order: Message,
	 * PrivateKey, PublicKey, the result of this task is a object array in the
	 * first position is the decrypted message and in the second one a boolean
	 * value that corresponds to the sign verification result
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class DecryptVerifyDecryptTask extends
			AsyncTask<Object, Void, Object[]> {

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
		protected Object[] doInBackground(Object... params) {

			if (params.length != 3) {
				return null;
			}

			// Check if the first parameter is a string a message or byte array
			if (!(params[0] instanceof String || params[0] instanceof byte[])) {
				return null;
			}

			// Check if the second parameter is a private key
			if (!(params[1] instanceof RSAPrivateKey
					|| params[1] instanceof ECPrivateKey
					|| params[1] instanceof RSAKeyPair || params[1] instanceof ECKeyPair)) {
				return null;
			}

			// Check if the third parameter is a public key
			if (!(params[2] instanceof RSAPublicKey || params[2] instanceof ECPublicKey)) {
				return null;
			}

			try {
				// If the message is a string or a byte array
				if (params[0] instanceof String) {
					String message = (String) params[0];

					String decMessage = "";
					// Check if the public key is RSA or EC

					if (params[2] instanceof RSAPublicKey) {
						RSAPublicKey publicKey = (RSAPublicKey) params[2];

						String sign = "";
						// Decrypt the received message
						decMessage = decryptMessage(message, params[1]);
						// If an error occurs during decrypting the message stop
						// the process
						if (decMessage == null)
							return null;

						// Parse the message into sign and original encrypted
						// message using ";" for separating it
						int index = decMessage.indexOf(";");
						if (index == -1) {
							return null;
						}

						String messageEnc = decMessage.substring(0, index)
								.trim();
						sign = decMessage.substring(index + 1,
								decMessage.length()).trim();

						// Decrypts again the message in order to the the
						// original one and go to sign verification
						decMessage = decryptMessage(messageEnc, params[1]);
						if (decMessage == null) {
							return null;
						}

						Boolean verify = asymmetricCryptoUtils.verify(
								decMessage, sign, publicKey);
						Object[] res = new Object[2];
						res[0] = decMessage;
						res[1] = verify;

						return res;

					}

					// For ECPublic key
					if (params[2] instanceof ECPublicKey) {
						ECPublicKey publicKey = (ECPublicKey) params[2];

						String sign = "";

						// Decrypt the received message
						decMessage = decryptMessage(message, params[1],
								publicKey);
						// If an error occurs during decrypting the message stop
						// the process
						if (decMessage == null)
							return null;

						// Parse the message into sign and original encrypted
						// message using ";" for separating it
						int index = decMessage.indexOf(";");
						if (index == -1) {
							return null;
						}

						String messageEnc = decMessage.substring(0, index)
								.trim();
						sign = decMessage.substring(index + 1,
								decMessage.length()).trim();

						// Decrypts again the message in order to the the
						// original one and go to sign verification
						decMessage = decryptMessage(messageEnc, params[1],
								publicKey);
						if (decMessage == null) {
							return null;
						}

						// Parse the sign string to a BigInteger array, so the
						// string should contain both r and s using a comma ","
						// as separator

						index = sign.indexOf(",");
						if (index == -1) {
							// If the sign does not contain a comma, the string
							// format is incorrect and the process should not
							// continue
							return null;
						}
						String signR = sign.substring(0, index).trim();
						String signS = sign.substring(index + 1, sign.length())
								.trim();

						BigInteger r = new BigInteger(signR, 16);
						BigInteger s = new BigInteger(signS, 16);
						BigInteger ecSign[] = { r, s };
						Boolean verify = asymmetricCryptoUtils.verify(
								decMessage, ecSign, publicKey);
						Object[] res = new Object[2];
						res[0] = decMessage;
						res[1] = verify;

						return res;

					}

				} else {
					byte[] messageBytes = (byte[]) params[0];

					String message = new String(messageBytes);
					// Log.i(PKITrustNetworkActivity.TAG, "ORG MSG BYTES: " +
					// message);
					String decMessage;
					// Check if the public key is RSA or EC
					if (params[2] instanceof RSAPublicKey) {
						RSAPublicKey publicKey = (RSAPublicKey) params[2];

						String sign = "";
						// Decrypt the received message
						decMessage = decryptMessage(message, params[1]);
						// If an error occurs during decrypting the message stop
						// the process
						if (decMessage == null)
							return null;

						// Parse the message into sign and original encrypted
						// message using ";" for separating it
						int index = decMessage.indexOf(";");
						if (index == -1) {
							return null;
						}

						String messageEnc = decMessage.substring(0, index)
								.trim();
						sign = decMessage.substring(index + 1,
								decMessage.length()).trim();

						// Decrypts again the message in order to the the
						// original one and go to sign verification
						byte[] decMessageBytes = decryptMessageBytes(
								messageEnc, params[1]);
						if (decMessageBytes == null) {
							return null;
						}

						Boolean verify = asymmetricCryptoUtils
								.verify(decMessageBytes, Base64.decode(sign),
										publicKey);
						Object[] res = new Object[2];
						res[0] = decMessageBytes;
						res[1] = verify;

						return res;

					}

					// For ECPublic key
					if (params[2] instanceof ECPublicKey) {
						ECPublicKey publicKey = (ECPublicKey) params[2];

						String sign = "";

						// Decrypt the received message
						decMessage = decryptMessage(message, params[1],
								publicKey);
						// If an error occurs during decrypting the message stop
						// the process
						if (decMessage == null)
							return null;

						// Parse the message into sign and original encrypted
						// message using ";" for separating it
						int index = decMessage.indexOf(";");
						if (index == -1) {
							return null;
						}

						String messageEnc = decMessage.substring(0, index)
								.trim();
						sign = decMessage.substring(index + 1,
								decMessage.length()).trim();

						// Decrypts again the message in order to the the
						// original one and go to sign verification
						byte[] decMessageBytes = decryptMessageBytes(
								messageEnc, params[1], publicKey);

						if (decMessageBytes == null) {
							return null;
						}

						// Parse the sign string to a BigInteger array, so the
						// string should contain both r and s using a comma ","
						// as separator

						index = sign.indexOf(",");
						if (index == -1) {
							// If the sign does not contain a comma, the string
							// format is incorrect and the process should not
							// continue
							return null;
						}
						String signR = sign.substring(0, index).trim();
						String signS = sign.substring(index + 1, sign.length())
								.trim();

						BigInteger r = new BigInteger(signR, 16);
						BigInteger s = new BigInteger(signS, 16);
						BigInteger ecSign[] = { r, s };
						Boolean verify = asymmetricCryptoUtils.verify(
								decMessageBytes, ecSign, publicKey);
						Object[] res = new Object[2];
						res[0] = decMessageBytes;
						res[1] = verify;

						return res;

					}
				}

				return null;
			} catch (CryptoUtilsException e) {
				e.printStackTrace();
				return null;
			}

		}

		@Override
		protected void onPostExecute(Object[] processResult) {
			if (processResult != null && processResult.length == 2) {
				Boolean verification = (Boolean) processResult[1];

				int currentView = mViewPager.getCurrentItem();
				// Check if we are at message or file page
				if (currentView == SecureOperationCollectionPagerAdapter.FILE_PAGE) {
					byte[] message = (byte[]) processResult[0];
					// For file page
					try {
						String fileName = txtOutputFileName.getText()
								.toString();
						File outputFile = new File(fileName);
						FileOutputStream fOut;

						fOut = new FileOutputStream(outputFile);
						BufferedOutputStream osw = new BufferedOutputStream(
								fOut);
						osw.write(message);
						osw.flush();
						osw.close();

						Log.i(PKITrustNetworkActivity.TAG, "OutputFile: "
								+ fileName);
						String messageRes = getString(R.string.msgCryptoDecipherVerifyOKFile);
						Toast.makeText(getApplicationContext(),
								messageRes + " " + fileName, Toast.LENGTH_LONG)
								.show();

						try {
							TextView txtResult;
							if (verification) {
								txtResult = (TextView) mCollectionPagerAdapter
										.getFragmentFile().getView()
										.findViewById(R.id.imgVerifyResultOk);
							} else {
								txtResult = (TextView) mCollectionPagerAdapter
										.getFragmentFile().getView()
										.findViewById(R.id.imgVerifyResultFail);
							}
							if (txtResult != null) {
								txtResult.setVisibility(View.VISIBLE);
							}
						} catch (NullPointerException ex) {
							// If something is null, means that the view has not
							// been instantiated in the activity and no
							// verification result must be shown, because the
							// app is in other activity
						}
					} catch (FileNotFoundException e) {
						e.printStackTrace();
					} catch (IOException e) {
						Toast.makeText(getApplicationContext(),
								R.string.error_crypto_writing_resulting_file,
								Toast.LENGTH_LONG).show();
						e.printStackTrace();
					}

				} else {
					String message = (String) processResult[0];
					// For messages
					copyToClipBoard(message);
					Toast.makeText(getApplicationContext(),
							R.string.msgCryptoDecipherVerifyOKMsg,
							Toast.LENGTH_LONG).show();
					TextView txtMessage = (TextView) findViewById(R.id.txtMessage);
					if (txtMessage != null) {
						txtMessage.setText(message);
					}

					try {
						TextView txtResult;
						if (verification) {
							txtResult = (TextView) mCollectionPagerAdapter
									.getFragmentMessage().getView()
									.findViewById(R.id.imgVerifyResultOk);
						} else {
							txtResult = (TextView) mCollectionPagerAdapter
									.getFragmentMessage().getView()
									.findViewById(R.id.imgVerifyResultFail);
						}
						if (txtResult != null) {
							txtResult.setVisibility(View.VISIBLE);
						}
					} catch (NullPointerException ex) {
						// If something is null, means that the view has not
						// been instantiated in the activity and no
						// verification result must be shown, because the
						// app is in other activity
					}
				}

			} else {
				try {
					TextView txtResult;

					txtResult = (TextView) mCollectionPagerAdapter
							.getFragmentMessage().getView()
							.findViewById(R.id.imgVerifyResultOk);

					if (txtResult != null) {
						txtResult.setVisibility(View.GONE);
					}

					txtResult = (TextView) mCollectionPagerAdapter
							.getFragmentMessage().getView()
							.findViewById(R.id.imgVerifyResultFail);

					if (txtResult != null) {
						txtResult.setVisibility(View.GONE);
					}

				} catch (NullPointerException ex) {
					// If something is null, means that the view has not
					// been instantiated in the activity and no
					// verification result must be shown, because the
					// app is in other activity
				}
				Toast.makeText(getApplicationContext(),
						R.string.error_crypto_decipher_verify,
						Toast.LENGTH_LONG).show();

			}
			// Disable the indeterminate progress icon on the action bar
			setSupportProgressBarIndeterminateVisibility(false);

		}
	}

	@SuppressWarnings("deprecation")
	@SuppressLint({ "NewApi", "NewApi", "NewApi" })
	protected void copyToClipBoard(String text) {
		int sdk = android.os.Build.VERSION.SDK_INT;
		if (sdk < android.os.Build.VERSION_CODES.HONEYCOMB) {
			android.text.ClipboardManager clipboard = (android.text.ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
			clipboard.setText(text);
		} else {
			ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
			// Creates a new text clip to put on the clipboard
			ClipData clip = ClipData.newPlainText("Cipher Message", text);
			// Set the clipboard's primary clip.
			clipboard.setPrimaryClip(clip);
		}
	}

	/**
	 * Decrypts a message using the encrypted message format:
	 * "encrytedMessage, sessionKey"
	 * 
	 * @param messageEnc
	 *            Message to be decrypted, should be a string containing the
	 *            actual encrypted message and the session key used for encrypt
	 *            the message separated with a comma ","
	 * @param key
	 *            Private key to be used for decrypt the message
	 * @return A String corresponding to the decrypted message or null if an
	 *         error occurs
	 * @throws CryptoUtilsException
	 *             If an error happened in the decryption function
	 */
	private String decryptMessage(String messageEnc, Object key)
			throws CryptoUtilsException {
		int index = messageEnc.indexOf(",");
		if (index == -1) {
			return null;
		}

		String messageAux = messageEnc.substring(0, index).trim();
		String encKey = messageEnc.substring(index + 1, messageEnc.length())
				.trim();

		// Log.i(PKITrustNetworkActivity.TAG, "ENC KEY= " + encKey);
		// Log.i(PKITrustNetworkActivity.TAG, "MESSAGE ENC= " + messageAux);

		// Verify the type of the Private key and decrypt the message
		if (key instanceof RSAPrivateKey) {
			RSAPrivateKey privateKey = (RSAPrivateKey) key;
			return asymmetricCryptoUtils
					.decrypt(messageAux, encKey, privateKey);
		}

		if (key instanceof RSAKeyPair) {
			RSAKeyPair keyPair = (RSAKeyPair) key;
			return asymmetricCryptoUtils.decrypt(messageAux, encKey,
					keyPair.getPrivateKey());
		}
		return null;
	}

	/**
	 * Decrypts a message using the encrypted message format:
	 * "encrytedMessage, sessionKey"
	 * 
	 * @param messageEnc
	 *            Message to be decrypted, should be a string containing the
	 *            actual encrypted message and the session key used for encrypt
	 *            the message separated with a comma ","
	 * @param key
	 *            Private key to be used for decrypt the message
	 * @return A String corresponding to the decrypted message or null if an
	 *         error occurs
	 * @throws CryptoUtilsException
	 *             If an error happened in the decryption function
	 */
	private byte[] decryptMessageBytes(String messageEnc, Object key)
			throws CryptoUtilsException {
		int index = messageEnc.indexOf(",");
		if (index == -1) {
			return null;
		}

		String messageAux = messageEnc.substring(0, index).trim();
		String encKey = messageEnc.substring(index + 1, messageEnc.length())
				.trim();

		// Log.i(PKITrustNetworkActivity.TAG, "ENC KEY= " + encKey);
		// Log.i(PKITrustNetworkActivity.TAG, "MESSAGE ENC= " + messageAux);

		// Verify the type of the Private key and decrypt the message
		if (key instanceof RSAPrivateKey) {
			RSAPrivateKey privateKey = (RSAPrivateKey) key;
			return asymmetricCryptoUtils.decrypt(Base64.decode(messageAux),
					Base64.decode(encKey), privateKey);
		}

		if (key instanceof RSAKeyPair) {
			RSAKeyPair keyPair = (RSAKeyPair) key;
			return asymmetricCryptoUtils.decrypt(Base64.decode(messageAux),
					Base64.decode(encKey), keyPair.getPrivateKey());
		}
		return null;
	}

	/**
	 * Decrypts a message using the encrypted message format:
	 * "encrytedMessage, sessionKey"
	 * 
	 * @param messageEnc
	 *            Message to be decrypted, should be a string containing the
	 *            actual encrypted message and the session key used for encrypt
	 *            the message separated with a comma ","
	 * @param key
	 *            Private key to be used for decrypt the message
	 * @param publicKey
	 *            Public key needed for the EC decryption functions
	 * @return A String corresponding to the decrypted message or null if an
	 *         error occurs
	 * @throws CryptoUtilsException
	 *             If an error happened in the decryption function
	 */
	private String decryptMessage(String messageEnc, Object key,
			ECPublicKey publicKey) throws CryptoUtilsException {
		int index = messageEnc.indexOf(",");
		if (index == -1) {
			return null;
		}

		String messageAux = messageEnc.substring(0, index).trim();
		String encKey = messageEnc.substring(index + 1, messageEnc.length())
				.trim();

		// Log.i(PKITrustNetworkActivity.TAG, "ENC KEY= " + encKey);
		// Log.i(PKITrustNetworkActivity.TAG, "MESSAGE ENC= " + messageAux);

		// Verify the type of the Private key and decrypt the message
		if (key instanceof RSAPrivateKey) {
			RSAPrivateKey privateKey = (RSAPrivateKey) key;
			return asymmetricCryptoUtils
					.decrypt(messageAux, encKey, privateKey);
		}

		if (key instanceof RSAKeyPair) {
			RSAKeyPair keyPair = (RSAKeyPair) key;
			return asymmetricCryptoUtils.decrypt(messageAux, encKey,
					keyPair.getPrivateKey());
		}

		if (key instanceof ECPrivateKey) {
			ECPrivateKey privateKey = (ECPrivateKey) key;
			return asymmetricCryptoUtils.decrypt(messageAux, encKey, publicKey,
					privateKey);
		}

		if (key instanceof ECKeyPair) {
			ECKeyPair keyPair = (ECKeyPair) key;
			return asymmetricCryptoUtils.decrypt(messageAux, encKey, publicKey,
					keyPair.getPrivateKey());
		}

		return null;
	}

	/**
	 * Decrypts a message using the encrypted message format:
	 * "encrytedMessage, sessionKey"
	 * 
	 * @param messageEnc
	 *            Message to be decrypted, should be a string containing the
	 *            actual encrypted message and the session key used for encrypt
	 *            the message separated with a comma ","
	 * @param key
	 *            Private key to be used for decrypt the message
	 * @param publicKey
	 *            Public key needed for the EC decryption functions
	 * @return A String corresponding to the decrypted message or null if an
	 *         error occurs
	 * @throws CryptoUtilsException
	 *             If an error happened in the decryption function
	 */
	private byte[] decryptMessageBytes(String messageEnc, Object key,
			ECPublicKey publicKey) throws CryptoUtilsException {
		int index = messageEnc.indexOf(",");
		if (index == -1) {
			return null;
		}

		String messageAux = messageEnc.substring(0, index).trim();
		String encKey = messageEnc.substring(index + 1, messageEnc.length())
				.trim();

		// Log.i(PKITrustNetworkActivity.TAG, "ENC KEY= " + encKey);
		// Log.i(PKITrustNetworkActivity.TAG, "MESSAGE ENC= " + messageAux);

		// Verify the type of the Private key and decrypt the message
		if (key instanceof RSAPrivateKey) {
			RSAPrivateKey privateKey = (RSAPrivateKey) key;
			return asymmetricCryptoUtils.decrypt(Base64.decode(messageAux),
					Base64.decode(encKey), privateKey);
		}

		if (key instanceof RSAKeyPair) {
			RSAKeyPair keyPair = (RSAKeyPair) key;
			return asymmetricCryptoUtils.decrypt(Base64.decode(messageAux),
					Base64.decode(encKey), keyPair.getPrivateKey());
		}

		if (key instanceof ECPrivateKey) {
			ECPrivateKey privateKey = (ECPrivateKey) key;
			return asymmetricCryptoUtils.decrypt(Base64.decode(messageAux),
					Base64.decode(encKey), publicKey, privateKey);
		}

		if (key instanceof ECKeyPair) {
			ECKeyPair keyPair = (ECKeyPair) key;
			return asymmetricCryptoUtils.decrypt(Base64.decode(messageAux),
					Base64.decode(encKey), publicKey, keyPair.getPrivateKey());
		}

		return null;
	}

}
