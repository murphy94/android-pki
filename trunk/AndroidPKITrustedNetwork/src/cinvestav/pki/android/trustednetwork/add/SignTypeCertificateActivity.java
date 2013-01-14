/**
 *  Created on  : 04/10/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	 This activity will contain the certificate sign type and will allow the user
 * to know the risk of signing a certificate depending on the certificate
 * signature type, will also give the option to verify the selected certificate
 */
package cinvestav.pki.android.trustednetwork.add;

import java.security.cert.X509Certificate;
import java.util.Arrays;

import android.content.Intent;
import android.os.Bundle;
import android.support.v4.app.NavUtils;
import android.support.v4.app.TaskStackBuilder;
import android.util.Log;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.utils.X509Utils;
import cinvestav.android.pki.cryptography.utils.X509UtilsDictionary;
import cinvestav.android.pki.db.controller.CertificateController;
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;
import cinvestav.pki.android.trustednetwork.selection.SelectCAHolderActivity;
import cinvestav.pki.android.trustednetwork.selection.SelectVerificationTypeActivity;

import com.actionbarsherlock.app.ActionBar;
import com.actionbarsherlock.app.SherlockActivity;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuItem;
import com.actionbarsherlock.view.Window;

/**
 * This activity will contain the certificate sign type and will allow the user
 * to know the risk of signing a certificate depending on the certificate
 * signature type, will also give the option to verify the selected certificate
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 04/10/2012
 * @version 1.0
 */
public class SignTypeCertificateActivity extends SherlockActivity {

	private static final int MENU_SIGN = 0;
	private static final int MENU_CANCEL = 1;

	CertificateController certificateController;

	/**
	 * selected certificate id
	 */
	private Integer certificateId;

	private X509Utils _X509Utils;

	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		certificateController = new CertificateController(
				getApplicationContext());

		try {
			_X509Utils = new X509Utils();
		} catch (CryptoUtilsException e) {
			e.printStackTrace();
		}

		// This has to be called before setContentView and you must use the
		// class in com.actionbarsherlock.view and NOT android.view
		requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

		setContentView(R.layout.sign_type_certificate);
		setSupportProgressBarIndeterminateVisibility(false);

		// Set up action bar.
		final ActionBar actionBar = getSupportActionBar();

		// Specify that the Home button should show an "Up" caret, indicating
		// that touching the
		// button will take the user one step up in the application's hierarchy.
		actionBar.setDisplayHomeAsUpEnabled(true);
		actionBar.setSubtitle(R.string.subtitle_cert_sign_warning);

		// Get Selected certificate ID
		certificateId = getIntent().getIntExtra(
				SignCertificateActivity.EXTRA_CERTIFICATE_ID, 0);

		try {
			CertificateDAO certificate = certificateController
					.getById(certificateId);

			X509Certificate x509Certificate = _X509Utils.decode(certificate
					.getCertificateStr().getBytes());

			byte[] authKeyId = _X509Utils
					.getAuthorityKeyIdentifier(x509Certificate);
			byte[] subjKeyId = _X509Utils
					.getSubjectKeyIdentifier(x509Certificate);

			Integer certificateSignType = -1;
			if (authKeyId == null || subjKeyId == null) {
				certificateSignType = X509UtilsDictionary.CERTIFICATE_SIGN_TYPE_UNKNOWN;
			} else {
				if (Arrays.equals(authKeyId, subjKeyId)) {
					certificateSignType = X509UtilsDictionary.CERTIFICATE_SIGN_TYPE_SELF_SIGNED;
				} else {
					certificateSignType = X509UtilsDictionary.CERTIFICATE_SIGN_TYPE_CA_SIGNED;
				}
			}

			// Fill view fields
			// Serial number
			TextView txtCertificateSerialNumber = (TextView) findViewById(R.id.txtCertificateSerialNumber);
			txtCertificateSerialNumber.setText(x509Certificate
					.getSerialNumber().toString());
			TextView txtCertificateSignType = (TextView) findViewById(R.id.txtCertificateSignType);
			TextView lblCertificateSignTypeWarning = (TextView) findViewById(R.id.lblCertificateSignTypeWarning);
			switch (certificateSignType) {
			case 0:
				txtCertificateSignType
						.setText(R.string.certificateSignTypeSelfSigned);
				lblCertificateSignTypeWarning
						.setText(R.string.lblCertificateSignTypeWarningSelfSigned);
				break;
			case 1:
				txtCertificateSignType
						.setText(R.string.certificateSignTypeCASigned);
				lblCertificateSignTypeWarning
						.setText(R.string.lblCertificateSignTypeWarningCASigned);
				break;
			case 2:
				txtCertificateSignType
						.setText(R.string.certificateSignTypeUnknown);
				lblCertificateSignTypeWarning
						.setText(R.string.lblCertificateSignTypeWarningUnknown);
				break;
			default:
				txtCertificateSignType
						.setText(R.string.certificateSignTypeUnknown);
				lblCertificateSignTypeWarning
						.setText(R.string.lblCertificateSignTypeWarningUnknown);
			}

			((TextView) findViewById(R.id.lblImgVerifyCertificate))
					.setOnClickListener(new View.OnClickListener() {

						@Override
						public void onClick(View v) {
							verify();
						}
					});

		} catch (DBException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
			e.printStackTrace();
			Toast.makeText(this, R.string.error_db_load_cert, Toast.LENGTH_LONG)
					.show();
			returnHome();
		} catch (CryptoUtilsException e) {
			Log.e(PKITrustNetworkActivity.TAG, e.getMessage());
			e.printStackTrace();
			Toast.makeText(this, R.string.error_cert_decode, Toast.LENGTH_LONG)
					.show();
			returnHome();
		}

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
			next();
			return true;
		case MENU_CANCEL:
			returnHome();
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
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
	 * This is called when the user selects the next button, shows the next
	 * activity in the signing task that its SelectCAHolderActivity
	 */
	public void next() {
		Intent intent = new Intent(this, SelectCAHolderActivity.class);

		intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
				PKITrustNetworkActivity.CERTIFICATE);

		intent.putExtra(SignCertificateActivity.EXTRA_CERTIFICATE_ID,
				certificateId);
		startActivity(intent);

	}

	/**
	 * Verify the selected certificate
	 */
	public void verify() {
		Intent intent = new Intent(this, SelectVerificationTypeActivity.class);

		intent.putExtra(SelectVerificationTypeActivity.EXTRA_CERTIFICATE_ID,
				certificateId);
		intent.putExtra(PKITrustNetworkActivity.CURRENT_OPTION,
				PKITrustNetworkActivity.CERTIFICATE);
		intent.putExtra(SelectVerificationTypeActivity.EXTRA_CURRENT_OPERATION,
				SelectVerificationTypeActivity.SIGN);
		
		startActivity(intent);
	}
}
