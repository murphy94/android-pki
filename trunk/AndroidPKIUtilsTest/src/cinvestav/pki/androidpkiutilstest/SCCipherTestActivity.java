package cinvestav.pki.androidpkiutilstest;

import android.app.Activity;
import android.os.AsyncTask;
import android.os.Bundle;
import android.provider.Settings.Secure;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.key.RSAPrivateKey;
import cinvestav.android.pki.db.dao.PersonalKeyDAO;
import cinvestav.android.pki.utils.LogUtil;

public class SCCipherTestActivity extends Activity {
	// public static final String TAG = "SCCIPHERTEST";
	protected static LogUtil log = new LogUtil("ANDROID_PKI_UTILS");
	public static String ANDROID_ID;

	private Button btnIniciar;
	private RadioGroup rdbGruop;
	private CheckBox chkDetails;
	private CheckBox chkTiming;
	private TextView txtStatus;
	InitTask initTask;

	/** Called when the activity is first created. */
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.main);

		// Get a unique device ID value;
		ANDROID_ID = Secure.getString(this.getContentResolver(),
				Secure.ANDROID_ID);
		btnIniciar = (Button) findViewById(R.id.btnIniciar);
		rdbGruop = (RadioGroup) findViewById(R.id.rdbGroup);
		rdbGruop.check(R.id.rdbAES);
		chkDetails = (CheckBox) findViewById(R.id.chkDetailResult);
		chkTiming = (CheckBox) findViewById(R.id.chkTiming);
		txtStatus = (TextView) findViewById(R.id.txtStatus);

		txtStatus.setText("Esperando...");
		/*
		 * TextView txt = (TextView) findViewById(R.id.txtTitle);
		 * txt.setText(txt.getText()+" \n Otro Texto;");
		 * txt.setText(txt.getText()+" \n Otro Texto;");
		 */

		btnIniciar.setOnClickListener(new OnClickListener() {

			@Override
			public void onClick(View v) {
				// TODO Auto-generated method stub
				if (initTask == null
						|| !initTask.getStatus().equals(
								AsyncTask.Status.RUNNING)) {
					initTask = new InitTask();
					initTask.execute();
				} else {
					Toast.makeText(getApplicationContext(), "Trabajando...",
							Toast.LENGTH_SHORT).show();
				}

			}
		});

	}

	/**
	 * Inner class that create an asynchronous task in which a
	 * {@link RSAPrivateKey} is loaded and decoded from a {@link PersonalKeyDAO}
	 * object
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	private class InitTask extends AsyncTask<Void, Void, Void> {

		@Override
		protected void onPreExecute() {
			txtStatus.setText("Corriendo...");
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see android.os.AsyncTask#doInBackground(Params[])
		 */
		@Override
		protected Void doInBackground(Void... params) {
			iniciar();
			return null;

		}

		@Override
		protected void onPostExecute(Void privateKey) {
			txtStatus.setText("Terminado...");
		}
	}

	public void iniciar() {
		int idSeleccionado = rdbGruop.getCheckedRadioButtonId();
		log.info("ID= " + idSeleccionado);
		// AES
		if (idSeleccionado == R.id.rdbAES) {
			runAESTest();
		}
		if (idSeleccionado == R.id.rdbKeyStore) {
			runKeyStoreTest();
		}
		if (idSeleccionado == R.id.rdbRSA) {
			runRSATest();
		}

		if (idSeleccionado == R.id.rdbX509) {
			runX509Test();
		}

		if (idSeleccionado == R.id.rdbPGP) {
			runPGPTest();
		}

		if (idSeleccionado == R.id.rdbEC) {
			runECTest();
		}

		if (idSeleccionado == R.id.rdbDB) {
			runDBTest();
		}
	}

	private void runAESTest() {
		AESTestRunner aesTestRunner = new AESTestRunner();
		if (!chkTiming.isChecked()) {
			aesTestRunner.runTest(chkDetails.isChecked());
		} else {
			aesTestRunner.runTestTiming(chkDetails.isChecked());
		}

	}

	private void runKeyStoreTest() {
		KeyStoreTestRunner keyStoreTestRunner = new KeyStoreTestRunner();
		keyStoreTestRunner.runTest();
	}

	private void runRSATest() {
		RSATestRunner rsaTestRunner;
		try {
			rsaTestRunner = new RSATestRunner();
			if (!chkTiming.isChecked()) {
				rsaTestRunner.runTest(chkDetails.isChecked());
			} else {
				rsaTestRunner.runTestTiming();

			}
		} catch (CryptoUtilsException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void runX509Test() {
		try {
			X509TestRunner x509TestRunner = new X509TestRunner();
			if (!chkTiming.isChecked()) {
				x509TestRunner.runTest(chkDetails.isChecked());
			}else{
				x509TestRunner.runTestTiming();
			}
		} catch (CryptoUtilsException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void runPGPTest() {
		AESTestRunner aesTestRunner = new AESTestRunner();
		RSATestRunner rsaTestRunner;
		ECTestRunner ecTestRunner;
		try {
			rsaTestRunner = new RSATestRunner();
			ecTestRunner = new ECTestRunner();
			if (!chkTiming.isChecked()) {
				aesTestRunner.runTest(chkDetails.isChecked());
			} else {
				aesTestRunner.runTestTiming(chkDetails.isChecked());
				rsaTestRunner.runTestTiming();
				ecTestRunner.runTestTiming();
			}
		} catch (CryptoUtilsException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		/*
		 * try { PGPTestRunner pgpTestRunner = new PGPTestRunner();
		 * pgpTestRunner.runTest(chkDetails.isChecked()); } catch
		 * (CryptoUtilsException e) { // TODO Auto-generated catch block
		 * e.printStackTrace(); }
		 */
	}

	private void runECTest() {
		try {
			ECTestRunner ecTestRunner = new ECTestRunner();
			if (!chkTiming.isChecked()) {
				ecTestRunner.runTest(chkDetails.isChecked());
			} else {
				ecTestRunner.runTestTiming();
			}

		} catch (CryptoUtilsException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void runDBTest() {
		DBTestRunner dbTestRunner;
		try {
			dbTestRunner = new DBTestRunner(this);
			dbTestRunner.runTest(this, chkDetails.isChecked());
		} catch (CryptoUtilsException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
}