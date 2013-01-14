/**
 *  Created on  : 27/03/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Android Key Store Util class tester, contains the tester methods
 */
package cinvestav.pki.androidpkiutilstest;

import java.security.KeyStore;

import android.os.Environment;
import android.util.Log;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.utils.KeyStoreUtil;
import cinvestav.android.pki.utils.LogUtil;

/**
 * @author Ing. Javier Silva Pérez - [javier]
 * 
 */
public class KeyStoreTestRunner {

	// public static final String TAG = "SCCIPHERTEST";
	protected static LogUtil log = new LogUtil("ANDROID_PKI_UTILS");
	private KeyStoreUtil keyStoreUtil;

	/**
	 * 
	 */
	public KeyStoreTestRunner() {
		// TODO Auto-generated constructor stub
		keyStoreUtil = new KeyStoreUtil();
	}

	public void runTest() {
		testCreateNewKeyStore();
		testSaveAndLoadKeyStore();
		testSaveAndLoadKeyStoreWrongPassword();
	}

	public void testCreateNewKeyStore() {
		try {

			log.info("Create Key Store ");
			KeyStore ks = keyStoreUtil.createNewKeyStore();
			log.info("CREATE KEY STORE= " + ks);
		} catch (CryptoUtilsException e) {
			// TODO Auto-generated catch block
			log.error("CREATE KEY STORE= " + e.getMessage(), e.getCause());
		}
	}

	public void testSaveAndLoadKeyStore() {
		String keyFileName = Environment.getExternalStorageDirectory()
				+ "/cryptoTest/TestKeyStore.ks";

		try {

			log.info("Save Key Store");
			KeyStore ks = keyStoreUtil.createNewKeyStore();
			log.info("SAVED KEY STORE= " + ks);

			keyStoreUtil.saveKeyStore(ks, keyFileName, "PASSWORD");

			KeyStore loadKs = keyStoreUtil
					.loadKeyStore(keyFileName, "PASSWORD");
			log.info("LOAD KEY STORE= " + loadKs);
		} catch (CryptoUtilsException e) {
			// TODO Auto-generated catch block
			log.error("SAVE AND LOAD KEY STORE= " + e.getMessage(),
					e.getCause());
		}

	}

	public void testSaveAndLoadKeyStoreWrongPassword() {
		String keyFileName = Environment.getExternalStorageDirectory()
				+ "/cryptoTest/TestKeyStore.ks";

		try {

			log.info("Save Key Store");
			KeyStore ks = keyStoreUtil.createNewKeyStore();
			log.info("SAVED KEY STORE= " + ks);

			keyStoreUtil.saveKeyStore(ks, keyFileName, "PASSWORD");

			KeyStore loadKs = keyStoreUtil.loadKeyStore(keyFileName,
					"PASSWORD2");
			log.info("LOAD KEY STORE= " + loadKs);
		} catch (CryptoUtilsException e) {
			// TODO Auto-generated catch block
			log.error("WRONG PASSWORD= " + e.getMessage(), e.getCause());
		}

	}

}
