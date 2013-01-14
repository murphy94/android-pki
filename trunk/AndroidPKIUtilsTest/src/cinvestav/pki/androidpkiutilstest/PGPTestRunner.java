/**
 *  Created on  : 01/06/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	
 */
package cinvestav.pki.androidpkiutilstest;

import java.io.File;
import java.util.Date;
import java.util.HashMap;

import android.os.Environment;
import cinvestav.android.pki.cryptography.cert.CertificateInformationKeys;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.key.RSAKeyPair;
import cinvestav.android.pki.cryptography.key.RSAPublicKey;
import cinvestav.android.pki.cryptography.utils.AsymmetricCryptoUtils;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;
import cinvestav.android.pki.cryptography.utils.PGPUtils;
import cinvestav.android.pki.utils.LogUtil;

/**
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 01/06/2012
 * @version 1.0
 */
public class PGPTestRunner {
	// public static final String TAG = "SCCIPHERTEST";
	protected static LogUtil log = new LogUtil("ANDROID_PKI_UTILS");
	private PGPUtils _PGPUtils;
	private AsymmetricCryptoUtils asymmetricCryptoUtils;
	private String defaultEncoder = CryptoUtils.ENCODER_HEX;

	public PGPTestRunner() throws CryptoUtilsException {
		_PGPUtils = new PGPUtils();
		asymmetricCryptoUtils = new AsymmetricCryptoUtils();
	}

	public void runTest(Boolean detailResult) {
		// log.info(" ********* AES NIST Test Begin *********");
		// testEncryptDecryptStatic();
		Integer primeSize = 1024;
		log.info(" ********* RSA 1024 Test Begin *********");
		runTest(primeSize, detailResult);
	}

	private void runTest(Integer primeSize, Boolean detailResult) {

		log.info("[" + primeSize + "] ---- OpenPGP ---- ");
		testSaveAndLoadRSAPublicKey(primeSize, detailResult);

		/*
		 * SecureRandom secureRandom = new SecureRandom(); for (int i = 0; i <
		 * 5; i++) { int inputSize = secureRandom.nextInt(64); log.info(
		 * "---- Input Size: " + inputSize + " ---- ");
		 * testEncryptDecryptRandom(keySizeInBits, detailResult, inputSize); }
		 */

		// testEncryptDecryptRandom(keySizeInBits, detailResult, 127);
		// testEncryptDecryptRandom(keySizeInBits, detailResult, 12);
	}

	private void testSaveAndLoadRSAPublicKey(Integer primeSize,
			Boolean detailResult) {
		try {
			RSAKeyPair key;

			// Generate Key
			key = asymmetricCryptoUtils.generateKeys(primeSize);

			String keyFileName = Environment.getExternalStorageDirectory()
					+ "/cryptoTest/RSA_PGP_" + primeSize + "_";
			File f = new File(keyFileName);
			if (!f.getParentFile().exists()) {
				f.getParentFile().mkdir();
			}
			if (detailResult)
				log.info("[" + primeSize + "] Original KEY= "
						+ key.toString(defaultEncoder));

			// Certificate Parameters
			Integer certificateSerial = 1;
			Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60
					* 60 * 24 * 30);
			Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60
					* 60 * 24 * 30);

			// Generates CAs keys
			RSAKeyPair rootCARSAKeyPair = asymmetricCryptoUtils
					.generateKeys(primeSize);
			/*
			 * RSAKeyPair ca1RSAKeyPair = asymmetricCryptoUtils
			 * .generateKeys(primeSize); RSAKeyPair ca2RSAKeyPair =
			 * asymmetricCryptoUtils .generateKeys(primeSize); RSAKeyPair
			 * masterRootRSAKeyPair = asymmetricCryptoUtils
			 * .generateKeys(primeSize);
			 */

			// Generate CAs certificate Information Maps
			HashMap<String, String> rootCertificateInformationMap = new HashMap<String, String>();
			rootCertificateInformationMap.put(
					CertificateInformationKeys.FRIENDLY_NAME, "Root CA");
			rootCertificateInformationMap.put(
					CertificateInformationKeys.COUNTRY, "MX");
			rootCertificateInformationMap
					.put(CertificateInformationKeys.EmailAddress,
							"rootCA@gmail.com");
			rootCertificateInformationMap
					.put(CertificateInformationKeys.FULL_COMMON_NAME,
							"Root CA Name");
			rootCertificateInformationMap.put(
					CertificateInformationKeys.LOCALITY, "GAM");
			rootCertificateInformationMap.put(CertificateInformationKeys.STATE,
					"DF");
			rootCertificateInformationMap.put(
					CertificateInformationKeys.ORGANIZATION, "Cinvestav");

			certificateSerial++;
			// Create Subject Information Map
			HashMap<String, String> subjCertificateInformationMap = new HashMap<String, String>();
			subjCertificateInformationMap
					.put(CertificateInformationKeys.FRIENDLY_NAME,
							"Javier Key Test");
			subjCertificateInformationMap.put(
					CertificateInformationKeys.COUNTRY, "MX");
			subjCertificateInformationMap.put(
					CertificateInformationKeys.EmailAddress,
					"javier.sp@gmail.com");
			subjCertificateInformationMap.put(
					CertificateInformationKeys.FULL_COMMON_NAME,
					"Javier Silva Perez");
			subjCertificateInformationMap.put(
					CertificateInformationKeys.LOCALITY, "Tlalnepantla");
			subjCertificateInformationMap.put(CertificateInformationKeys.STATE,
					"Mexico");
			subjCertificateInformationMap.put(
					CertificateInformationKeys.ORGANIZATION, "Cinvestav");

			// Save RootCA RSA PublicKey
			testSaveAndLoadRSAPublicKey(keyFileName + "Root_",
					rootCARSAKeyPair.getPublicKey(), rootCARSAKeyPair,
					rootCertificateInformationMap, false, primeSize);

			testSaveAndLoadRSAPublicKey(keyFileName + "Root_",
					rootCARSAKeyPair.getPublicKey(), rootCARSAKeyPair,
					rootCertificateInformationMap, true, primeSize);

			testSaveAndLoadRSAPublicKey(keyFileName + "Subject_",
					key.getPublicKey(), rootCARSAKeyPair,
					subjCertificateInformationMap, false, primeSize);

			testSaveAndLoadRSAPublicKey(keyFileName + "Subject_",
					key.getPublicKey(), rootCARSAKeyPair,
					subjCertificateInformationMap, true, primeSize);

		} catch (CryptoUtilsException e) {
			log.error(
					"testSaveAndLoadRSAPublicKey [" + primeSize + "]= "
							+ e.getMessage(), e.getCause());
		}

	}

	private void testSaveAndLoadRSAPublicKey(String keyFileName,
			RSAPublicKey publicKey, RSAKeyPair issuerKeyPair,
			HashMap<String, String> informationMap, Boolean ascArmor,
			Integer primeSize) throws CryptoUtilsException {
		String ascArmorStr = ascArmor ? "ASCII_ARMOR" : "";
		log.info("[" + primeSize + "] ---- Save PGP RSA PubliKey "
				+ ascArmorStr + " ---- ");
		String fileSufix = "";
		String res = "";
		fileSufix = "PublicKey_" + ascArmorStr + ".asc";

		_PGPUtils.saveRSAPublicKey(keyFileName + fileSufix, publicKey,
				informationMap, issuerKeyPair, ascArmor);

		res = true ? "OK" : "FAIL";
		log.info("[" + primeSize + "] Save PublicKey" + ascArmorStr + " = "
				+ res);
	}
}
