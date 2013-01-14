/**
 *  Created on  : 26/03/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	In this class are all the methods to test AES functions contained in the class AndroidSymmetricCryptoUtils
 *  	
 */
package cinvestav.pki.androidpkiutilstest;

import java.security.KeyStore;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;

import javax.crypto.SecretKey;

import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.encoders.Hex;

import android.os.Environment;
import cinvestav.android.pki.cryptography.algorithm.AES;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.utils.KeyStoreUtil;
import cinvestav.android.pki.cryptography.utils.SymmetricCryptoUtils;
import cinvestav.android.pki.utils.LogUtil;

/**
 * @author Ing. Javier Silva Pérez - [javier]
 * 
 */
public class AESTestRunner {
	// public static final String TAG = "SCCIPHERTEST";
	private SymmetricCryptoUtils symmetricCryptoUtils;
	protected static LogUtil log = new LogUtil("ANDROID_PKI_UTILS");

	private static final byte[] tData = Hex
			.decode("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114F3F6752AE8D7831138F041560631B1145A01020304050607");
	private static final byte[] outCBC1 = Hex
			.decode("a444a9a4d46eb30cb7ed34d62873a89f8fdf2bf8a54e1aeadd06fd85c9cb46f021ee7cd4f418fa0bb72e9d07c70d5d20");
	private static final byte[] outCFB1 = Hex
			.decode("82a1744e8ebbd053ca72362d5e5703264b4182de3208c374b8ac4fa36af9c5e5f4f87d1e3b67963d06acf5eb13914c90");
	private static final byte[] outOFB1 = Hex
			.decode("82a1744e8ebbd053ca72362d5e5703261ebf1fdbec05e57b3465b583132f84b43bf95b2c89040ad1677b22d42db69a7a");
	String logFileName = "performance_aes_d1";
	SecureRandom random;

	public AESTestRunner() {
		symmetricCryptoUtils = new SymmetricCryptoUtils();
		random = new SecureRandom();
	}

	public void runTest(Boolean detailResult) {
		log.info(" ********* AES NIST Test Begin *********");
		// testEncryptDecryptStatic();
		Integer keySize = 128;
		log.info(" ********* AES 128 Test Begin *********");
		runTest(keySize, detailResult);
		log.info(" ********* AES 192 Test Begin ");
		keySize = 192;
		// runTest(keySize, detailResult);
		log.info(" ********* AES 256 Test Begin *********");
		keySize = 256;
		// runTest(keySize, detailResult);
	}

	public void runTestTiming(Boolean detailResult) {

		log.toFile("***************************************", logFileName);

		testKeyGenTiming(128);
		testKeyGenTiming(192);
		testKeyGenTiming(256);

		testSaveAndLoadKeyFileTiming(128);
		testSaveAndLoadKeyFileTiming(192);
		testSaveAndLoadKeyFileTiming(256);

		testAddKeyToKeyStoreTiming(128);
		testAddKeyToKeyStoreTiming(192);
		testAddKeyToKeyStoreTiming(256);

		runTestTiming(128, detailResult);
		runTestTiming(192, detailResult);
		runTestTiming(256, detailResult);
	}

	/**
	 * Run all the AES test with the specified key Size
	 * 
	 * @param keySize
	 *            KeySize to be used with AES
	 */
	private void runTest(Integer keySize, Boolean detailResult) {
		testKeyGen(keySize);
		testSaveAndLoadKeyFile(keySize);
		testAddKeyToKeyStore(keySize);
		// testEncryptDecryptStatic();
		for (int i = 0; i < 15; i++) {
			int inputSize = random.nextInt(4096);
			log.info("---- Input Size: " + inputSize + " ---- ");
			testEncryptDecryptRandom(keySize, detailResult, inputSize,
					Boolean.FALSE);
		}

	}

	/**
	 * Run all the AES test with the specified key Size for timing
	 * 
	 * @param keySize
	 *            KeySize to be used with AES
	 */
	private void runTestTiming(Integer keySize, Boolean detailResult) {
		int inputSize[] = { 1024, 3072 };

		for (int i = 0; i < inputSize.length; i++) {
			performEncryptDecryptTiming(keySize, inputSize[i],
					AES.OPERATION_MODE_CBC, AES.PADDING_TYPE_PKCS7);

			performEncryptDecryptTiming(keySize, inputSize[i],
					AES.OPERATION_MODE_OFB, AES.PADDING_TYPE_ISO7816d4);

			performEncryptDecryptTiming(keySize, inputSize[i],
					AES.OPERATION_MODE_CFB, AES.PADDING_TYPE_ISO10126d2);

			performEncryptDecryptTiming(keySize, inputSize[i],
					AES.OPERATION_MODE_OPENPGP, AES.PADDING_TYPE_X932);

			performEncryptDecryptTiming(keySize, inputSize[i],
					AES.OPERATION_MODE_CBC, AES.PADDING_TYPE_ZEROBYTE);
		}
	}

	/**
	 * Test the Key Generation Process
	 * 
	 * @param keySize
	 */
	private void testKeyGen(Integer keySize) {
		try {
			// Generate the AES key and display it
			byte[] key = symmetricCryptoUtils.aes_generateKey(keySize);
			log.info("[" + keySize + "] ---- Key Generation ---- ");
			log.info("[" + keySize + "] KEY= " + new String(Base64.encode(key)));
		} catch (CryptoUtilsException e) {

			log.error("KeyGen [" + keySize + "]= " + e.getMessage(),
					e.getCause());
		}
	}

	/**
	 * In this test a AES key is generated, then saved and loaded from a file
	 * finally the loaded key is compared with the original one
	 * 
	 * @param keySize
	 */
	private void testSaveAndLoadKeyFile(Integer keySize) {
		log.info("[" + keySize + "] ---- SAVE AND LOAD KEY FROM FILE---- ");
		try {
			byte[] key = symmetricCryptoUtils.aes_generateKey(keySize);
			String keyFileName = Environment.getExternalStorageDirectory()
					+ "/cryptoTest/AESkey" + keySize + ".key";
			String keyStr = new String(Base64.encode(key));

			log.info("[" + keySize + "] Original KEY= " + keyStr);

			symmetricCryptoUtils.aes_saveKeyToFile(key, keyFileName);
			byte[] recoveredKey = symmetricCryptoUtils.aes_getKey(keyFileName);
			String recoveredKeyStr = new String(Base64.encode(recoveredKey));
			log.info("[" + keySize + "] Recovered KEY= "
					+ new String(Base64.encode(recoveredKey)));
			log.info("[" + keySize + "] RES= "
					+ recoveredKeyStr.equalsIgnoreCase(keyStr));
		} catch (CryptoUtilsException e) {

			e.printStackTrace();
			log.error(
					"testSaveAndLoadKeyFile [" + keySize + "]= "
							+ e.getMessage(), e.getCause());
		}
	}

	/**
	 * Generates AES-keySize key, add it to an empty KeyStore, then the key is
	 * recovered from the key store and compared with the original one, finally
	 * the keystore is saved and loaded again in order to compare the loaded key
	 * with the original
	 * 
	 * @param keySize
	 */
	private void testAddKeyToKeyStore(Integer keySize) {
		String keyFileName = Environment.getExternalStorageDirectory()
				+ "/cryptoTest/TestAESKeyStore.ks";
		String keyStorePassword = "KSPASSWORD";
		KeyStoreUtil keyStoreUtil = new KeyStoreUtil();

		log.info("[" + keySize + "] ---- ADD AND GET KEY FROM KEY STORE ----");
		try {
			// Generates AES-keySize Key
			byte[] key = symmetricCryptoUtils.aes_generateKey(keySize);
			String keyStr = new String(Base64.encode(key));
			log.info("[" + keySize + "] Original KEY= " + keyStr);
			String alias = "SecretKey" + keySize;
			String keyPassword = "SecretKeyPassword" + keySize;

			// Creates an empty key store
			KeyStore ks = keyStoreUtil.createNewKeyStore();

			// Add the key to the key Store
			symmetricCryptoUtils.aes_addKeyToKeyStore(ks,
					symmetricCryptoUtils.aes_getSecretKey(key), alias,
					keyPassword);

			// Shows the generated key with the one saved in the key store
			log.info("[" + keySize + "] BEFORE SAVE");
			KeyStore.SecretKeyEntry entry = (SecretKeyEntry) ks.getEntry(alias,
					new KeyStore.PasswordProtection(keyPassword.toCharArray()));
			byte[] recoverKey = entry.getSecretKey().getEncoded();
			String recoverkeyStr = new String(Base64.encode(recoverKey));
			String res = (keyStr.equalsIgnoreCase(recoverkeyStr)) ? "OK"
					: "FAIL";
			log.info("[" + keySize + "] Recover KEY (SecretKey)= "
					+ recoverkeyStr + "  :" + res);

			SecretKey secret = (SecretKey) ks.getKey(alias,
					keyPassword.toCharArray());
			byte[] recoverKey2 = secret.getEncoded();
			String recoverkeyStr2 = new String(Base64.encode(recoverKey2));
			res = (keyStr.equalsIgnoreCase(recoverkeyStr2)) ? "OK" : "FAIL";
			log.info("[" + keySize + "] Recover KEY (SecretKey2)= "
					+ recoverkeyStr2 + "  :" + res);

			// Save and load the key Store
			keyStoreUtil.saveKeyStore(ks, keyFileName, keyStorePassword);
			ks = keyStoreUtil.loadKeyStore(keyFileName, keyStorePassword);

			// Get the key from key Store and compare it with the original one
			log.info("[" + keySize + "] AFTER LOAD");
			entry = (SecretKeyEntry) ks.getEntry(alias,
					new KeyStore.PasswordProtection(keyPassword.toCharArray()));
			recoverKey = entry.getSecretKey().getEncoded();
			recoverkeyStr = new String(Base64.encode(recoverKey));
			res = (keyStr.equalsIgnoreCase(recoverkeyStr)) ? "OK" : "FAIL";
			log.info("[" + keySize + "] Recover KEY (SecretKey)= "
					+ recoverkeyStr + "  :" + res);

			secret = (SecretKey) ks.getKey(alias, keyPassword.toCharArray());
			recoverKey2 = secret.getEncoded();
			recoverkeyStr2 = new String(Base64.encode(recoverKey2));
			res = (keyStr.equalsIgnoreCase(recoverkeyStr2)) ? "OK" : "FAIL";
			log.info("[" + keySize + "] Recover KEY (SecretKey2)= "
					+ recoverkeyStr2 + "  :" + res);

			// Test key extraction with wrong password
			log.info("[" + keySize + "] WRONG KEY PASSWORD");
			try {
				secret = (SecretKey) ks.getKey(alias,
						(keyPassword + "X").toCharArray());
			} catch (UnrecoverableKeyException e) {

				log.info("WRONG PASS EXCEPTION= " + e.getMessage());
			}

			// Test key extraction with wrong alias
			log.info("[" + keySize + "] WRONG KEY ALIAS");
			secret = (SecretKey) ks.getKey(alias + "X",
					keyPassword.toCharArray());
			if (secret == null) {
				log.info("WRONG ALIAS= OK");
			}

		} catch (CryptoUtilsException e) {

			log.error("ADD AND RECOVER KEY FROM KEY STORE= " + e.getMessage(),
					e.getCause());
		} catch (NoSuchAlgorithmException e) {

			log.error("ADD AND RECOVER KEY FROM KEY STORE= " + e.getMessage(),
					e.getCause());
		} catch (UnrecoverableEntryException e) {

			log.error("ADD AND RECOVER KEY FROM KEY STORE= " + e.getMessage(),
					e.getCause());
		} catch (KeyStoreException e) {

			log.error("ADD AND RECOVER KEY FROM KEY STORE= " + e.getMessage(),
					e.getCause());
		} catch (UnrecoverableKeyException e) {

			log.error("ADD AND RECOVER KEY FROM KEY STORE= " + e.getMessage(),
					e.getCause());
		}
	}

	/**
	 * Test AES encryption / Decryption using the Test vectors from the NIST
	 * standard tests, in this method only (CBC,CFB OFB) operation modes will be
	 * testes, using AES-128 and No padding
	 * 
	 */
	private void testEncryptDecryptStatic() {

		log.info("---- ENCRYPT DECRYPT STATIC----");

		byte[] cipher;
		byte[] decipher;
		String cipherStr;
		String decipherStr;
		String staticOutStr;
		String res;
		String resDe;
		String dataStr = new String(Hex.encode(tData));
		byte[] key;
		byte[] iv;
		String keyStr;

		key = Hex.decode("5F060D3716B345C253F6749ABAC10917");
		iv = new byte[16];
		keyStr = new String(Hex.encode(key));

		log.info("DATA= " + dataStr);
		log.info("KEY= " + keyStr);
		try {

			// Encrypt using AES 128, CBC operation mode and NO PADDING
			cipher = symmetricCryptoUtils.aes_encrypt(128, tData, key, iv,
					AES.OPERATION_MODE_CBC, AES.PADDING_TYPE_NO_PADDING);
			cipherStr = new String(Hex.encode(cipher));
			staticOutStr = new String(Hex.encode(outCBC1));
			res = cipherStr.equalsIgnoreCase(staticOutStr) ? "OK" : "FAIL";

			// Decrypt using AES 128, CBC operation mode and NO PADDING
			decipher = symmetricCryptoUtils.aes_decrypt(128, cipher, key, iv,
					AES.OPERATION_MODE_CBC, AES.PADDING_TYPE_NO_PADDING);
			decipherStr = new String(Hex.encode(decipher));
			resDe = decipherStr.equalsIgnoreCase(dataStr) ? "OK" : "FAIL";

			log.info("[CBC] ENCYPTED= " + cipherStr);
			log.info("[CBC] EXPECTED= " + staticOutStr);
			log.info("[CBC] RES ENC = " + res);
			log.info("[CBC] DATA ORI= " + dataStr);
			log.info("[CBC] DECYPTED= " + decipherStr);
			log.info("[CBC] RES DEC = " + resDe);

			// Encrypt using AES 128, OFB operation mode and NO PADDING
			cipher = symmetricCryptoUtils.aes_encrypt(128, tData, key, iv,
					AES.OPERATION_MODE_OFB, AES.PADDING_TYPE_NO_PADDING);
			cipherStr = new String(Hex.encode(cipher));
			staticOutStr = new String(Hex.encode(outOFB1));
			res = cipherStr.equalsIgnoreCase(staticOutStr) ? "OK" : "FAIL";
			// Decrypt using AES 128, CBC operation mode and NO PADDING
			decipher = symmetricCryptoUtils.aes_decrypt(128, cipher, key, iv,
					AES.OPERATION_MODE_OFB, AES.PADDING_TYPE_NO_PADDING);
			decipherStr = new String(Hex.encode(decipher));
			resDe = decipherStr.equalsIgnoreCase(dataStr) ? "OK" : "FAIL";

			log.info("[OFB] ENCYPTED= " + cipherStr);
			log.info("[OFB] EXPECTED= " + staticOutStr);
			log.info("[OFB] RES ENC = " + res);
			log.info("[OFB] DATA ORI= " + dataStr);
			log.info("[OFB] DECYPTED= " + decipherStr);
			log.info("[OFB] RES DEC = " + resDe);

			// Encrypt using AES 128, OFB operation mode and NO PADDING
			cipher = symmetricCryptoUtils.aes_encrypt(128, tData, key, iv,
					AES.OPERATION_MODE_CFB, AES.PADDING_TYPE_NO_PADDING);
			cipherStr = new String(Hex.encode(cipher));
			staticOutStr = new String(Hex.encode(outCFB1));
			res = cipherStr.equalsIgnoreCase(staticOutStr) ? "OK" : "FAIL";
			// Decrypt using AES 128, CBC operation mode and NO PADDING
			decipher = symmetricCryptoUtils.aes_decrypt(128, cipher, key, iv,
					AES.OPERATION_MODE_CFB, AES.PADDING_TYPE_NO_PADDING);
			decipherStr = new String(Hex.encode(decipher));
			resDe = decipherStr.equalsIgnoreCase(dataStr) ? "OK" : "FAIL";

			log.info("[CFB] ENCYPTED= " + cipherStr);
			log.info("[CFB] EXPECTED= " + staticOutStr);
			log.info("[CFB] RES ENC = " + res);
			log.info("[CFB] DATA ORI= " + dataStr);
			log.info("[CFB] DECYPTED= " + decipherStr);
			log.info("[CFB] RES DEC = " + resDe);

		} catch (CryptoUtilsException e) {

			log.error("ENCRYPT/DECRYPT: " + e.getMessage(), e.getCause());
		}

	}

	private void testEncryptDecryptAllRandom(int keySize, Boolean details,
			int inputSize, Boolean timing) {
		log.info("---- ENCRYPT DECRYPT RANDOM [" + keySize + "]----");

		byte[] key;
		byte[] data = new byte[inputSize];
		String keyStr;
		String dataStr;

		try {
			// Generate Key and random input data
			key = symmetricCryptoUtils.aes_generateKey(keySize);
			SecureRandom random = new SecureRandom();
			random.nextBytes(data);

			keyStr = new String(Base64.encode(key));
			dataStr = new String(Base64.encode(data));

			if (details) {
				log.info("KEY= " + keyStr);
				log.info("DATA= " + dataStr);
			}

			// Perform Test
			// CBC - With all the different padding types
			performEncryptDecrypt(keySize, data, key, AES.OPERATION_MODE_CBC,
					AES.PADDING_TYPE_NO_PADDING, details, timing);
			performEncryptDecrypt(keySize, data, key, AES.OPERATION_MODE_CBC,
					AES.PADDING_TYPE_ISO10126d2, details, timing);
			performEncryptDecrypt(keySize, data, key, AES.OPERATION_MODE_CBC,
					AES.PADDING_TYPE_ISO7816d4, details, timing);
			performEncryptDecrypt(keySize, data, key, AES.OPERATION_MODE_CBC,
					AES.PADDING_TYPE_PKCS7, details, timing);
			performEncryptDecrypt(keySize, data, key, AES.OPERATION_MODE_CBC,
					AES.PADDING_TYPE_X932, details, timing);
			performEncryptDecrypt(keySize, data, key, AES.OPERATION_MODE_CBC,
					AES.PADDING_TYPE_ZEROBYTE, details, timing);

			// CFB - With all the different padding types
			performEncryptDecrypt(keySize, data, key, AES.OPERATION_MODE_CFB,
					AES.PADDING_TYPE_NO_PADDING, details, timing);
			performEncryptDecrypt(keySize, data, key, AES.OPERATION_MODE_CFB,
					AES.PADDING_TYPE_ISO10126d2, details, timing);
			performEncryptDecrypt(keySize, data, key, AES.OPERATION_MODE_CFB,
					AES.PADDING_TYPE_ISO7816d4, details, timing);
			performEncryptDecrypt(keySize, data, key, AES.OPERATION_MODE_CFB,
					AES.PADDING_TYPE_PKCS7, details, timing);
			performEncryptDecrypt(keySize, data, key, AES.OPERATION_MODE_CFB,
					AES.PADDING_TYPE_X932, details, timing);
			performEncryptDecrypt(keySize, data, key, AES.OPERATION_MODE_CFB,
					AES.PADDING_TYPE_ZEROBYTE, details, timing);

			// OFB - With all the different padding types
			performEncryptDecrypt(keySize, data, key, AES.OPERATION_MODE_OFB,
					AES.PADDING_TYPE_NO_PADDING, details, timing);
			performEncryptDecrypt(keySize, data, key, AES.OPERATION_MODE_OFB,
					AES.PADDING_TYPE_ISO10126d2, details, timing);
			performEncryptDecrypt(keySize, data, key, AES.OPERATION_MODE_OFB,
					AES.PADDING_TYPE_ISO7816d4, details, timing);
			performEncryptDecrypt(keySize, data, key, AES.OPERATION_MODE_OFB,
					AES.PADDING_TYPE_PKCS7, details, timing);
			performEncryptDecrypt(keySize, data, key, AES.OPERATION_MODE_OFB,
					AES.PADDING_TYPE_X932, details, timing);
			performEncryptDecrypt(keySize, data, key, AES.OPERATION_MODE_OFB,
					AES.PADDING_TYPE_ZEROBYTE, details, timing);

			// OPENPGP - With all the different padding types
			performEncryptDecrypt(keySize, data, key,
					AES.OPERATION_MODE_OPENPGP, AES.PADDING_TYPE_NO_PADDING,
					details, timing);
			performEncryptDecrypt(keySize, data, key,
					AES.OPERATION_MODE_OPENPGP, AES.PADDING_TYPE_ISO10126d2,
					details, timing);
			performEncryptDecrypt(keySize, data, key,
					AES.OPERATION_MODE_OPENPGP, AES.PADDING_TYPE_ISO7816d4,
					details, timing);
			performEncryptDecrypt(keySize, data, key,
					AES.OPERATION_MODE_OPENPGP, AES.PADDING_TYPE_PKCS7,
					details, timing);
			performEncryptDecrypt(keySize, data, key,
					AES.OPERATION_MODE_OPENPGP, AES.PADDING_TYPE_X932, details,
					timing);
			performEncryptDecrypt(keySize, data, key,
					AES.OPERATION_MODE_OPENPGP, AES.PADDING_TYPE_ZEROBYTE,
					details, timing);

			// PGP - With all the different padding types
			/*
			 * performEncryptDecrypt(keySize, data, key, AES.OPERATION_MODE_PGP,
			 * AES.PADDING_TYPE_NO_PADDING, details, timing);
			 * performEncryptDecrypt(keySize, data, key, AES.OPERATION_MODE_PGP,
			 * AES.PADDING_TYPE_ISO10126d2, details, timing);
			 * performEncryptDecrypt(keySize, data, key, AES.OPERATION_MODE_PGP,
			 * AES.PADDING_TYPE_ISO7816d4, details, timing);
			 * performEncryptDecrypt(keySize, data, key, AES.OPERATION_MODE_PGP,
			 * AES.PADDING_TYPE_PKCS7, details, timing);
			 * performEncryptDecrypt(keySize, data, key, AES.OPERATION_MODE_PGP,
			 * AES.PADDING_TYPE_X932, details, timing);
			 * performEncryptDecrypt(keySize, data, key, AES.OPERATION_MODE_PGP,
			 * AES.PADDING_TYPE_ZEROBYTE, details, timing);
			 */

		} catch (CryptoUtilsException e) {

			log.error("ENCRYPT/DECRYPT: " + e.getMessage(), e.getCause());
		}

	}

	private void testEncryptDecryptRandom(int keySize, Boolean details,
			int inputSize, Boolean timing) {
		log.info("---- ENCRYPT DECRYPT RANDOM [" + keySize + "]----");

		byte[] key;
		byte[] data = new byte[inputSize];
		String keyStr;
		String dataStr;

		try {
			// Generate Key and random input data
			key = symmetricCryptoUtils.aes_generateKey(keySize);
			SecureRandom random = new SecureRandom();
			random.nextBytes(data);

			keyStr = new String(Base64.encode(key));
			dataStr = new String(Base64.encode(data));

			if (details) {
				log.info("KEY= " + keyStr);
				log.info("DATA= " + dataStr);
			}

			String[] availableOperationMode = { AES.OPERATION_MODE_CBC,
					AES.OPERATION_MODE_CFB, AES.OPERATION_MODE_OFB,
					AES.OPERATION_MODE_OPENPGP };
			String[] availablePaddings = { AES.PADDING_TYPE_NO_PADDING,
					AES.PADDING_TYPE_ISO10126d2, AES.PADDING_TYPE_ISO7816d4,
					AES.PADDING_TYPE_PKCS7, AES.PADDING_TYPE_X932,
					AES.PADDING_TYPE_ZEROBYTE };

			int randomOperationMode = random
					.nextInt(availableOperationMode.length);
			int randomPadding = random.nextInt(availablePaddings.length);

			// Perform Test using a random padding with a random operation mode
			performEncryptDecrypt(keySize, data, key,
					availableOperationMode[randomOperationMode],
					availablePaddings[randomPadding], details, timing);

		} catch (CryptoUtilsException e) {

			log.error("ENCRYPT/DECRYPT: " + e.getMessage(), e.getCause());
		}

	}

	private void performEncryptDecrypt(int keySize, byte[] data, byte[] key,
			String operationMode, String paddingStyle, Boolean details,
			Boolean timing) {
		byte[] cipher;
		byte[] decipher;
		byte[] iv = new byte[16];

		String cipherStr;
		String decipherStr;
		String res;
		String dataStr;
		dataStr = new String(Base64.encode(data));
		try {
			if (timing) {
				performEncryptDecryptTiming(keySize, data.length,
						operationMode, paddingStyle);
				return;
			}
			// Encrypt using the specified parameters
			cipher = symmetricCryptoUtils.aes_encrypt(keySize, data, key, iv,
					operationMode, paddingStyle);
			cipherStr = new String(Base64.encode(cipher));

			// Decrypt using the specified parameters
			decipher = symmetricCryptoUtils.aes_decrypt(keySize, cipher, key,
					iv, operationMode, paddingStyle);

			decipherStr = new String(Base64.encode(decipher));
			res = decipherStr.equalsIgnoreCase(dataStr) ? "OK" : "FAIL";

			log.info("[" + keySize + ": " + operationMode + " - "
					+ paddingStyle + "] - " + res);

			if (details) {
				log.info("ENCYPTED= " + cipherStr);
				log.info("DECYPTED= " + decipherStr);
			}
		} catch (CryptoUtilsException e) {

			log.error("[" + keySize + ": " + operationMode + " - "
					+ paddingStyle + "] - ENCRYPT/DECRYPT P: " + e.getMessage());
		}
	}

	private void performEncryptDecryptTiming(int keySize, int inputSize,
			String operationMode, String paddingStyle) {
		byte[] cipher;
		byte[] decipher;
		byte[] iv = new byte[16];
		byte[] key;
		byte[] data = new byte[inputSize];
		long startnowCipher;
		long startnowDecipher;
		long endnowCipher;
		long endnowDecipher;
		long totalCipher = 0;
		long totalDecipher = 0;

		int totalRounds = 50;
		try {

			for (int i = 0; i < totalRounds; i++) {
				// Generate Key and random input data
				key = symmetricCryptoUtils.aes_generateKey(keySize);
				random.nextBytes(data);

				for (int j = 0; j < totalRounds; j++) {
					startnowCipher = java.lang.System.nanoTime();
					cipher = symmetricCryptoUtils.aes_encrypt(keySize, data,
							key, iv, operationMode, paddingStyle);
					endnowCipher = java.lang.System.nanoTime();
					totalCipher += (endnowCipher - startnowCipher);

					startnowDecipher = java.lang.System.nanoTime();
					decipher = symmetricCryptoUtils.aes_decrypt(keySize,
							cipher, key, iv, operationMode, paddingStyle);
					endnowDecipher = java.lang.System.nanoTime();
					totalDecipher += (endnowDecipher - startnowDecipher);
				}

			}

			String totalCipherStr = "[" + keySize + " - " + inputSize + ": "
					+ operationMode + " - " + paddingStyle + "] - CIPHER= "
					+ (totalCipher / (totalRounds * totalRounds * 1.0));
			String totalDecipherStr = "[" + keySize + " - " + inputSize + ": "
					+ operationMode + " - " + paddingStyle + "] - DECIPHER= "
					+ (totalDecipher / (totalRounds * totalRounds * 1.0));
			log.info(totalCipherStr);
			log.toFile(totalCipherStr, logFileName);
			log.info(totalDecipherStr);
			log.toFile(totalDecipherStr, logFileName);

		} catch (CryptoUtilsException e) {

			log.error("[" + keySize + " - " + inputSize + ": " + operationMode
					+ " - " + paddingStyle + "] - ENCRYPT/DECRYPT P: "
					+ e.getMessage());
			log.toFile("[" + keySize + " - " + inputSize + ": " + operationMode
					+ " - " + paddingStyle + "] - ENCRYPT/DECRYPT P: ",
					logFileName);
		}
	}

	/**
	 * Times the save and load to key store operation
	 * 
	 * @param keySize
	 */
	private void testAddKeyToKeyStoreTiming(Integer keySize) {
		String keyFileName = Environment.getExternalStorageDirectory()
				+ "/cryptoTest/TestAESKeyStore.ks";
		String keyStorePassword = "KSPASSWORD";
		KeyStoreUtil keyStoreUtil = new KeyStoreUtil();
		int totalRounds = 10;
		byte[] key;
		String alias = "SecretKey" + keySize;
		String keyPassword = "SecretKeyPassword" + keySize;
		KeyStore ks;
		KeyStore.SecretKeyEntry entry;
		byte[] recoverKey;

		long startnowSave;
		long startnowLoad;
		long endnowSave;
		long endnowLoad;
		long totalSave = 0;
		long totalLoad = 0;
		//

		try {

			// Creates an empty key store
			ks = keyStoreUtil.createNewKeyStore();
			for (int i = 0; i < totalRounds; i++) {

				// Generates AES-keySize Key
				key = symmetricCryptoUtils.aes_generateKey(keySize);

				for (int j = 0; j < totalRounds; j++) {

					startnowSave = java.lang.System.nanoTime();

					// Add the key to the key Store
					symmetricCryptoUtils.aes_addKeyToKeyStore(ks,
							symmetricCryptoUtils.aes_getSecretKey(key), alias,
							keyPassword);

					// Save and load the key Store
					keyStoreUtil
							.saveKeyStore(ks, keyFileName, keyStorePassword);
					endnowSave = java.lang.System.nanoTime();
					totalSave += (endnowSave - startnowSave);

					startnowLoad = java.lang.System.nanoTime();
					ks = keyStoreUtil.loadKeyStore(keyFileName,
							keyStorePassword);

					// Get the key from key Store and compare it with the
					// original one
					entry = (SecretKeyEntry) ks.getEntry(
							alias,
							new KeyStore.PasswordProtection(keyPassword
									.toCharArray()));
					recoverKey = entry.getSecretKey().getEncoded();
					endnowLoad = java.lang.System.nanoTime();
					totalLoad += (endnowLoad - startnowLoad);
				}
			}

			String totalSaveStr = "[" + keySize + "] TOKEYSTORE= " + "  SAVE:"
					+ (totalSave / (totalRounds * totalRounds * 1.0));
			String totalLoadStr = "[" + keySize + "] TOKEYSTORE= " + "  LOAD:"
					+ (totalLoad / (totalRounds * totalRounds * 1.0));
			log.info(totalSaveStr);
			log.toFile(totalSaveStr, logFileName);
			log.info(totalLoadStr);
			log.toFile(totalLoadStr, logFileName);

		} catch (CryptoUtilsException e) {

			log.error("ADD AND RECOVER KEY FROM KEY STORE= " + e.getMessage(),
					e.getCause());
			log.toFile("ADD AND RECOVER KEY FROM KEY STORE= " + e.getMessage(),
					logFileName);
		} catch (NoSuchAlgorithmException e) {

			log.error("ADD AND RECOVER KEY FROM KEY STORE= " + e.getMessage(),
					e.getCause());
			log.toFile("ADD AND RECOVER KEY FROM KEY STORE= " + e.getMessage(),
					logFileName);
		} catch (UnrecoverableEntryException e) {

			log.error("ADD AND RECOVER KEY FROM KEY STORE= " + e.getMessage(),
					e.getCause());
			log.toFile("ADD AND RECOVER KEY FROM KEY STORE= " + e.getMessage(),
					logFileName);
		} catch (KeyStoreException e) {

			log.error("ADD AND RECOVER KEY FROM KEY STORE= " + e.getMessage(),
					e.getCause());
			log.toFile("ADD AND RECOVER KEY FROM KEY STORE= " + e.getMessage(),
					logFileName);
		}
	}

	/**
	 * Timing the save and load AES key functions
	 * 
	 * @param keySize
	 */
	private void testSaveAndLoadKeyFileTiming(Integer keySize) {

		long startnowSave;
		long startnowLoad;
		long endnowSave;
		long endnowLoad;
		long totalSave = 0;
		long totalLoad = 0;
		byte[] key;
		String keyFileName = Environment.getExternalStorageDirectory()
				+ "/cryptoTest/AESkey" + keySize + ".key";
		byte[] recoveredKey;
		int totalRounds = 100;

		try {
			for (int i = 0; i < totalRounds; i++) {

				// Generates AES-keySize Key
				key = symmetricCryptoUtils.aes_generateKey(keySize);

				for (int j = 0; j < totalRounds; j++) {
					startnowSave = java.lang.System.nanoTime();
					symmetricCryptoUtils.aes_saveKeyToFile(key, keyFileName);
					endnowSave = java.lang.System.nanoTime();
					totalSave += (endnowSave - startnowSave);

					startnowLoad = java.lang.System.nanoTime();
					recoveredKey = symmetricCryptoUtils.aes_getKey(keyFileName);
					endnowLoad = java.lang.System.nanoTime();
					totalLoad += (endnowLoad - startnowLoad);
				}
			}

			String totalSaveStr = "[" + keySize + "] TOFILE= " + "  SAVE:"
					+ (totalSave / (totalRounds * totalRounds * 1.0));
			String totalLoadStr = "[" + keySize + "] TOFILE= " + "  LOAD:"
					+ (totalLoad / (totalRounds * totalRounds * 1.0));
			log.info(totalSaveStr);
			log.toFile(totalSaveStr, logFileName);
			log.info(totalLoadStr);
			log.toFile(totalLoadStr, logFileName);

		} catch (CryptoUtilsException e) {

			e.printStackTrace();
			log.error(
					"testSaveAndLoadKeyFile [" + keySize + "]= "
							+ e.getMessage(), e.getCause());
			log.toFile(
					"testSaveAndLoadKeyFile [" + keySize + "]= "
							+ e.getMessage(), logFileName);
		}
	}

	/**
	 * Timing the Key Generation Process
	 * 
	 * @param keySize
	 */
	private void testKeyGenTiming(Integer keySize) {
		long startnow;
		long endnow;
		long total = 0;
		int totalRounds = 100;

		try {
			for (int i = 0; i < totalRounds; i++) {
				for (int j = 0; j < totalRounds; j++) {
					startnow = java.lang.System.nanoTime();
					symmetricCryptoUtils.aes_generateKey(keySize);
					endnow = java.lang.System.nanoTime();
					total += (endnow - startnow);
				}
			}

			String totalStr = "[" + keySize + "] KEYGEN= "
					+ (total / (totalRounds * totalRounds * 1.0));
			log.info(totalStr);
			log.toFile(totalStr, logFileName);
		} catch (CryptoUtilsException e) {

			log.error("KeyGen [" + keySize + "]= " + e.getMessage(),
					e.getCause());
			log.toFile("KeyGen [" + keySize + "]= " + e.getMessage(),
					logFileName);
		}
	}
}
