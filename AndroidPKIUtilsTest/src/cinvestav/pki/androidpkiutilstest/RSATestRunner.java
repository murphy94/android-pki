/**
 *  Created on  : 21/04/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	
 */
package cinvestav.pki.androidpkiutilstest;

import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.encoders.Hex;

import android.os.Environment;
import cinvestav.android.pki.cryptography.algorithm.RSA;
import cinvestav.android.pki.cryptography.cert.CertificateInformationKeys;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsX509ExtensionException;
import cinvestav.android.pki.cryptography.key.RSAKeyPair;
import cinvestav.android.pki.cryptography.key.RSAPrivateKey;
import cinvestav.android.pki.cryptography.key.RSAPublicKey;
import cinvestav.android.pki.cryptography.utils.AsymmetricCryptoUtils;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;
import cinvestav.android.pki.cryptography.utils.X509Utils;
import cinvestav.android.pki.cryptography.utils.X509UtilsDictionary;
import cinvestav.android.pki.utils.LogUtil;

/**
 * @author Ing. Javier Silva Pérez - [javier]
 * 
 */
public class RSATestRunner {

	// public static final String TAG = "SCCIPHERTEST";
	protected static LogUtil log = new LogUtil("ANDROID_PKI_UTILS");
	private AsymmetricCryptoUtils asymmetricCryptoUtils;
	private String defaultEncoder = CryptoUtils.ENCODER_HEX;
	private X509Utils _X509Utils;
	String logFileName = "performance_rsa_d1";
	SecureRandom rand;

	public RSATestRunner() throws CryptoUtilsException {
		asymmetricCryptoUtils = new AsymmetricCryptoUtils();
		rand = new SecureRandom();
		try {
			_X509Utils = new X509Utils();
		} catch (CryptoUtilsException e) {

			e.printStackTrace();
			log.error("testX509CertificateV3 = " + e.getMessage(), e.getCause());
		}
	}

	public void runTest(Boolean detailResult) {
		Integer keySizeInBits = 1024;
		log.info(" ********* RSA " + keySizeInBits + " Test Begin *********");
		runTest(keySizeInBits, detailResult);

		keySizeInBits = 2048;
		log.info(" ********* RSA " + keySizeInBits + " Test Begin *********");
		// runTest(keySizeInBits, detailResult);
	}

	public void runTestTiming() {

		log.toFile("***************************************", logFileName);
		
		/*testKeyGenTiming(1024);
		testKeyGenTiming(2048);
		testKeyGenTiming(4096);

		testSaveAndLoadKeyFileTiming(1024);
		testSaveAndLoadKeyFileTiming(2048);
		testSaveAndLoadKeyFileTiming(4096);

		testEncryptDecryptRandomTiming(1024, 1024);
		testEncryptDecryptRandomTiming(1024, 3072);
		testEncryptDecryptRandomTiming(2048, 1024);
		testEncryptDecryptRandomTiming(2048, 3072);
		testEncryptDecryptRandomTiming(4096, 1024);
		testEncryptDecryptRandomTiming(4096, 3072);

		testSignVerifyRandomTiming(1024, 1024);
		testSignVerifyRandomTiming(1024, 3072);
		testSignVerifyRandomTiming(2048, 1024);
		testSignVerifyRandomTiming(2048, 3072);*/
		testSignVerifyRandomTiming(4096, 1024);
		testSignVerifyRandomTiming(4096, 3072);
	}

	private void runTest(Integer keySizeInBits, Boolean detailResult) {
		try {
			testKeyGen(keySizeInBits);

			testEncodeDecodeKey(keySizeInBits, detailResult);
			testSaveAndLoadKeyFile(keySizeInBits, detailResult);

			SecureRandom secureRandom = new SecureRandom();
			for (int i = 0; i < 10; i++) {
				int inputSize = secureRandom.nextInt(8192);
				log.info("---- Input Size: " + inputSize + " ---- ");
				// testEncryptDecryptRandom(keySizeInBits, detailResult,
				// inputSize);
				// testSignVerigyRandom(keySizeInBits, detailResult, inputSize);
			}

			// testSignVerigyRandom(keySizeInBits, detailResult, 512);
			/*
			 * testEncryptDecryptRandom(keySizeInBits, detailResult, 8192);
			 * testEncryptDecryptRandom(keySizeInBits, detailResult, 4096);
			 * testEncryptDecryptRandom(keySizeInBits, detailResult, 2048);
			 * testEncryptDecryptRandom(keySizeInBits, detailResult, 1024);
			 * testEncryptDecryptRandom(keySizeInBits, detailResult, 512);
			 * testEncryptDecryptRandom(keySizeInBits, detailResult, 256);
			 * testEncryptDecryptRandom(keySizeInBits, detailResult, 127);
			 * testEncryptDecryptRandom(keySizeInBits, detailResult, 12);
			 */
		} catch (CryptoUtilsException e) {

			e.printStackTrace();
		}
	}

	/**
	 * Test the Key Generation Process
	 * 
	 * @param keySizeInBits
	 * @throws CryptoUtilsException
	 */
	private void testKeyGen(Integer keySizeInBits) throws CryptoUtilsException {
		log.info("[" + keySizeInBits + "] ---- Key Generation ---- ");
		// Generate the RSA key and display it
		RSAKeyPair key;
		key = asymmetricCryptoUtils.generateKeys(keySizeInBits);

		log.info("[" + keySizeInBits + "] KEY = "
				+ key.toString(defaultEncoder));
	}

	/**
	 * Timing the Key Generation Process
	 * 
	 * @param keySizeInBits
	 * @throws CryptoUtilsException
	 */
	private void testKeyGenTiming(Integer keySizeInBits) {
		long startnow;
		long endnow;
		long total = 0;
		int totalRounds = 10;

		RSAKeyPair key;

		for (int j = 0; j < totalRounds; j++) {
			try {
				// Generate the RSA key
				startnow = java.lang.System.nanoTime();

				key = asymmetricCryptoUtils.generateKeys(keySizeInBits);
				endnow = java.lang.System.nanoTime();
				total += (endnow - startnow);
			} catch (CryptoUtilsException e) {
				e.printStackTrace();
				log.toFile("GenerateKey = " + e.getMessage(), logFileName);

			}
		}

		String totalStr = "[" + keySizeInBits + "] KEYGEN= "
				+ (total / (totalRounds * 1.0));
		log.info(totalStr);
		log.toFile(totalStr, logFileName);

	}

	private void testEncryptDecryptRandom(int primeSize, Boolean details,
			int inputSize) throws CryptoUtilsException {
		log.info("---- ENCRYPT DECRYPT RANDOM [" + inputSize + "]----");

		RSAKeyPair key;
		byte[] data = new byte[inputSize];
		String dataStr;

		// Generate Key and random input data
		key = asymmetricCryptoUtils.generateKeys(primeSize);
		SecureRandom random = new SecureRandom();
		random.nextBytes(data);

		// keyStr = new String(Base64.encode(key));
		if (defaultEncoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
			dataStr = new String(Base64.encode(data));
		} else {
			dataStr = new String(Hex.encode(data));
		}

		if (details) {
			// log.info("KEY= " + keyStr);
			log.info("DATA= " + dataStr);
		}

		log.info("---- BYTES ----");
		// Perform Test
		// OAEP
		performEncryptDecrypt(data, key.getPublicKey(), key.getPrivateKey(),
				RSA.OPERATION_MODE_OAEP, details, primeSize);
		// PKCS1
		performEncryptDecrypt(data, key.getPublicKey(), key.getPrivateKey(),
				RSA.OPERATION_MODE_PKCS1, details, primeSize);
		// ISO9796d1
		performEncryptDecrypt(data, key.getPublicKey(), key.getPrivateKey(),
				RSA.OPERATION_MODE_ISO9796d1, details, primeSize);

		log.info("---- STR - Base64 ----");
		dataStr = new String(Base64.encode(data));
		// Perform Test
		// OAEP
		performEncryptDecrypt(dataStr, key.getPublicKey(), key.getPrivateKey(),
				RSA.OPERATION_MODE_OAEP, details, primeSize,
				CryptoUtils.ENCODER_BASE64);
		// PKCS1
		performEncryptDecrypt(dataStr, key.getPublicKey(), key.getPrivateKey(),
				RSA.OPERATION_MODE_PKCS1, details, primeSize,
				CryptoUtils.ENCODER_BASE64);
		// ISO9796d1
		performEncryptDecrypt(dataStr, key.getPublicKey(), key.getPrivateKey(),
				RSA.OPERATION_MODE_ISO9796d1, details, primeSize,
				CryptoUtils.ENCODER_BASE64);

		log.info("---- STR - HEX ----");
		dataStr = new String(Hex.encode(data));
		// Perform Test
		// OAEP
		performEncryptDecrypt(dataStr, key.getPublicKey(), key.getPrivateKey(),
				RSA.OPERATION_MODE_OAEP, details, primeSize,
				CryptoUtils.ENCODER_HEX);
		// PKCS1
		performEncryptDecrypt(dataStr, key.getPublicKey(), key.getPrivateKey(),
				RSA.OPERATION_MODE_PKCS1, details, primeSize,
				CryptoUtils.ENCODER_HEX);
		// ISO9796d1
		performEncryptDecrypt(dataStr, key.getPublicKey(), key.getPrivateKey(),
				RSA.OPERATION_MODE_ISO9796d1, details, primeSize,
				CryptoUtils.ENCODER_HEX);

	}

	private void testSignVerifyRandom(int primeSize, Boolean details,
			int inputSize) throws CryptoUtilsException {
		log.info("---- SIGN VERIFY RANDOM [" + inputSize + "]----");

		RSAKeyPair key;
		byte[] data = new byte[inputSize];
		String dataStr;

		// Generate Key and random input data
		key = asymmetricCryptoUtils.generateKeys(primeSize);
		SecureRandom random = new SecureRandom();
		random.nextBytes(data);

		// keyStr = new String(Base64.encode(key));
		if (defaultEncoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
			dataStr = new String(Base64.encode(data));
		} else {
			dataStr = new String(Hex.encode(data));
		}

		if (details) {
			// log.info("KEY= " + keyStr);
			log.info("DATA= " + dataStr);
		}

		// Perform Test
		// SHA-1
		performSignVerify(data, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_SHA_1, details, primeSize,
				Boolean.FALSE);
		// SHA-224
		performSignVerify(data, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_SHA_224, details, primeSize,
				Boolean.FALSE);
		// SHA-256
		performSignVerify(data, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_SHA_256, details, primeSize,
				Boolean.FALSE);
		// SHA-384
		performSignVerify(data, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_SHA_384, details, primeSize,
				Boolean.FALSE);
		// SHA-512
		performSignVerify(data, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_SHA_512, details, primeSize,
				Boolean.FALSE);

		// MD2
		performSignVerify(data, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_MD2, details, primeSize,
				Boolean.FALSE);
		// MD4
		performSignVerify(data, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_MD4, details, primeSize,
				Boolean.FALSE);
		// MD5
		performSignVerify(data, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_MD5, details, primeSize,
				Boolean.FALSE);

		// RIPEMD128
		performSignVerify(data, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_RIPEMD128, details, primeSize,
				Boolean.FALSE);
		// RIPEMD160
		performSignVerify(data, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_RIPEMD160, details, primeSize,
				Boolean.FALSE);
		// RIPEMD256
		performSignVerify(data, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_RIPEMD256, details, primeSize,
				Boolean.FALSE);

		String encoder;
		encoder = CryptoUtils.ENCODER_HEX;
		// SHA-1
		performSignVerigy(dataStr, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_SHA_1, encoder, details, primeSize,
				Boolean.FALSE);
		// SHA-224
		performSignVerigy(dataStr, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_SHA_224, encoder, details,
				primeSize, Boolean.FALSE);
		// SHA-256
		performSignVerigy(dataStr, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_SHA_256, encoder, details,
				primeSize, Boolean.FALSE);
		// SHA-384
		performSignVerigy(dataStr, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_SHA_384, encoder, details,
				primeSize, Boolean.FALSE);
		// SHA-512
		performSignVerigy(dataStr, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_SHA_512, encoder, details,
				primeSize, Boolean.FALSE);

		// MD2
		performSignVerigy(dataStr, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_MD2, encoder, details, primeSize,
				Boolean.FALSE);
		// MD4
		performSignVerigy(dataStr, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_MD4, encoder, details, primeSize,
				Boolean.FALSE);
		// MD5
		performSignVerigy(dataStr, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_MD5, encoder, details, primeSize,
				Boolean.FALSE);

		// RIPEMD128
		performSignVerigy(dataStr, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_RIPEMD128, encoder, details,
				primeSize, Boolean.FALSE);
		// RIPEMD160
		performSignVerigy(dataStr, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_RIPEMD160, encoder, details,
				primeSize, Boolean.FALSE);
		// RIPEMD256
		performSignVerigy(dataStr, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_RIPEMD256, encoder, details,
				primeSize, Boolean.FALSE);

		encoder = CryptoUtils.ENCODER_BASE64;
		// SHA-1
		performSignVerigy(dataStr, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_SHA_1, encoder, details, primeSize,
				Boolean.FALSE);
		// SHA-224
		performSignVerigy(dataStr, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_SHA_224, encoder, details,
				primeSize, Boolean.FALSE);
		// SHA-256
		performSignVerigy(dataStr, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_SHA_256, encoder, details,
				primeSize, Boolean.FALSE);
		// SHA-384
		performSignVerigy(dataStr, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_SHA_384, encoder, details,
				primeSize, Boolean.FALSE);
		// SHA-512
		performSignVerigy(dataStr, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_SHA_512, encoder, details,
				primeSize, Boolean.FALSE);

		// MD2
		performSignVerigy(dataStr, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_MD2, encoder, details, primeSize,
				Boolean.FALSE);
		// MD4
		performSignVerigy(dataStr, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_MD4, encoder, details, primeSize,
				Boolean.FALSE);
		// MD5
		performSignVerigy(dataStr, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_MD5, encoder, details, primeSize,
				Boolean.FALSE);

		// RIPEMD128
		performSignVerigy(dataStr, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_RIPEMD128, encoder, details,
				primeSize, Boolean.FALSE);
		// RIPEMD160
		performSignVerigy(dataStr, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_RIPEMD160, encoder, details,
				primeSize, Boolean.FALSE);
		// RIPEMD256
		performSignVerigy(dataStr, key.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_RIPEMD256, encoder, details,
				primeSize, Boolean.FALSE);

		// Change the public or private key
		RSAKeyPair keyS = asymmetricCryptoUtils.generateKeys(primeSize);
		// SHA-1
		performSignVerify(data, keyS.getPublicKey(), key.getPrivateKey(),
				CryptoUtils.DIGEST_FUNCTION_SHA_1, details, primeSize,
				Boolean.TRUE);

	}

	/**
	 * Perform Encrypt/Decrypt test with the input data, in this test data is
	 * encrypted, then decrypted and compared if the result at the end of the
	 * process is the same as the input the result will be OK otherwise FAIL
	 * 
	 * @param data
	 * @param publicKey
	 * @param privateKey
	 * @param operationMode
	 * @param details
	 * @param primeSize
	 */
	private void performEncryptDecrypt(byte[] data, RSAPublicKey publicKey,
			RSAPrivateKey privateKey, String operationMode, Boolean details,
			Integer primeSize) {
		List<byte[]> cipher;
		byte[] decipher;

		String cipherStr;
		String decipherStr;
		String res;
		String dataStr;
		if (defaultEncoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
			dataStr = new String(Base64.encode(data));
		} else {
			dataStr = new String(Hex.encode(data));
		}
		try {
			// Encrypt using the specified parameters
			cipher = asymmetricCryptoUtils.encrypt(data, publicKey,
					operationMode);
			if (defaultEncoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
				cipherStr = new String(Base64.encode(cipher.get(0)));
			} else {
				cipherStr = new String(Hex.encode(cipher.get(0)));
			}

			// Decrypt using the specified parameters
			decipher = asymmetricCryptoUtils.decrypt(cipher.get(0),
					cipher.get(1), privateKey, operationMode);

			if (defaultEncoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
				decipherStr = new String(Base64.encode(decipher));
			} else {
				decipherStr = new String(Hex.encode(decipher));
			}

			res = decipherStr.equalsIgnoreCase(dataStr) ? "OK" : "FAIL";

			log.info("[" + primeSize + ": " + operationMode + " - " + "] - "
					+ res);
			if (details) {
				log.info("ENCYPTED= " + cipherStr);
				log.info("DECYPTED= " + decipherStr);
			}
		} catch (CryptoUtilsException e) {

			log.error("ENCRYPT/DECRYPT P: " + e.getMessage());
		}
	}

	/**
	 * Perform Encrypt/Decrypt test with the input data, in this test data is
	 * encrypted, then decrypted and compared if the result at the end of the
	 * process is the same as the input the result will be OK otherwise FAIL
	 * 
	 * @param data
	 * @param publicKey
	 * @param privateKey
	 * @param operationMode
	 * @param details
	 * @param primeSize
	 */
	private void performEncryptDecrypt(String data, RSAPublicKey publicKey,
			RSAPrivateKey privateKey, String operationMode, Boolean details,
			Integer primeSize, String encoder) {
		List<String> cipher;
		String decipher;
		String res;
		// dataStr = new String(Base64.encode(data));
		try {
			// Encrypt using the specified parameters
			cipher = asymmetricCryptoUtils.encrypt(data, publicKey, encoder,
					operationMode);
			// cipherStr = new String(Base64.encode(cipher.get(0)));

			// Decrypt using the specified parameters
			decipher = asymmetricCryptoUtils.decrypt(cipher.get(0),
					cipher.get(1), privateKey, encoder, operationMode);

			// decipherStr = new String(Base64.encode(decipher));
			res = decipher.equalsIgnoreCase(data) ? "OK" : "FAIL";

			log.info("[" + primeSize + ": " + operationMode + " - " + "] - "
					+ res);
			if (details) {
				log.info("ENCYPTED= " + cipher);
				log.info("DECYPTED= " + decipher);
			}
		} catch (CryptoUtilsException e) {

			log.error("ENCRYPT/DECRYPT P: " + e.getMessage());
		}
	}

	/**
	 * Perform the signing of a message and the verification of that signature
	 * and determine if its correct or not
	 * 
	 * @param data
	 *            Data to be signed
	 * @param publicKey
	 *            Public key to verify the sign
	 * @param privateKey
	 *            Private Key to sign the data
	 * @param digestName
	 *            name of the digest Function to use in the signature
	 * @param details
	 *            if the test should write detail result to the log
	 * @param primeSize
	 *            The key prime size that is been using in this test
	 * @param tamperParams
	 *            If FALSE, the verification should be true so the result of the
	 *            test will be OK, but when TRUE, indicates that one of the
	 *            parameters is tampered (sign, data or wrong public-private
	 *            keys) are using so the result of the verification is false,
	 *            but the result of the test is OK
	 */
	private void performSignVerify(byte[] data, RSAPublicKey publicKey,
			RSAPrivateKey privateKey, String digestName, Boolean details,
			Integer primeSize, Boolean tamperParams) {
		byte[] sign;
		Boolean verifyResult;

		String signStr;
		String res;
		String dataStr;
		if (defaultEncoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
			dataStr = new String(Base64.encode(data));
		} else {
			dataStr = new String(Hex.encode(data));
		}

		try {
			// Sign using the specified parameters
			sign = asymmetricCryptoUtils.sign(data, privateKey, digestName);

			if (defaultEncoder.equalsIgnoreCase(CryptoUtils.ENCODER_BASE64)) {
				signStr = new String(Base64.encode(sign));
			} else {
				signStr = new String(Hex.encode(sign));
			}

			// Verify using the specified parameters
			verifyResult = asymmetricCryptoUtils.verify(data, sign, publicKey,
					digestName);

			res = verifyResult || tamperParams ? "OK" : "FAIL";

			log.info("[" + primeSize + ": " + digestName + " - BYTE" + "] - "
					+ res);
			if (details) {
				log.info("SIGN= " + signStr);
				log.info("VERIFY RES= " + verifyResult);
			}
		} catch (CryptoUtilsException e) {

			log.error("SIGN/VERIFY Error: " + e.getMessage());
		}
	}

	/**
	 * Perform the signing of a message and the verification of that signature
	 * and determine if its correct or not
	 * 
	 * @param data
	 *            Data to be signed
	 * @param publicKey
	 *            Public key to verify the sign
	 * @param privateKey
	 *            Private Key to sign the data
	 * @param digestName
	 *            name of the digest Function to use in the signature
	 * @param encoder
	 *            Encoder for the result
	 * @param details
	 *            if the test should write detail result to the log
	 * @param primeSize
	 *            The key prime size that is been using in this test
	 * @param tamperParams
	 *            If FALSE, the verification should be true so the result of the
	 *            test will be OK, but when TRUE, indicates that one of the
	 *            parameters is tampered (sign, data or wrong public-private
	 *            keys) are using so the result of the verification is false,
	 *            but the result of the test is OK
	 */
	private void performSignVerigy(String data, RSAPublicKey publicKey,
			RSAPrivateKey privateKey, String digestName, String encoder,
			Boolean details, Integer primeSize, Boolean tamperParams) {
		Boolean verifyResult;

		String signStr;
		String res;
		String dataStr;

		try {
			// Sign using the specified parameters
			signStr = asymmetricCryptoUtils.sign(data, privateKey, digestName,
					encoder);

			// Verify using the specified parameters
			verifyResult = asymmetricCryptoUtils.verify(data, signStr,
					publicKey, digestName, encoder);

			res = verifyResult || tamperParams ? "OK" : "FAIL";

			log.info("[" + primeSize + ": " + digestName + " - STR - "
					+ encoder + "] - " + res);
			if (details) {
				log.info("SIGN= " + signStr);
				log.info("VERIFY RES= " + verifyResult);
			}
		} catch (CryptoUtilsException e) {

			log.error("SIGN/VERIFY Error: " + e.getMessage());
		}
	}

	/**
	 * In this test a RSA key pair is generated, then saved and loaded from a
	 * file finally the loaded key is compared with the original one
	 * 
	 * @param keySize
	 */
	private void testSaveAndLoadKeyFile(Integer primeSize, Boolean detailResult) {
		log.info("[" + primeSize + "] ---- SAVE AND LOAD KEY FROM FILE---- ");
		try {
			RSAKeyPair key;

			// Generate Key and random input data
			key = asymmetricCryptoUtils.generateKeys(primeSize);

			String keyFileName = Environment.getExternalStorageDirectory()
					+ "/cryptoTest/RSAkey" + primeSize;
			File f = new File(keyFileName);
			if (!f.getParentFile().exists()) {
				f.getParentFile().mkdir();
			}
			if (detailResult)
				log.info("[" + primeSize + "] Original KEY= "
						+ key.toString(defaultEncoder));

			// testPKCS8PEMPrivateKey(key, keyFileName, primeSize,
			// detailResult);
			// testPKCS8DERPrivateKey(key, keyFileName, primeSize,
			// detailResult);
			testPKCS8DERPublicKey(key, keyFileName, primeSize, detailResult);

		} catch (CryptoUtilsException e) {
			e.printStackTrace();
			log.error(
					"testSaveAndLoadKeyFile [" + primeSize + "]= "
							+ e.getMessage(), e.getCause());
		}
	}

	/**
	 * Timing the process for saving a RSA Keys
	 * 
	 * @param keySize
	 */
	private void testSaveAndLoadKeyFileTiming(Integer primeSize) {
		try {

			RSAKeyPair key;
			key = asymmetricCryptoUtils.generateKeys(primeSize);

			String keyFileName = Environment.getExternalStorageDirectory()
					+ "/cryptoTest/RSAkey" + primeSize;
			File f = new File(keyFileName);
			if (!f.getParentFile().exists()) {
				f.getParentFile().mkdir();
			}

			testPKCS8DERPublicKeyTiming(key, keyFileName, primeSize);
			testPKCS8PEMPrivateKeyTiming(key, keyFileName, primeSize);

		} catch (CryptoUtilsException e) {
			e.printStackTrace();
			log.error("TimingSaveAndLoadKeyFile = " + e.getMessage(),
					e.getCause());
			log.toFile("TimingSaveAndLoadKeyFile = " + e.getMessage(),
					logFileName);
		}
	}

	/**
	 * In this test a RSA key pair is generated, then encoded and decoded,
	 * finally the decoded key is compared with the original one
	 * 
	 * @param keySize
	 */
	private void testEncodeDecodeKey(Integer primeSize, Boolean detailResult) {
		log.info("[" + primeSize + "] ---- ENCODE AND DECODE KEY ---- ");
		try {
			RSAKeyPair key;
			RSAPrivateKey resPrivateKey;
			RSAPublicKey resPublicKey;
			RSAKeyPair resKey;
			String res;

			// Generate Key and random input data
			key = asymmetricCryptoUtils.generateKeys(primeSize);
			String password = "PASSWORD";
			// String keyStr = "";
			byte[] keyBytes;

			if (detailResult)
				log.info("[" + primeSize + "] Original KEY= "
						+ key.toString(defaultEncoder));

			// Start ENCODE - DECODE Private Key test
			keyBytes = key.getPrivateKey().encode(password);
			// keyStr = new String(keyBytes);
			resPrivateKey = RSAPrivateKey.decode(keyBytes, password);

			if (detailResult) {
				log.info("[" + primeSize + "] Recovered Private KEY= "
						+ resPrivateKey.toString(defaultEncoder));
			}

			res = resPrivateKey.equals(key.getPrivateKey()) ? "OK" : "FAIL";
			log.info("[" + primeSize + "] RES PRIVATE KEY= " + res);

			// Start ENCODE - DECODE Public Key test
			keyBytes = key.getPublicKey().encode();
			// keyStr = new String(keyBytes);
			resPublicKey = RSAPublicKey.decode(keyBytes);

			if (detailResult)
				log.info("[" + primeSize + "] Recovered Public KEY= "
						+ resPublicKey.toString(defaultEncoder));

			res = resPublicKey.equals(key.getPublicKey()) ? "OK" : "FAIL";
			log.info("[" + primeSize + "] RES PUBLIC KEY= " + res);

			// Start ENCODE - DECODE PKCS12 test
			Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60
					* 60 * 24 * 30);
			Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60
					* 60 * 24 * 30);

			Certificate[] chain;

			List<Integer> keyUsageList;
			String certType;
			certType = X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA;
			keyUsageList = new LinkedList<Integer>();
			keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
			keyUsageList
					.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
			keyUsageList
					.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
			keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
			keyUsageList
					.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);

			HashMap<String, String> subject1CertificateInformationMap = new HashMap<String, String>();
			subject1CertificateInformationMap.put(
					CertificateInformationKeys.FRIENDLY_NAME, "Subject1");
			subject1CertificateInformationMap.put(
					CertificateInformationKeys.COUNTRY, "MX");
			subject1CertificateInformationMap.put(
					CertificateInformationKeys.EmailAddress,
					"subject1@gmail.com");
			subject1CertificateInformationMap.put(
					CertificateInformationKeys.FULL_COMMON_NAME,
					"Subject1 Name Master");
			subject1CertificateInformationMap.put(
					CertificateInformationKeys.LOCALITY, "GAM");
			subject1CertificateInformationMap.put(
					CertificateInformationKeys.STATE, "DF");
			subject1CertificateInformationMap.put(
					CertificateInformationKeys.ORGANIZATION, "Cinvestav");
			// Creates Root CA self signed certificate
			chain = new Certificate[1];
			chain[0] = _X509Utils.createV3Cert(key.getPublicKey(),
					key.getPrivateKey(), BigInteger.valueOf(1), notBefore,
					notAfter, subject1CertificateInformationMap, keyUsageList,
					certType,
					X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_SHA1withRSA);

			keyBytes = key.encodePKCS12(password, password, chain);
			// keyStr = new String(keyBytes);
			Object[] resObj = RSAKeyPair.decodePKCS12(keyBytes, password,
					password);
			resKey = (RSAKeyPair) resObj[0];

			if (detailResult)
				log.info("[" + primeSize + "] Recovered Key Pair= "
						+ resKey.toString(defaultEncoder));

			res = resKey.equals(key) ? "OK" : "FAIL";
			log.info("[" + primeSize + "] RES KEY PAIR= " + res);

		} catch (CryptoUtilsException e) {
			e.printStackTrace();
			log.error(
					"testEncodeDecodeKey [" + primeSize + "]= "
							+ e.getMessage(), e.getCause());
		} catch (CryptoUtilsX509ExtensionException e) {

			e.printStackTrace();
			log.error(
					"testEncodeDecodeKey [" + primeSize + "]= "
							+ e.getMessage(), e.getCause());
		}
	}

	/**
	 * Test save and read the private key in PKCS8 format, will test PEM
	 * encoding as well as encrypted (using different algorithms) and plain
	 * storage
	 * 
	 * @param keyPair
	 *            Key Pair that contains the private key
	 * @param filePath
	 *            File Path in which the keys will be stored
	 * @param primeSize
	 * @param detailResult
	 *            If the result should print the details
	 * @throws CryptoUtilsException
	 */
	private void testPKCS8PEMPrivateKey(RSAKeyPair keyPair, String filePath,
			Integer primeSize, Boolean detailResult)
			throws CryptoUtilsException {
		RSAPrivateKey privateKeyOriginal = keyPair.getPrivateKey();
		RSAPrivateKey privateKeyRecovered;

		String fileSufix = "";
		String algorithm = "";
		String password = "PASSWORD";
		String algorithmName = "";
		String res = "";
		// Start Plain PEM Private Key test
		log.info("[" + primeSize + "] - PEM Private Key-");
		fileSufix = "PEM_Priv_Plain.pem";
		privateKeyOriginal.savePKCS8PEM(filePath + fileSufix);

		privateKeyRecovered = RSAPrivateKey.loadPKCS8PEM(filePath + fileSufix);

		if (detailResult)
			log.info("[" + primeSize + "] Recovered PEM KEY= "
					+ privateKeyRecovered.toString(defaultEncoder));

		res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + primeSize + "] RES PEM PLAIN= " + res);

		// Start Encrypted PKCS8 PEM Private Key test
		algorithm = CryptoUtils.AES_128_CBC;
		algorithmName = "AES_128_CBC";
		fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
				password);
		privateKeyRecovered = RSAPrivateKey.loadPKCS8PEM(filePath + fileSufix,
				password);

		if (detailResult)
			log.info("[" + primeSize + "] Recovered PEM - " + algorithmName
					+ " KEY= " + privateKeyRecovered.toString(defaultEncoder));

		res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " + res);

		algorithm = CryptoUtils.AES_192_CBC;
		algorithmName = "AES_192_CBC";
		fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
				password);
		privateKeyRecovered = RSAPrivateKey.loadPKCS8PEM(filePath + fileSufix,
				password);

		if (detailResult)
			log.info("[" + primeSize + "] Recovered PEM - " + algorithmName
					+ " KEY= " + privateKeyRecovered.toString(defaultEncoder));
		res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " + res);

		algorithm = CryptoUtils.AES_256_CBC;
		algorithmName = "AES_256_CBC";
		fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
				password);
		privateKeyRecovered = RSAPrivateKey.loadPKCS8PEM(filePath + fileSufix,
				password);

		if (detailResult)
			log.info("[" + primeSize + "] Recovered PEM - " + algorithmName
					+ " KEY= " + privateKeyRecovered.toString(defaultEncoder));
		res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " + res);

		algorithm = CryptoUtils.DES3_CBC;
		algorithmName = "DES3_CBC";
		fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
				password);
		privateKeyRecovered = RSAPrivateKey.loadPKCS8PEM(filePath + fileSufix,
				password);

		if (detailResult)
			log.info("[" + primeSize + "] Recovered PEM - " + algorithmName
					+ " KEY= " + privateKeyRecovered.toString(defaultEncoder));
		res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " + res);

		algorithm = CryptoUtils.PBE_SHA1_2DES;
		algorithmName = "PBE_SHA1_2DES";
		fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
				password);
		privateKeyRecovered = RSAPrivateKey.loadPKCS8PEM(filePath + fileSufix,
				password);

		if (detailResult)
			log.info("[" + primeSize + "] Recovered PEM - " + algorithmName
					+ " KEY= " + privateKeyRecovered.toString(defaultEncoder));
		res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " + res);

		algorithm = CryptoUtils.PBE_SHA1_3DES;
		algorithmName = "PBE_SHA1_3DES";
		fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
				password);
		privateKeyRecovered = RSAPrivateKey.loadPKCS8PEM(filePath + fileSufix,
				password);

		if (detailResult)
			log.info("[" + primeSize + "] Recovered PEM - " + algorithmName
					+ " KEY= " + privateKeyRecovered.toString(defaultEncoder));
		res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " + res);

		algorithm = CryptoUtils.PBE_SHA1_RC2_128;
		algorithmName = "PBE_SHA1_RC2_128";
		fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
				password);
		privateKeyRecovered = RSAPrivateKey.loadPKCS8PEM(filePath + fileSufix,
				password);

		if (detailResult)
			log.info("[" + primeSize + "] Recovered PEM - " + algorithmName
					+ " KEY= " + privateKeyRecovered.toString(defaultEncoder));
		res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " + res);

		algorithm = CryptoUtils.PBE_SHA1_RC2_40;
		algorithmName = "PBE_SHA1_RC2_40";
		fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
				password);
		privateKeyRecovered = RSAPrivateKey.loadPKCS8PEM(filePath + fileSufix,
				password);

		if (detailResult)
			log.info("[" + primeSize + "] Recovered PEM - " + algorithmName
					+ " KEY= " + privateKeyRecovered.toString(defaultEncoder));
		res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " + res);

		algorithm = CryptoUtils.PBE_SHA1_RC4_128;
		algorithmName = "PBE_SHA1_RC4_128";
		fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
				password);
		privateKeyRecovered = RSAPrivateKey.loadPKCS8PEM(filePath + fileSufix,
				password);

		if (detailResult)
			log.info("[" + primeSize + "] Recovered PEM - " + algorithmName
					+ " KEY= " + privateKeyRecovered.toString(defaultEncoder));
		res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " + res);

		algorithm = CryptoUtils.PBE_SHA1_RC4_40;
		algorithmName = "PBE_SHA1_RC4_40";
		fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
				password);
		privateKeyRecovered = RSAPrivateKey.loadPKCS8PEM(filePath + fileSufix,
				password);

		if (detailResult)
			log.info("[" + primeSize + "] Recovered PEM - " + algorithmName
					+ " KEY= " + privateKeyRecovered.toString(defaultEncoder));
		res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " + res);

	}

	/**
	 * Test save and read the private key in PKCS8 format, will test DER
	 * encoding as well as encrypted (using different algorithms) and plain
	 * storage
	 * 
	 * @param keyPair
	 *            Key Pair that contains the private key
	 * @param filePath
	 *            File Path in which the keys will be stored
	 * @param primeSize
	 * @param detailResult
	 *            If the result should print the details
	 * @throws CryptoUtilsException
	 */
	private void testPKCS8DERPrivateKey(RSAKeyPair keyPair, String filePath,
			Integer primeSize, Boolean detailResult)
			throws CryptoUtilsException {
		RSAPrivateKey privateKeyOriginal = keyPair.getPrivateKey();
		RSAPrivateKey privateKeyRecovered;

		String fileSufix = "";
		String algorithm = "";
		String password = "PASSWORD";
		String algorithmName = "";
		String res = "";
		// Start Plain PEM Private Key test
		log.info("[" + primeSize + "] - DER Private Key-");
		fileSufix = "DER_Priv_Plain.der";
		privateKeyOriginal.savePKCS8DER(filePath + fileSufix);

		privateKeyRecovered = RSAPrivateKey.loadPKCS8DER(filePath + fileSufix);

		if (detailResult)
			log.info("[" + primeSize + "] Recovered DER KEY= "
					+ privateKeyRecovered.toString(defaultEncoder));

		res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + primeSize + "] RES DER PLAIN= " + res);

		// Start Encrypted PKCS8 PEM Private Key test
		/*
		 * algorithm = RSAPrivateKey.AES_128_CBC; algorithmName = "AES_128_CBC";
		 * fileSufix = "DER_Priv_Enc" + algorithmName + ".der";
		 * privateKeyOriginal.savePKCS8DER(filePath + fileSufix, algorithm,
		 * password);
		 * 
		 * //privateKeyRecovered.readPKCS8DER(filePath + fileSufix, password);
		 * privateKeyRecovered
		 * .readPKCS8DER(Environment.getExternalStorageDirectory() +
		 * "/cryptoTest/pkcs8v2_rsa_aes128_cbc.der", password);
		 */

		/*
		 * if (detailResult) log.info("[" + primeSize + "] Recovered PEM - " +
		 * algorithmName + " KEY= " +
		 * privateKeyRecovered.toString(defaultEncoder));
		 * 
		 * res = privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		 * log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " +
		 * res);
		 * 
		 * algorithm = RSAPrivateKey.AES_192_CBC; algorithmName = "AES_192_CBC";
		 * fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		 * privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
		 * password); privateKeyRecovered.loadPKCS8PEM(filePath + fileSufix,
		 * password);
		 * 
		 * if (detailResult) log.info("[" + primeSize + "] Recovered PEM - " +
		 * algorithmName + " KEY= " +
		 * privateKeyRecovered.toString(defaultEncoder)); res =
		 * privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		 * log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " +
		 * res);
		 * 
		 * algorithm = RSAPrivateKey.AES_256_CBC; algorithmName = "AES_256_CBC";
		 * fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		 * privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
		 * password); privateKeyRecovered.loadPKCS8PEM(filePath + fileSufix,
		 * password);
		 * 
		 * if (detailResult) log.info("[" + primeSize + "] Recovered PEM - " +
		 * algorithmName + " KEY= " +
		 * privateKeyRecovered.toString(defaultEncoder)); res =
		 * privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		 * log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " +
		 * res);
		 * 
		 * algorithm = RSAPrivateKey.DES3_CBC; algorithmName = "DES3_CBC";
		 * fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		 * privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
		 * password); privateKeyRecovered.loadPKCS8PEM(filePath + fileSufix,
		 * password);
		 * 
		 * if (detailResult) log.info("[" + primeSize + "] Recovered PEM - " +
		 * algorithmName + " KEY= " +
		 * privateKeyRecovered.toString(defaultEncoder)); res =
		 * privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		 * log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " +
		 * res);
		 * 
		 * algorithm = RSAPrivateKey.PBE_SHA1_2DES; algorithmName =
		 * "PBE_SHA1_2DES"; fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		 * privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
		 * password); privateKeyRecovered.loadPKCS8PEM(filePath + fileSufix,
		 * password);
		 * 
		 * if (detailResult) log.info("[" + primeSize + "] Recovered PEM - " +
		 * algorithmName + " KEY= " +
		 * privateKeyRecovered.toString(defaultEncoder)); res =
		 * privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		 * log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " +
		 * res);
		 * 
		 * algorithm = RSAPrivateKey.PBE_SHA1_3DES; algorithmName =
		 * "PBE_SHA1_3DES"; fileSufix = "PEM_Priv_Enc" + algorithmName + ".pem";
		 * privateKeyOriginal.savePKCS8PEM(filePath + fileSufix, algorithm,
		 * password); privateKeyRecovered.loadPKCS8PEM(filePath + fileSufix,
		 * password);
		 * 
		 * if (detailResult) log.info("[" + primeSize + "] Recovered PEM - " +
		 * algorithmName + " KEY= " +
		 * privateKeyRecovered.toString(defaultEncoder)); res =
		 * privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		 * log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " +
		 * res);
		 * 
		 * algorithm = RSAPrivateKey.PBE_SHA1_RC2_128; algorithmName =
		 * "PBE_SHA1_RC2_128"; fileSufix = "PEM_Priv_Enc" + algorithmName +
		 * ".pem"; privateKeyOriginal.savePKCS8PEM(filePath + fileSufix,
		 * algorithm, password); privateKeyRecovered.loadPKCS8PEM(filePath +
		 * fileSufix, password);
		 * 
		 * if (detailResult) log.info("[" + primeSize + "] Recovered PEM - " +
		 * algorithmName + " KEY= " +
		 * privateKeyRecovered.toString(defaultEncoder)); res =
		 * privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		 * log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " +
		 * res);
		 * 
		 * algorithm = RSAPrivateKey.PBE_SHA1_RC2_40; algorithmName =
		 * "PBE_SHA1_RC2_40"; fileSufix = "PEM_Priv_Enc" + algorithmName +
		 * ".pem"; privateKeyOriginal.savePKCS8PEM(filePath + fileSufix,
		 * algorithm, password); privateKeyRecovered.loadPKCS8PEM(filePath +
		 * fileSufix, password);
		 * 
		 * if (detailResult) log.info("[" + primeSize + "] Recovered PEM - " +
		 * algorithmName + " KEY= " +
		 * privateKeyRecovered.toString(defaultEncoder)); res =
		 * privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		 * log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " +
		 * res);
		 * 
		 * algorithm = RSAPrivateKey.PBE_SHA1_RC4_128; algorithmName =
		 * "PBE_SHA1_RC4_128"; fileSufix = "PEM_Priv_Enc" + algorithmName +
		 * ".pem"; privateKeyOriginal.savePKCS8PEM(filePath + fileSufix,
		 * algorithm, password); privateKeyRecovered.loadPKCS8PEM(filePath +
		 * fileSufix, password);
		 * 
		 * if (detailResult) log.info("[" + primeSize + "] Recovered PEM - " +
		 * algorithmName + " KEY= " +
		 * privateKeyRecovered.toString(defaultEncoder)); res =
		 * privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		 * log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " +
		 * res);
		 * 
		 * algorithm = RSAPrivateKey.PBE_SHA1_RC4_40; algorithmName =
		 * "PBE_SHA1_RC4_40"; fileSufix = "PEM_Priv_Enc" + algorithmName +
		 * ".pem"; privateKeyOriginal.savePKCS8PEM(filePath + fileSufix,
		 * algorithm, password); privateKeyRecovered.loadPKCS8PEM(filePath +
		 * fileSufix, password);
		 * 
		 * if (detailResult) log.info("[" + primeSize + "] Recovered PEM - " +
		 * algorithmName + " KEY= " +
		 * privateKeyRecovered.toString(defaultEncoder)); res =
		 * privateKeyRecovered.equals(privateKeyOriginal) ? "OK" : "FAIL";
		 * log.info("[" + primeSize + "] RES PEM - " + algorithmName + "= " +
		 * res);
		 */
	}

	/**
	 * Test save and read the private key in PKCS8 format, will test DER
	 * encoding as well as encrypted (using different algorithms) and plain
	 * storage
	 * 
	 * @param keyPair
	 *            Key Pair that contains the private key
	 * @param filePath
	 *            File Path in which the keys will be stored
	 * @param primeSize
	 * @param detailResult
	 *            If the result should print the details
	 * @throws CryptoUtilsException
	 */
	private void testPKCS8DERPublicKey(RSAKeyPair keyPair, String filePath,
			Integer primeSize, Boolean detailResult)
			throws CryptoUtilsException {
		RSAPublicKey publicKeyOriginal = keyPair.getPublicKey();
		RSAPublicKey publicKeyRecovered;

		String fileSufix = "";
		String res = "";
		// Start Plain PEM Private Key test
		log.info("[" + primeSize + "] - DER Public Key-");
		fileSufix = "DER_Pub.der";
		publicKeyOriginal.saveDER(filePath + fileSufix);

		publicKeyRecovered = RSAPublicKey.loadDER(filePath + fileSufix);

		if (detailResult)
			log.info("[" + primeSize + "] Recovered DER KEY= "
					+ publicKeyRecovered.toString(defaultEncoder));

		res = publicKeyRecovered.equals(publicKeyOriginal) ? "OK" : "FAIL";
		log.info("[" + primeSize + "] RES DER PUBLIC= " + res);
	}

	private String describe(Object obj) {
		if (obj instanceof KeyPair) {
			return describeKeyPair((KeyPair) obj);
		}
		return obj.toString();
	}

	private String describeKeyPair(KeyPair kp) {
		return describe("privateKey=" + kp.getPrivate() + " publicKey="
				+ kp.getPublic());
	}

	/**
	 * Timing save and read the private key in PKCS8 format, will test DER
	 * encoding
	 * 
	 * @param keyPair
	 *            Key Pair that contains the private key
	 * @param filePath
	 *            File Path in which the keys will be stored
	 * @param primeSize
	 * @param detailResult
	 *            If the result should print the details
	 * @throws CryptoUtilsException
	 */
	private void testPKCS8DERPublicKeyTiming(RSAKeyPair keyPair,
			String filePath, Integer primeSize) throws CryptoUtilsException {
		RSAPublicKey publicKeyOriginal = keyPair.getPublicKey();

		String fileSufix = "";

		fileSufix = "DER_Pub.der";

		long startnow;
		long endnow;
		long total = 0;
		long startnowAux;
		long endnowAux;
		long totalAux = 0;
		int totalRounds = 100;

		try {
			for (int i = 0; i < totalRounds; i++) {
				for (int j = 0; j < totalRounds; j++) {
					// Start Plain DER Public Key test
					startnow = java.lang.System.nanoTime();
					publicKeyOriginal.saveDER(filePath + fileSufix);
					endnow = java.lang.System.nanoTime();
					total += (endnow - startnow);

					startnowAux = java.lang.System.nanoTime();
					RSAPublicKey.loadDER(filePath + fileSufix);
					endnowAux = java.lang.System.nanoTime();
					totalAux += (endnowAux - startnowAux);
				}
			}

			String totalStr = "[" + primeSize + "] PUBLIC DER SAVE= "
					+ (total / (totalRounds * totalRounds * 1.0));
			String totalAuxStr = "[" + primeSize + "] PUBLIC DER LOAD= "
					+ (totalAux / (totalRounds * totalRounds * 1.0));
			log.info(totalStr);
			log.toFile(totalStr, logFileName);
			log.info(totalAuxStr);
			log.toFile(totalAuxStr, logFileName);
		} catch (CryptoUtilsException e) {

			log.error(
					"KeyGen [" + primeSize + "]= SAVE/LOAD DER PUBLIC: "
							+ e.getMessage(), e.getCause());
			log.toFile(
					"KeyGen [" + primeSize + "]= SAVE/LOAD DER PUBLIC: "
							+ e.getMessage(), logFileName);
		}
	}

	/**
	 * Timing save and read the private key in PKCS8 format, will test PEM
	 * encoding as well as encrypted (using different algorithms) and plain
	 * storage
	 * 
	 * @param keyPair
	 *            Key Pair that contains the private key
	 * @param filePath
	 *            File Path in which the keys will be stored
	 * @param primeSize
	 * @param detailResult
	 *            If the result should print the details
	 * @throws CryptoUtilsException
	 */
	private void testPKCS8PEMPrivateKeyTiming(RSAKeyPair keyPair,
			String filePath, Integer primeSize) throws CryptoUtilsException {
		RSAPrivateKey privateKeyOriginal = keyPair.getPrivateKey();

		String fileSufix = "";
		String algorithm = "";
		String password = "PASSWORD";
		long startnow;
		long endnow;
		long total = 0;
		long startnowAux;
		long endnowAux;
		long totalAux = 0;
		int totalRounds = 50;
		String totalStr = "";
		String totalAuxStr = "";

		fileSufix = "PEM_Priv_Plain.pem";

		for (int i = 0; i < totalRounds; i++) {
			for (int j = 0; j < totalRounds; j++) {
				// Start Plain PEM Private Key timing
				startnow = java.lang.System.nanoTime();
				privateKeyOriginal.savePKCS8PEM(filePath + fileSufix);
				endnow = java.lang.System.nanoTime();
				total += (endnow - startnow);

				startnowAux = java.lang.System.nanoTime();
				RSAPrivateKey.loadPKCS8PEM(filePath + fileSufix);
				endnowAux = java.lang.System.nanoTime();
				totalAux += (endnowAux - startnowAux);
			}
		}

		totalStr = "[" + primeSize + "] PRIVATE PEM PLAIN SAVE= "
				+ (total / (totalRounds * totalRounds * 1.0));
		totalAuxStr = "[" + primeSize + "] PRIVATE PEM PLAIN LOAD= "
				+ (totalAux / (totalRounds * totalRounds * 1.0));
		log.info(totalStr);
		log.toFile(totalStr, logFileName);
		log.info(totalAuxStr);
		log.toFile(totalAuxStr, logFileName);

		// Create available algorithms array
		String[] availableAlgorithm = { CryptoUtils.AES_256_CBC,
				CryptoUtils.PBE_SHA1_3DES };
		int selectedAlgorithm;

		for (selectedAlgorithm = 0; selectedAlgorithm < 2; selectedAlgorithm++) {
			// Restart counters
			startnow = 0;
			endnow = 0;
			total = 0;
			startnowAux = 0;
			endnowAux = 0;
			totalAux = 0;
			totalStr = "";
			totalAuxStr = "";
			totalRounds = 10;
			algorithm = availableAlgorithm[selectedAlgorithm];
			for (int i = 0; i < totalRounds; i++) {
				for (int j = 0; j < totalRounds; j++) {
					// Start Plain PEM Private Key timing
					startnow = java.lang.System.nanoTime();
					privateKeyOriginal.savePKCS8PEM(filePath + fileSufix,
							algorithm, password);
					endnow = java.lang.System.nanoTime();
					total += (endnow - startnow);

					startnowAux = java.lang.System.nanoTime();
					RSAPrivateKey.loadPKCS8PEM(filePath + fileSufix, password);
					endnowAux = java.lang.System.nanoTime();
					totalAux += (endnowAux - startnowAux);
				}
			}

			totalStr = "[" + primeSize + "] PRIVATE PEM " + algorithm
					+ " SAVE= " + (total / (totalRounds * totalRounds * 1.0));
			totalAuxStr = "[" + primeSize + "] PRIVATE PEM " + algorithm
					+ " LOAD= "
					+ (totalAux / (totalRounds * totalRounds * 1.0));
			log.info(totalStr);
			log.toFile(totalStr, logFileName);
			log.info(totalAuxStr);
			log.toFile(totalAuxStr, logFileName);
		}

	}

	/**
	 * Timing save and read the private key in PKCS8 format, will test DER
	 * encoding with plain storage
	 * 
	 * @param keyPair
	 *            Key Pair that contains the private key
	 * @param filePath
	 *            File Path in which the keys will be stored
	 * @param primeSize
	 * @param detailResult
	 *            If the result should print the details
	 * @throws CryptoUtilsException
	 */
	private void testPKCS8DERPrivateKeyTiming(RSAKeyPair keyPair,
			String filePath, Integer primeSize) throws CryptoUtilsException {
		RSAPrivateKey privateKeyOriginal = keyPair.getPrivateKey();
		String fileSufix = "DER_Priv_Plain.der";

		long startnow;
		long endnow;
		long total = 0;
		long startnowAux;
		long endnowAux;
		long totalAux = 0;
		int totalRounds = 50;

		try {
			for (int i = 0; i < totalRounds; i++) {
				for (int j = 0; j < totalRounds; j++) {
					// Start Plain PEM Private Key test
					startnow = java.lang.System.nanoTime();
					privateKeyOriginal.savePKCS8DER(filePath + fileSufix);
					endnow = java.lang.System.nanoTime();
					total += (endnow - startnow);

					startnowAux = java.lang.System.nanoTime();
					RSAPrivateKey.loadPKCS8DER(filePath + fileSufix);

					endnowAux = java.lang.System.nanoTime();
					totalAux += (endnowAux - startnowAux);
				}
			}

			String totalStr = "[" + primeSize + "] PRIVATE DER SAVE= "
					+ (total / (totalRounds * totalRounds * 1.0));
			String totalAuxStr = "[" + primeSize + "] PRIVATE DER LOAD= "
					+ (totalAux / (totalRounds * totalRounds * 1.0));
			log.info(totalStr);
			log.info(totalAuxStr);
		} catch (CryptoUtilsException e) {

			log.error(
					"KeyGen [" + primeSize + "]= SAVE/LOAD DER PRIVATE: "
							+ e.getMessage(), e.getCause());
		}

	}

	private void testEncryptDecryptRandomTiming(int primeSize, int inputSize) {

		RSAKeyPair key;

		// Generate Key and random input data
		try {
			key = asymmetricCryptoUtils.generateKeys(primeSize);

			String[] availableMode = { RSA.OPERATION_MODE_OAEP,
					RSA.OPERATION_MODE_PKCS1, RSA.OPERATION_MODE_ISO9796d1 };

			for (int i = 0; i < availableMode.length; i++) {
				// Perform Test EncryptDecryptTest
				performEncryptDecryptTiming(inputSize, key.getPublicKey(),
						key.getPrivateKey(), availableMode[i], primeSize);
			}
		} catch (CryptoUtilsException e) {
			log.error(
					"[" + primeSize + "]= ENCRYPT/DECRYPT -" + e.getMessage(),
					e.getCause());

		}

	}

	private void testSignVerifyRandomTiming(int primeSize, int inputSize) {

		RSAKeyPair key;

		// Generate Key and random input data
		try {
			key = asymmetricCryptoUtils.generateKeys(primeSize);

			String[] availableDigest = { CryptoUtils.DIGEST_FUNCTION_SHA_1,
					CryptoUtils.DIGEST_FUNCTION_SHA_256,
					CryptoUtils.DIGEST_FUNCTION_SHA_512,
					CryptoUtils.DIGEST_FUNCTION_MD5,
					CryptoUtils.DIGEST_FUNCTION_RIPEMD160 };

			for (int selectedDigest = 0; selectedDigest < availableDigest.length; selectedDigest++) {
				// Perform the sign / verify timing using a random digest
				performSignVerifyTiming(inputSize, key.getPublicKey(),
						key.getPrivateKey(), availableDigest[selectedDigest],
						primeSize);
			}

		} catch (CryptoUtilsException e) {
			log.error(
					"[" + primeSize + "]= ENCRYPT/DECRYPT -" + e.getMessage(),
					e.getCause());

		}

	}

	/**
	 * Timing Encrypt/Decrypt test with the input data, in this test data is
	 * encrypted, then decrypted and compared if the result at the end of the
	 * process is the same as the input the result will be OK otherwise FAIL
	 * 
	 * @param data
	 * @param publicKey
	 * @param privateKey
	 * @param operationMode
	 * @param details
	 * @param primeSize
	 */
	private void performEncryptDecryptTiming(int inputSize,
			RSAPublicKey publicKey, RSAPrivateKey privateKey,
			String operationMode, Integer primeSize) {
		List<byte[]> cipher;

		byte[] data = new byte[inputSize];
		long startnow;
		long endnow;
		long total = 0;
		long startnowAux;
		long endnowAux;
		long totalAux = 0;
		int totalRounds = 30;

		for (int i = 0; i < totalRounds; i++) {
			rand.nextBytes(data);
			for (int j = 0; j < totalRounds; j++) {
				// Encrypt using the specified parameters
				try {
					startnow = java.lang.System.nanoTime();
					cipher = asymmetricCryptoUtils.encrypt(data, publicKey,
							operationMode);
					endnow = java.lang.System.nanoTime();
					total += (endnow - startnow);

					startnowAux = java.lang.System.nanoTime();
					// Decrypt using the specified parameters
					asymmetricCryptoUtils.decrypt(cipher.get(0), cipher.get(1),
							privateKey, operationMode);
					endnowAux = java.lang.System.nanoTime();
					totalAux += (endnowAux - startnowAux);

				} catch (CryptoUtilsException e) {
					log.error("[" + primeSize + "]= ENCRYPT/DECRYPT -"
							+ operationMode + ": " + e.getMessage(),
							e.getCause());
					log.toFile(
							"[" + primeSize + " - " + inputSize
									+ "]= ENCRYPT/DECRYPT -" + operationMode
									+ ": " + e.getMessage(), logFileName);
				}
			}
		}

		String totalStr = "[" + primeSize + " - " + inputSize
				+ "] ENCRIPT RSA-" + operationMode + "= "
				+ (total / (totalRounds * totalRounds * 1.0));
		String totalAuxStr = "[" + primeSize + " - " + inputSize
				+ "] DECRIPT RSA-" + operationMode + "= "
				+ (totalAux / (totalRounds * totalRounds * 1.0));
		log.info(totalStr);
		log.toFile(totalStr, logFileName);
		log.info(totalAuxStr);
		log.toFile(totalAuxStr, logFileName);

	}

	/**
	 * timing the signing of a message and the verification of that signature
	 * and determine if its correct or not
	 * 
	 * @param data
	 *            Data to be signed
	 * @param publicKey
	 *            Public key to verify the sign
	 * @param privateKey
	 *            Private Key to sign the data
	 * @param digestName
	 *            name of the digest Function to use in the signature
	 * @param primeSize
	 *            The key prime size that is been using in this test
	 */
	private void performSignVerifyTiming(int inputSize, RSAPublicKey publicKey,
			RSAPrivateKey privateKey, String digestName, Integer primeSize) {
		byte[] sign;

		byte[] data = new byte[inputSize];
		long startnow;
		long endnow;
		long total = 0;
		long startnowAux;
		long endnowAux;
		long totalAux = 0;
		int totalRounds = 30;

		for (int i = 0; i < totalRounds; i++) {
			rand.nextBytes(data);
			for (int j = 0; j < totalRounds; j++) {

				try {
					startnow = java.lang.System.nanoTime();
					// Sign using the specified parameters
					sign = asymmetricCryptoUtils.sign(data, privateKey,
							digestName);
					endnow = java.lang.System.nanoTime();
					total += (endnow - startnow);

					startnowAux = java.lang.System.nanoTime();
					// Verify using the specified parameters
					asymmetricCryptoUtils.verify(data, sign, publicKey,
							digestName);
					endnowAux = java.lang.System.nanoTime();
					totalAux += (endnowAux - startnowAux);

				} catch (CryptoUtilsException e) {
					log.error("[" + primeSize + "]= SIGN/VERIFY-" + digestName
							+ ": " + e.getMessage(), e.getCause());
					log.toFile(
							"[" + primeSize + " - " + inputSize
									+ "]= SIGN/VERIFY -" + digestName + ": "
									+ e.getMessage(), logFileName);
				}
			}
		}

		String totalStr = "[" + primeSize + " - " + inputSize + "] SIGN RSA-"
				+ digestName + "= "
				+ (total / (totalRounds * totalRounds * 1.0));
		String totalAuxStr = "[" + primeSize + " - " + inputSize
				+ "] Verify RSA-" + digestName + "= "
				+ (totalAux / (totalRounds * totalRounds * 1.0));
		log.info(totalStr);
		log.toFile(totalStr, logFileName);
		log.info(totalAuxStr);
		log.toFile(totalAuxStr, logFileName);

	}

}
