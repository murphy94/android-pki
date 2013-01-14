/**
 *  Created on  : 22/05/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Test for every X509 functions in the cryptographic library
 */
package cinvestav.pki.androidpkiutilstest;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x500.X500NameBuilder;
import org.spongycastle.asn1.x500.style.BCStyle;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.X509v3CertificateBuilder;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.spongycastle.crypto.params.RSAKeyParameters;
import org.spongycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.spongycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.bc.BcRSAContentSignerBuilder;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.encoders.Hex;

import android.os.Environment;
import android.util.Log;
import cinvestav.android.pki.cryptography.cert.CertificateInformationKeys;
import cinvestav.android.pki.cryptography.cert.X509CRLRevokedCertificateEntry;
import cinvestav.android.pki.cryptography.cert.X509RevokedCertificateReason;
import cinvestav.android.pki.cryptography.ec.ECDomainParameters;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsX509ExtensionException;
import cinvestav.android.pki.cryptography.key.ECKeyPair;
import cinvestav.android.pki.cryptography.key.RSAKeyPair;
import cinvestav.android.pki.cryptography.utils.AsymmetricCryptoUtils;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;
import cinvestav.android.pki.cryptography.utils.X509Utils;
import cinvestav.android.pki.cryptography.utils.X509UtilsDictionary;
import cinvestav.android.pki.utils.LogUtil;

/**
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 22/05/2012
 * @version 1.0
 */
public class X509TestRunner {
	// public static final String TAG = "SCCIPHERTEST";
	protected static LogUtil log = new LogUtil("ANDROID_PKI_UTILS");
	private X509Utils _X509Utils;
	private AsymmetricCryptoUtils asymmetricCryptoUtils;
	private String defaultEncoder = CryptoUtils.ENCODER_HEX;
	String logFileName = "performance_x509_d1";
	SecureRandom rand;

	public X509TestRunner() throws CryptoUtilsException {
		try {
			_X509Utils = new X509Utils();
		} catch (CryptoUtilsException e) {
			e.printStackTrace();
			log.error("testX509CertificateV3 = " + e.getMessage(), e.getCause());
		}
		asymmetricCryptoUtils = new AsymmetricCryptoUtils();
		rand = new SecureRandom();
	}

	public void runTest(Boolean detailResult) {
		// log.info(" ********* AES NIST Test Begin *********");
		// testEncryptDecryptStatic();
		Integer certificateSerial = 1;
		Integer primeSize = 1024;
		String nistCurveName;
		// testCertificateParametersInformation();
		log.info(" ********* RSA " + primeSize + " Test Begin *********");
		runTest(primeSize, detailResult, certificateSerial);

		nistCurveName = ECDomainParameters.NIST_CURVE_P_192;
		log.info(" ********* EC Test Begin *********");
		runTest(nistCurveName, detailResult, certificateSerial);

		log.info(" ********* MIX Test Begin *********");
		runTest(primeSize, nistCurveName, detailResult, certificateSerial);
	}

	/**
	 * Timing X509 Certificate Test
	 */
	public void runTestTiming() {
		testX509CertificateV3Timing(1024);
		testX509CertificateV3Timing(ECDomainParameters.NIST_CURVE_P_192);
		testX509CertificateV3Timing(1024, ECDomainParameters.NIST_CURVE_P_192);
		
		testPKCS12Timing(1024);
		testPKCS12Timing(2048);
		testPKCS12Timing(4096);
		testPKCS12Timing(ECDomainParameters.NIST_CURVE_P_192);
		testPKCS12Timing(ECDomainParameters.NIST_CURVE_P_256);
		testPKCS12Timing(ECDomainParameters.NIST_CURVE_P_384);
	}

	private void runTest(Integer primeSize, Boolean detailResult,
			Integer certificateSerial) {

		log.info("[" + primeSize + "] ---- X509 V3 ---- ");

		testX509CertificateV3(primeSize, detailResult, certificateSerial);
	}

	private void testCertificateParametersInformation() {
		SecureRandom secureRandom = new SecureRandom();
		byte[] auxBytes = new byte[128];
		secureRandom.nextBytes(auxBytes);

		auxBytes = "dc01a288859f329b".getBytes();
		testCertificateParametersInformation(auxBytes);

		auxBytes = "19.545616, -99.165988".getBytes();
		testCertificateParametersInformation(auxBytes);

		auxBytes = "IFE".getBytes();
		testCertificateParametersInformation(auxBytes);

		auxBytes = "5".getBytes();
		testCertificateParametersInformation(auxBytes);
	}

	private void testCertificateParametersInformation(byte[] testBytes) {

		DEROctetString certOctet;
		RSAKeyParameters lwPubKey = new RSAKeyParameters(
				false,
				new BigInteger(
						"b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7",
						16), new BigInteger("11", 16));

		RSAPrivateCrtKeyParameters lwPrivKey = new RSAPrivateCrtKeyParameters(
				new BigInteger(
						"b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7",
						16),
				new BigInteger("11", 16),
				new BigInteger(
						"9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89",
						16),
				new BigInteger(
						"c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb",
						16),
				new BigInteger(
						"f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5",
						16),
				new BigInteger(
						"b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391",
						16),
				new BigInteger(
						"d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd",
						16),
				new BigInteger(
						"b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19",
						16));

		//
		// distinguished name table.
		//
		X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

		builder.addRDN(BCStyle.C, "AU");
		builder.addRDN(BCStyle.O, "The Legion of the Bouncy Castle");
		builder.addRDN(BCStyle.L, "Melbourne");
		builder.addRDN(BCStyle.ST, "Victoria");
		builder.addRDN(BCStyle.E, "feedback-crypto@spongycastle.org");

		// byte[] aux = Base64.encode(testBytes);
		byte[] aux = testBytes;
		String original = new String(aux);
		log.info("Certificate Parameters Test : Original= " + original);
		String res = "";

		X509v3CertificateBuilder v3CertGen;
		try {

			X500Name issuer = builder.build();
			X500Name subject = builder.build();
			// Get the Public key contained in the certificate
			SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo(
					new AlgorithmIdentifier(
							PKCSObjectIdentifiers.rsaEncryption,
							DERNull.INSTANCE),
					new org.spongycastle.asn1.pkcs.RSAPublicKey(lwPubKey
							.getModulus(), lwPubKey.getExponent()));

			v3CertGen = new X509v3CertificateBuilder(issuer,
					BigInteger.valueOf(1), new Date(
							System.currentTimeMillis() - 50000), new Date(
							System.currentTimeMillis() + 50000), subject,
					pubInfo);
			v3CertGen.addExtension(CertificateInformationKeys.DEVICE_ID_OID,
					true, new DEROctetString(aux));

			AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
					.find("SHA256WithRSAEncryption");
			AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
					.find(sigAlgId);

			ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId,
					digAlgId).build(lwPrivKey);

			X509CertificateHolder certHolder = v3CertGen.build(sigGen);
			X509Certificate cert = new JcaX509CertificateConverter()
					.setProvider(CryptoUtils.PROVIDER).getCertificate(
							certHolder);

			byte[] resCert = cert
					.getExtensionValue(CertificateInformationKeys.DEVICE_ID_OID
							.getId());

			certOctet = (DEROctetString) (new ASN1InputStream(
					new ByteArrayInputStream(resCert)).readObject());

			byte[] asn1Octet = ASN1OctetString.getInstance(
					ASN1OctetString.getInstance(resCert).getOctets())
					.getOctets();

			ASN1Primitive resASN1 = JcaX509ExtensionUtils
					.parseExtensionValue(resCert);
			certOctet = new DEROctetString(resASN1);

			DEROctetString derOctetString = new DEROctetString(aux);
			DERBitString derBitString = new DERBitString(aux);

			DERBitString a;

			log.info("Certificate Parameters Test : OCTETSTRING= "
					+ derOctetString);
			log.info("Certificate Parameters Test : OCTETSTRING= " + certOctet);
			log.info("Certificate Parameters Test : OCTETSTRING= " + resASN1);
			log.info("Certificate Parameters Test : OCTETSTRING= "
					+ derOctetString.toString());
			log.info("Certificate Parameters Test : OCTETSTRING= "
					+ certOctet.toString());
			log.info("Certificate Parameters Test : OCTETSTRING= "
					+ resASN1.toString());
			log.info("Certificate Parameters Test : OCTETSTRING= "
					+ new String(derOctetString.getEncoded()));
			log.info("Certificate Parameters Test : OCTETSTRING= "
					+ new String(certOctet.getEncoded()));
			log.info("Certificate Parameters Test : OCTETSTRING= "
					+ new String(resASN1.getEncoded()));
			log.info("Certificate Parameters Test : OCTETSTRING= "
					+ new String(derOctetString.getOctets()));
			log.info("Certificate Parameters Test : OCTETSTRING= "
					+ new String(certOctet.getOctets()));
			log.info("Certificate Parameters Test : OCTETSTRING= "
					+ resASN1.toASN1Primitive());
			log.info("Certificate Parameters Test : ASN1= "
					+ new String(asn1Octet));
			String resOctetString = new String(derOctetString.getOctets());
			res = resOctetString.equals(original) ? "OK" : "FAIL";
			log.info("Certificate Parameters Test : OCTETSTRING= " + res);

			String resBitString = new String(derBitString.getBytes());
			log.info("Certificate Parameters Test : BITSTRING= " + derBitString);
			log.info("Certificate Parameters Test : BITSTRING= "
					+ derBitString.toString());
			log.info("Certificate Parameters Test : BITSTRING= "
					+ new String(derBitString.getEncoded()));
			log.info("Certificate Parameters Test : BITSTRING= "
					+ new String(derBitString.getBytes()));
			res = resBitString.equals(original) ? "OK" : "FAIL";
			log.info("Certificate Parameters Test : BITSTRING= " + res);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		}

	}

	private void runTest(String nistCurveName, Boolean detailResult,
			Integer certificateSerial) {
		// testKeyGen(keySizeInBits);

		// testSaveAndLoadKeyFile(keySizeInBits, detailResult);
		log.info("[" + nistCurveName + "] ---- X509 V3 ---- ");
		testX509CertificateV3(nistCurveName, detailResult, certificateSerial);

	}

	private void runTest(Integer primeSize, String nistCurveName,
			Boolean detailResult, Integer certificateSerial) {
		// testKeyGen(keySizeInBits);

		// testSaveAndLoadKeyFile(keySizeInBits, detailResult);
		log.info("[" + nistCurveName + "-" + primeSize + "] ---- X509 V3 ---- ");
		testX509CertificateV3(primeSize, nistCurveName, detailResult,
				certificateSerial);

	}

	private void fillCertificateHashMaps(
			HashMap<String, String> masterRootCertificateInformationMap,
			HashMap<String, String> rootCertificateInformationMap,
			HashMap<String, String> ca1CertificateInformationMap,
			HashMap<String, String> ca2CertificateInformationMap,
			HashMap<String, String> subjCertificateInformationMap) {
		// Generate CAs certificate Information Maps

		rootCertificateInformationMap.put(
				CertificateInformationKeys.FRIENDLY_NAME, "Root CA");
		rootCertificateInformationMap.put(CertificateInformationKeys.COUNTRY,
				"MX");
		rootCertificateInformationMap.put(
				CertificateInformationKeys.EmailAddress, "rootCA@gmail.com");
		rootCertificateInformationMap.put(
				CertificateInformationKeys.FULL_COMMON_NAME, "Root CA Name");
		rootCertificateInformationMap.put(CertificateInformationKeys.LOCALITY,
				"GAM");
		rootCertificateInformationMap.put(CertificateInformationKeys.STATE,
				"DF");
		rootCertificateInformationMap.put(
				CertificateInformationKeys.ORGANIZATION, "Cinvestav");
		rootCertificateInformationMap.put(CertificateInformationKeys.DEVICE_ID,
				SCCipherTestActivity.ANDROID_ID);
		rootCertificateInformationMap.put(
				CertificateInformationKeys.CREATION_POSITION_LATITUDE,
				"19,51091");
		rootCertificateInformationMap.put(
				CertificateInformationKeys.CREATION_POSITION_LONGITUDE,
				"-99,12769");
		rootCertificateInformationMap.put(CertificateInformationKeys.USER_ID,
				"1");
		rootCertificateInformationMap.put(
				CertificateInformationKeys.USER_PERMISSION_ID, "1");
		rootCertificateInformationMap.put(
				CertificateInformationKeys.IDENTIFICATION_DOCUMENT, "IFE");
		rootCertificateInformationMap.put(
				CertificateInformationKeys.SIGN_DEVICE_ID,
				SCCipherTestActivity.ANDROID_ID);

		ca1CertificateInformationMap.put(
				CertificateInformationKeys.FRIENDLY_NAME, "CA Nvl1");
		ca1CertificateInformationMap.put(CertificateInformationKeys.COUNTRY,
				"MX");
		ca1CertificateInformationMap.put(
				CertificateInformationKeys.EmailAddress, "CA1@gmail.com");
		ca1CertificateInformationMap.put(
				CertificateInformationKeys.FULL_COMMON_NAME, "CA Nvl1 Name");
		ca1CertificateInformationMap.put(CertificateInformationKeys.LOCALITY,
				"GAM");
		ca1CertificateInformationMap
				.put(CertificateInformationKeys.STATE, "DF");
		ca1CertificateInformationMap.put(
				CertificateInformationKeys.ORGANIZATION, "Cinvestav");
		ca1CertificateInformationMap.put(CertificateInformationKeys.DEVICE_ID,
				SCCipherTestActivity.ANDROID_ID);
		ca1CertificateInformationMap.put(
				CertificateInformationKeys.CREATION_POSITION_LATITUDE,
				"19,51091");
		ca1CertificateInformationMap.put(
				CertificateInformationKeys.CREATION_POSITION_LONGITUDE,
				"-99,12769");
		ca1CertificateInformationMap.put(CertificateInformationKeys.USER_ID,
				"2");
		ca1CertificateInformationMap.put(
				CertificateInformationKeys.USER_PERMISSION_ID, "2");
		ca1CertificateInformationMap.put(
				CertificateInformationKeys.IDENTIFICATION_DOCUMENT, "IFE");
		ca1CertificateInformationMap.put(
				CertificateInformationKeys.SIGN_DEVICE_ID,
				SCCipherTestActivity.ANDROID_ID);

		ca2CertificateInformationMap.put(
				CertificateInformationKeys.FRIENDLY_NAME, "CA Nvl2");
		ca2CertificateInformationMap.put(CertificateInformationKeys.COUNTRY,
				"MX");
		ca2CertificateInformationMap.put(
				CertificateInformationKeys.EmailAddress, "CA2@gmail.com");
		ca2CertificateInformationMap.put(
				CertificateInformationKeys.FULL_COMMON_NAME, "CA Nvl2 Name");
		ca2CertificateInformationMap.put(CertificateInformationKeys.LOCALITY,
				"GAM");
		ca2CertificateInformationMap
				.put(CertificateInformationKeys.STATE, "DF");
		ca2CertificateInformationMap.put(
				CertificateInformationKeys.ORGANIZATION, "Cinvestav");
		ca2CertificateInformationMap.put(CertificateInformationKeys.DEVICE_ID,
				SCCipherTestActivity.ANDROID_ID);
		ca2CertificateInformationMap.put(
				CertificateInformationKeys.CREATION_POSITION_LATITUDE,
				"19,51091");
		ca2CertificateInformationMap.put(
				CertificateInformationKeys.CREATION_POSITION_LONGITUDE,
				"-99,12769");
		ca2CertificateInformationMap.put(CertificateInformationKeys.USER_ID,
				"3");
		ca2CertificateInformationMap.put(
				CertificateInformationKeys.USER_PERMISSION_ID, "3");
		ca2CertificateInformationMap.put(
				CertificateInformationKeys.IDENTIFICATION_DOCUMENT, "IFE");
		ca2CertificateInformationMap.put(
				CertificateInformationKeys.SIGN_DEVICE_ID,
				SCCipherTestActivity.ANDROID_ID);

		masterRootCertificateInformationMap.put(
				CertificateInformationKeys.FRIENDLY_NAME, "Root CA Master");
		masterRootCertificateInformationMap.put(
				CertificateInformationKeys.COUNTRY, "MX");
		masterRootCertificateInformationMap.put(
				CertificateInformationKeys.EmailAddress, "mrootCA@gmail.com");
		masterRootCertificateInformationMap.put(
				CertificateInformationKeys.FULL_COMMON_NAME,
				"Root CA Name Master");
		masterRootCertificateInformationMap.put(
				CertificateInformationKeys.LOCALITY, "GAM");
		masterRootCertificateInformationMap.put(
				CertificateInformationKeys.STATE, "DF");
		masterRootCertificateInformationMap.put(
				CertificateInformationKeys.ORGANIZATION, "Cinvestav");
		masterRootCertificateInformationMap.put(
				CertificateInformationKeys.DEVICE_ID,
				SCCipherTestActivity.ANDROID_ID);
		masterRootCertificateInformationMap.put(
				CertificateInformationKeys.CREATION_POSITION_LATITUDE,
				"-99,12769");
		masterRootCertificateInformationMap.put(
				CertificateInformationKeys.CREATION_POSITION_LONGITUDE,
				"-99,12769");
		masterRootCertificateInformationMap.put(
				CertificateInformationKeys.USER_ID, "4");
		masterRootCertificateInformationMap.put(
				CertificateInformationKeys.USER_PERMISSION_ID, "4");
		masterRootCertificateInformationMap.put(
				CertificateInformationKeys.IDENTIFICATION_DOCUMENT, "IFE");
		masterRootCertificateInformationMap.put(
				CertificateInformationKeys.SIGN_DEVICE_ID,
				SCCipherTestActivity.ANDROID_ID);

		// Create Subject Information Map

		subjCertificateInformationMap.put(
				CertificateInformationKeys.FRIENDLY_NAME, "Javier Key Test");
		subjCertificateInformationMap.put(CertificateInformationKeys.COUNTRY,
				"MX");
		subjCertificateInformationMap.put(
				CertificateInformationKeys.EmailAddress, "javier.sp@gmail.com");
		subjCertificateInformationMap.put(
				CertificateInformationKeys.FULL_COMMON_NAME,
				"Javier Silva Perez");
		subjCertificateInformationMap.put(CertificateInformationKeys.LOCALITY,
				"Tlalnepantla");
		subjCertificateInformationMap.put(CertificateInformationKeys.STATE,
				"Mexico");
		subjCertificateInformationMap.put(
				CertificateInformationKeys.ORGANIZATION, "Cinvestav");
		subjCertificateInformationMap.put(CertificateInformationKeys.DEVICE_ID,
				SCCipherTestActivity.ANDROID_ID);
		subjCertificateInformationMap.put(
				CertificateInformationKeys.CREATION_POSITION_LATITUDE,
				"19.545616");
		subjCertificateInformationMap.put(
				CertificateInformationKeys.CREATION_POSITION_LONGITUDE,
				"-99.165988");
		subjCertificateInformationMap.put(CertificateInformationKeys.USER_ID,
				"5");
		subjCertificateInformationMap.put(
				CertificateInformationKeys.USER_PERMISSION_ID, "5");
		subjCertificateInformationMap.put(
				CertificateInformationKeys.IDENTIFICATION_DOCUMENT, "IFE");
		subjCertificateInformationMap.put(
				CertificateInformationKeys.SIGN_DEVICE_ID,
				SCCipherTestActivity.ANDROID_ID);

	}

	private void testX509CertificateV3(Integer primeSize, Boolean detailResult,
			Integer certificateSerial) {
		try {
			// Certificate Parameters
			Date notBefore = new Date();
			// - 1000L * 60 * 60 * 24 * 30);
			Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60
					* 60 * 24 * 30);
			HashMap<String, String> rootCertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> masterRootCertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> subjCertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> ca2CertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> ca1CertificateInformationMap = new HashMap<String, String>();

			fillCertificateHashMaps(masterRootCertificateInformationMap,
					rootCertificateInformationMap,
					ca1CertificateInformationMap, ca2CertificateInformationMap,
					subjCertificateInformationMap);

			RSAKeyPair key;
			// Generate Key and random input data
			key = asymmetricCryptoUtils.generateKeys(primeSize);
			if (detailResult)
				log.info("[" + primeSize + "] Original KEY= "
						+ key.toString(defaultEncoder));

			// Generates CAs keys
			RSAKeyPair rootCAKeyPair = asymmetricCryptoUtils
					.generateKeys(primeSize);
			RSAKeyPair ca1KeyPair = asymmetricCryptoUtils
					.generateKeys(primeSize);
			RSAKeyPair ca2KeyPair = asymmetricCryptoUtils
					.generateKeys(primeSize);
			RSAKeyPair masterRootKeyPair = asymmetricCryptoUtils
					.generateKeys(primeSize);

			// for (String algorithm : X509Utils.supportedRSASignAlgorithm) {
			String algorithm = X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_SHA1withRSA;
			testRSACertificate(masterRootKeyPair, rootCAKeyPair, ca1KeyPair,
					ca2KeyPair, key, masterRootCertificateInformationMap,
					rootCertificateInformationMap,
					ca1CertificateInformationMap, ca2CertificateInformationMap,
					subjCertificateInformationMap, notBefore, notAfter,
					certificateSerial, primeSize, detailResult, algorithm);

			testRSACertificateExtensionConstrain(masterRootKeyPair,
					rootCAKeyPair, ca1KeyPair, ca2KeyPair, key,
					masterRootCertificateInformationMap,
					rootCertificateInformationMap,
					ca1CertificateInformationMap, ca2CertificateInformationMap,
					subjCertificateInformationMap, notBefore, notAfter,
					certificateSerial, primeSize, detailResult, algorithm);
			// }

		} catch (CryptoUtilsException e) {
			e.printStackTrace();
			log.error(
					"testX509CertificateV3 [" + primeSize + "]= "
							+ e.getMessage(), e.getCause());
		} catch (CryptoUtilsX509ExtensionException e) {
			log.error(
					"testX509CertificateV3 [" + primeSize + "]= "
							+ e.getMessage(), e.getCause());
		}
	}

	private void testX509CertificateV3(String curveName, Boolean detailResult,
			Integer certificateSerial) {
		try {
			// Certificate Parameters
			Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60
					* 60 * 24 * 30);
			Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60
					* 60 * 24 * 30);
			HashMap<String, String> rootCertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> masterRootCertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> subjCertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> ca2CertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> ca1CertificateInformationMap = new HashMap<String, String>();

			fillCertificateHashMaps(masterRootCertificateInformationMap,
					rootCertificateInformationMap,
					ca1CertificateInformationMap, ca2CertificateInformationMap,
					subjCertificateInformationMap);

			ECKeyPair key;

			// Generate Key and random input data
			key = asymmetricCryptoUtils.generateKeys(curveName);

			// Generates CAs keys
			ECKeyPair rootCAKeyPair = asymmetricCryptoUtils
					.generateKeys(curveName);
			ECKeyPair ca1KeyPair = asymmetricCryptoUtils
					.generateKeys(curveName);
			ECKeyPair ca2KeyPair = asymmetricCryptoUtils
					.generateKeys(curveName);
			ECKeyPair masterRootKeyPair = asymmetricCryptoUtils
					.generateKeys(curveName);

			// for (String algorithm : X509Utils.supportedECSignAlgorithm) {
			String algorithm = X509UtilsDictionary.EC_X509_SIGN_ALGORITHM_SHA1withECDSA;
			testECCertificate(masterRootKeyPair, rootCAKeyPair, ca1KeyPair,
					ca2KeyPair, key, masterRootCertificateInformationMap,
					rootCertificateInformationMap,
					ca1CertificateInformationMap, ca2CertificateInformationMap,
					subjCertificateInformationMap, notBefore, notAfter,
					algorithm, certificateSerial, curveName, detailResult);

			testECCertificateExtensionConstrain(masterRootKeyPair,
					rootCAKeyPair, ca1KeyPair, ca2KeyPair, key,
					masterRootCertificateInformationMap,
					rootCertificateInformationMap,
					ca1CertificateInformationMap, ca2CertificateInformationMap,
					subjCertificateInformationMap, notBefore, notAfter,
					certificateSerial, curveName, detailResult, algorithm);
			// }

		} catch (CryptoUtilsException e) {
			e.printStackTrace();
			log.error(
					"testX509CertificateV3 [" + curveName + "]= "
							+ e.getMessage(), e.getCause());
		} catch (CryptoUtilsX509ExtensionException e) {
			e.printStackTrace();
			log.error(
					"testX509CertificateV3 [" + curveName + "]= "
							+ e.getMessage(), e.getCause());
		}
	}

	/**
	 * Mix Key Types certificate Test, CA and owner has different key types
	 * 
	 * @param primeSize
	 * @param curveName
	 * @param detailResult
	 * @param certificateSerial
	 */
	private void testX509CertificateV3(Integer primeSize, String curveName,
			Boolean detailResult, Integer certificateSerial) {
		try {
			// Certificate Parameters
			Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60
					* 60 * 24 * 30);
			Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60
					* 60 * 24 * 30);
			HashMap<String, String> rootCertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> masterRootCertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> subjCertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> ca2CertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> ca1CertificateInformationMap = new HashMap<String, String>();

			fillCertificateHashMaps(masterRootCertificateInformationMap,
					rootCertificateInformationMap,
					ca1CertificateInformationMap, ca2CertificateInformationMap,
					subjCertificateInformationMap);

			ECKeyPair key;

			// Generate Key and random input data
			key = asymmetricCryptoUtils.generateKeys(curveName);

			// Generates CAs keys
			ECKeyPair ca1ECKeyPair = asymmetricCryptoUtils
					.generateKeys(curveName);
			ECKeyPair masterECRootKeyPair = asymmetricCryptoUtils
					.generateKeys(curveName);

			// Generates CAs keys
			RSAKeyPair rootRSACAKeyPair = asymmetricCryptoUtils
					.generateKeys(primeSize);
			RSAKeyPair ca2RSAKeyPair = asymmetricCryptoUtils
					.generateKeys(primeSize);

			for (String algorithmEC : X509Utils.supportedECSignAlgorithm) {
				for (String algorithmRSA : X509Utils.supportedRSASignAlgorithm) {
					// String algorithmEC =
					// X509UtilsDictionary.EC_X509_SIGN_ALGORITHM_SHA1withECDSA;
					// String algorithmRSA =
					// X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_SHA1withRSA;
					testCertificate(masterECRootKeyPair, rootRSACAKeyPair,
							ca1ECKeyPair, ca2RSAKeyPair, key,
							masterRootCertificateInformationMap,
							rootCertificateInformationMap,
							ca1CertificateInformationMap,
							ca2CertificateInformationMap,
							subjCertificateInformationMap, notBefore, notAfter,
							algorithmEC, algorithmRSA, certificateSerial,
							curveName, primeSize, detailResult);
				}
			}

		} catch (CryptoUtilsException e) {
			e.printStackTrace();
			log.error(
					"testX509CertificateV3 [" + curveName + "]= "
							+ e.getMessage(), e.getCause());
		} catch (CryptoUtilsX509ExtensionException e) {
			e.printStackTrace();
			log.error(
					"testX509CertificateV3 [" + curveName + "]= "
							+ e.getMessage(), e.getCause());
		}
	}

	private void testX509Certificate(String fileName, X509Certificate cert,
			String encoding, Integer primeSize, Boolean detailResult,
			String algorithm) throws CryptoUtilsException {
		String fileSufix = "";
		String res = "";
		fileSufix = "cert_" + encoding + "." + encoding.toLowerCase();

		_X509Utils.saveCertificate(fileName + fileSufix, cert, encoding);

		X509Certificate certRes = _X509Utils.loadCertificate(fileName
				+ fileSufix);

		res = certRes.equals(cert) ? "OK" : "FAIL";
		log.info("[" + primeSize + "] Save " + algorithm + " " + encoding
				+ " = " + res);
	}

	private void testX509Certificate(String fileName, X509Certificate cert,
			String encoding, String curveName, Boolean detailResult,
			String algorithm) throws CryptoUtilsException {
		String fileSufix = "";
		String res = "";
		fileSufix = "cert_" + encoding + "." + encoding.toLowerCase();

		_X509Utils.saveCertificate(fileName + fileSufix, cert, encoding);

		X509Certificate certRes = _X509Utils.loadCertificate(fileName
				+ fileSufix);

		res = certRes.equals(cert) ? "OK" : "FAIL";
		log.info("[" + curveName + "] Save " + encoding + " " + algorithm
				+ "= " + res);
	}

	/**
	 * Save MIX-Keys certificate
	 * 
	 * @param fileName
	 * @param cert
	 * @param encoding
	 * @param curveName
	 * @param detailResult
	 * @param algorithm
	 * @throws CryptoUtilsException
	 */
	private void testX509Certificate(String fileName, X509Certificate cert,
			String encoding, String curveName, Integer primeSize,
			Boolean detailResult, String algorithmEC, String algorithmRSA)
			throws CryptoUtilsException {
		String fileSufix = "";
		String res = "";
		fileSufix = "cert_" + encoding + "." + encoding.toLowerCase();

		_X509Utils.saveCertificate(fileName + fileSufix, cert, encoding);

		X509Certificate certRes = _X509Utils.loadCertificate(fileName
				+ fileSufix);

		res = certRes.equals(cert) ? "OK" : "FAIL";
		log.info("[" + curveName + "-" + primeSize + "] Save " + encoding + " "
				+ algorithmEC + "-" + algorithmRSA + "= " + res);
	}

	private void testSeeCertificateDetails(X509Certificate cert, Integer i) {
		log.info("[CERTIFICATE DETAILS] [" + i + "] SEE CERTIFICATE DETAILS");
		log.info("[CERTIFICATE DETAILS] [" + i + "] CERT: " + cert);
		log.info("[CERTIFICATE DETAILS] [" + i + "] VERSION: "
				+ cert.getVersion());
		log.info("[CERTIFICATE DETAILS] [" + i + "] SERIAL NUMBER: "
				+ cert.getSerialNumber());
		log.info("[CERTIFICATE DETAILS] [" + i + "] SIGNATURE ALGORITHM: "
				+ cert.getSigAlgName());
		log.info("[CERTIFICATE DETAILS] [" + i + "] SIGNATURE BASE64: "
				+ new String(Base64.encode(cert.getSignature())));
		log.info("[CERTIFICATE DETAILS] [" + i + "] SIGNATURE HEX: "
				+ new String(Hex.encode(cert.getSignature())));
		log.info("[CERTIFICATE DETAILS] [" + i + "] ISSUER DN: "
				+ cert.getIssuerDN());
		log.info("[CERTIFICATE DETAILS] ["
				+ i
				+ "] ISSUER ID BASE64: "
				+ new String(Base64.encode(_X509Utils
						.getAuthorityKeyIdentifier(cert))));
		log.info("[CERTIFICATE DETAILS] ["
				+ i
				+ "] ISSUER ID HEX: "
				+ new String(Hex.encode(_X509Utils
						.getAuthorityKeyIdentifier(cert))));
		log.info("[CERTIFICATE DETAILS] [" + i + "] SUBJECT DN: "
				+ cert.getSubjectDN());
		log.info("[CERTIFICATE DETAILS] ["
				+ i
				+ "] SUBJECT ID BASE64: "
				+ new String(Base64.encode(_X509Utils
						.getSubjectKeyIdentifier(cert))));
		log.info("[CERTIFICATE DETAILS] ["
				+ i
				+ "] SUBJECT ID HEX: "
				+ new String(Hex.encode(_X509Utils
						.getSubjectKeyIdentifier(cert))));
		log.info("[CERTIFICATE DETAILS] [" + i + "] VALIDITY NOT BEFORE: "
				+ cert.getNotBefore());
		log.info("[CERTIFICATE DETAILS] [" + i + "] VALIDITY NOT AFTER: "
				+ cert.getNotAfter());
		log.info("[CERTIFICATE DETAILS] [" + i + "] PUBLIC KEY: "
				+ cert.getPublicKey());
		log.info("[CERTIFICATE DETAILS] [" + i + "] PUBLIC KEY CLASS: "
				+ cert.getPublicKey().getClass().getName());

		log.info("[CERTIFICATE DETAILS] : EXTENSION - BASIC CONSTRAIN"
				+ cert.getBasicConstraints());
		log.info("[CERTIFICATE DETAILS] : EXTENSION - CERTIFICATE TYPE"
				+ _X509Utils.getExtensionCertificateType(cert, ""));
		log.info("[CERTIFICATE DETAILS] : EXTENSION - KEY USAGE"
				+ _X509Utils.getKeyUsageList(cert));

		log.info("[CERTIFICATE DETAILS] : CERTIFICATE MAP: "
				+ _X509Utils.getCertificateInformationMap(cert));

		// log.info("[CERTIFICATE DETAILS] : " + cert);

	}

	private void testPKCS12(String fileName, RSAKeyPair subjectKeyPair,
			X509Certificate[] chain, Integer primeSize, Boolean detailResult)
			throws CryptoUtilsException {

		String fileSufix = "";
		String password = "PASSWORD";
		String passwordKEY = "PASSWORDXX";
		String res = "";
		RSAKeyPair resKeyPair;
		Certificate[] resChain;

		// Start Plain PEM Private Key test
		fileSufix = "pkcs12.p12";

		subjectKeyPair.savePKCS12(fileName + fileSufix, password, passwordKEY,
				chain);
		Object[] resObj = RSAKeyPair.loadPKCS12(fileName + fileSufix, password,
				password);
		resKeyPair = (RSAKeyPair) resObj[0];
		resChain = _X509Utils.loadCertificateChainPKCS12(fileName + fileSufix,
				password);

		Boolean keyEquals = resKeyPair.equals(subjectKeyPair);
		for (int i = 0; i < chain.length; i++) {
			// Certificate c1 = chain[i];
			// Certificate c2 = resChain[i];
			keyEquals &= chain[i].equals(resChain[i]);
		}

		res = keyEquals ? "OK" : "FAIL";
		log.info("[" + primeSize + "] PKCS12 = " + res);
	}

	private void testPKCS12(String fileName, ECKeyPair subjectKeyPair,
			X509Certificate[] chain, String curveName, Boolean detailResult)
			throws CryptoUtilsException {

		String fileSufix = "";
		String password = "PASSWORD";
		String res = "";
		ECKeyPair resKeyPair;
		Certificate[] resChain;

		// Start Plain PEM Private Key test
		fileSufix = "pkcs12.p12";

		subjectKeyPair.savePKCS12(fileName + fileSufix, password, password,
				chain);

		Object resEncoded[] = ECKeyPair.loadPKCS12(fileName + fileSufix,
				password, password);
		resKeyPair = (ECKeyPair) resEncoded[0];

		resChain = _X509Utils.loadCertificateChainPKCS12(fileName + fileSufix,
				password);

		Boolean keyEquals = resKeyPair.equals(subjectKeyPair);
		for (int i = 0; i < chain.length; i++) {
			keyEquals &= chain[i].equals(resChain[i]);
		}

		res = keyEquals ? "OK" : "FAIL";
		log.info("[" + curveName + "] PKCS12 = " + res);
	}

	/**
	 * Test creation and saving for RSA certificate, the test includes public
	 * certificates and PKCS12 files
	 * 
	 * @param masterRootCertificateInformationMap
	 * @param rootCertificateInformationMap
	 * @param ca1CertificateInformationMap
	 * @param ca2CertificateInformationMap
	 * @param subjCertificateInformationMap
	 * @param notBefore
	 * @param notAfter
	 * @param certificateSerial
	 * @param primeSize
	 * @param detailResult
	 * @param rootCAKeyPair
	 * @throws CryptoUtilsException
	 * @throws CryptoUtilsX509ExtensionException
	 */
	private void testRSACertificate(RSAKeyPair masterRootKeyPair,
			RSAKeyPair rootCAKeyPair, RSAKeyPair ca1KeyPair,
			RSAKeyPair ca2KeyPair, RSAKeyPair key,
			HashMap<String, String> masterRootCertificateInformationMap,
			HashMap<String, String> rootCertificateInformationMap,
			HashMap<String, String> ca1CertificateInformationMap,
			HashMap<String, String> ca2CertificateInformationMap,
			HashMap<String, String> subjCertificateInformationMap,
			Date notBefore, Date notAfter, Integer certificateSerial,
			Integer primeSize, Boolean detailResult, String algorithm)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException {

		String certFileName = Environment.getExternalStorageDirectory()
				+ "/cryptoTest/RSA_X509_" + primeSize + "_" + algorithm + "_";
		File f = new File(certFileName);
		if (!f.getParentFile().exists()) {
			f.getParentFile().mkdir();
		}

		List<Integer> keyUsageList;
		String certType;
		X509Certificate[] chain = new X509Certificate[5];

		// Creates Root CA self signed certificate
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		X509Certificate masterCert = _X509Utils.createV3Cert(
				masterRootKeyPair.getPublicKey(),
				masterRootKeyPair.getPrivateKey(),
				BigInteger.valueOf(certificateSerial), notBefore, notAfter,
				masterRootCertificateInformationMap, keyUsageList, certType,
				algorithm);

		chain[4] = masterCert;

		certType = X509UtilsDictionary.CERTIFICATE_TYPE_INTERMEDIATE_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		chain[3] = _X509Utils.createV3Cert(rootCAKeyPair.getPublicKey(),
				masterRootKeyPair.getPrivateKey(),
				BigInteger.valueOf(certificateSerial), notBefore, notAfter,
				(X509Certificate) chain[4], rootCertificateInformationMap,
				keyUsageList, certType, algorithm);
		certificateSerial++;

		// Create CA1 certificate signed by Root CA
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_FINAL_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		chain[2] = _X509Utils.createV3Cert(ca1KeyPair.getPublicKey(),
				rootCAKeyPair.getPrivateKey(),
				BigInteger.valueOf(certificateSerial), notBefore, notAfter,
				(X509Certificate) chain[3], ca1CertificateInformationMap,
				keyUsageList, certType, algorithm);
		certificateSerial++;

		// Create CA2 certificate signed by CA1
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_FINAL_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		chain[1] = _X509Utils.createV3Cert(ca2KeyPair.getPublicKey(),
				ca1KeyPair.getPrivateKey(),
				BigInteger.valueOf(certificateSerial), notBefore, notAfter,
				(X509Certificate) chain[2], ca2CertificateInformationMap,
				keyUsageList, certType, algorithm);
		certificateSerial++;

		// Create subject certificate signed by CA2
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_END_OWNER;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		chain[0] = _X509Utils.createV3Cert(key.getPublicKey(),
				ca2KeyPair.getPrivateKey(),
				BigInteger.valueOf(certificateSerial), notBefore, notAfter,
				(X509Certificate) chain[1], subjCertificateInformationMap,
				keyUsageList, certType, algorithm);

		// Saves each certificate of the chain in PEM and DER format
		for (int i = 0; i < chain.length; i++) {
			testX509Certificate(certFileName + "C" + i + "_", chain[i], "DER",
					primeSize, detailResult, algorithm);
			testX509Certificate(certFileName + "C" + i + "_", chain[i], "PEM",
					primeSize, detailResult, algorithm);
			testSeeCertificateDetails(chain[i], i);
		}

		testPKCS12(certFileName, key, chain, primeSize, detailResult);
		testX509CRL(masterRootKeyPair, masterCert, chain, algorithm, primeSize,
				detailResult);
	}

	/**
	 * Test RSA X509 certificate extensions constrains, checks key Usage and
	 * basicConstrain extensions, and that the CA certificate date. In order to
	 * do this, different kind of CA certificates are created and tries to
	 * create end user certificate with those certificates
	 * 
	 * @param masterRootCertificateInformationMap
	 * @param rootCertificateInformationMap
	 * @param ca1CertificateInformationMap
	 * @param ca2CertificateInformationMap
	 * @param subjCertificateInformationMap
	 * @param notBefore
	 * @param notAfter
	 * @param certificateSerial
	 * @param primeSize
	 * @param detailResult
	 * @param intermediateCAKeyPair
	 * @throws CryptoUtilsException
	 * @throws CryptoUtilsX509ExtensionException
	 */
	private void testRSACertificateExtensionConstrain(
			RSAKeyPair masterRootKeyPair, RSAKeyPair intermediateCAKeyPair,
			RSAKeyPair ca1KeyPair, RSAKeyPair ca2KeyPair, RSAKeyPair key,
			HashMap<String, String> masterRootCertificateInformationMap,
			HashMap<String, String> rootCertificateInformationMap,
			HashMap<String, String> ca1CertificateInformationMap,
			HashMap<String, String> ca2CertificateInformationMap,
			HashMap<String, String> subjCertificateInformationMap,
			Date notBefore, Date notAfter, Integer certificateSerial,
			Integer primeSize, Boolean detailResult, String algorithm)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException {

		List<Integer> keyUsageList;
		String certType;

		// Creates Root CA self signed certificate
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		X509Certificate rootCert = _X509Utils.createV3Cert(
				masterRootKeyPair.getPublicKey(),
				masterRootKeyPair.getPrivateKey(),
				BigInteger.valueOf(certificateSerial), notBefore, notAfter,
				masterRootCertificateInformationMap, keyUsageList, certType,
				algorithm);
		log.info("[" + primeSize + "] TEST CREATE CERTIFICATE " + algorithm
				+ ": " + certType + " SELF-SIGN = OK");

		// Intermediate CA certificate with an OK Master certificate
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_INTERMEDIATE_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		X509Certificate intermediateCert = null;
		try {
			intermediateCert = _X509Utils.createV3Cert(
					intermediateCAKeyPair.getPublicKey(),
					masterRootKeyPair.getPrivateKey(),
					BigInteger.valueOf(certificateSerial), notBefore, notAfter,
					(X509Certificate) rootCert, rootCertificateInformationMap,
					keyUsageList, certType, algorithm);
			log.info("[" + primeSize + "] TEST CREATE CERTIFICATE " + algorithm
					+ ": " + certType + " = OK");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + primeSize + "] TEST CREATE CERTIFICATE " + algorithm
					+ ": " + certType + " = FAIL");
		}
		certificateSerial++;

		// Create FULL FINAL_CA certificate signed by an OK INTERMEDIATE_CA
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_FINAL_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		X509Certificate finalCert_FULL = null;
		try {
			finalCert_FULL = _X509Utils.createV3Cert(ca1KeyPair.getPublicKey(),
					intermediateCAKeyPair.getPrivateKey(),
					BigInteger.valueOf(certificateSerial), notBefore, notAfter,
					(X509Certificate) intermediateCert,
					ca1CertificateInformationMap, keyUsageList, certType,
					algorithm);
			log.info("[" + primeSize + "] TEST CREATE CERTIFICATE " + algorithm
					+ ": " + certType + " = OK");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + primeSize + "] TEST CREATE CERTIFICATE " + algorithm
					+ ": " + certType + " = FAIL");
		}
		certificateSerial++;

		// Create FINAL_CA without CRL_SIGN and KEY_CERT_SIGN keyusage flags
		// certificate signed by an OK INTERMEDIATE_CA
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_FINAL_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		X509Certificate finalCert_NOSIGNCERT = null;
		try {
			finalCert_NOSIGNCERT = _X509Utils.createV3Cert(
					ca2KeyPair.getPublicKey(),
					intermediateCAKeyPair.getPrivateKey(),
					BigInteger.valueOf(certificateSerial), notBefore, notAfter,
					(X509Certificate) intermediateCert,
					ca2CertificateInformationMap, keyUsageList, certType,
					algorithm);
			log.info("[" + primeSize + "] TEST CREATE CERTIFICATE " + algorithm
					+ ": " + certType + " = OK");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + primeSize + "] TEST CREATE CERTIFICATE " + algorithm
					+ ": " + certType + " = FAIL");
		}
		certificateSerial++;

		// Create FINAL_CA expired certificate signed by an OK INTERMEDIATE_CA
		Date notBefore_Aux = new Date(System.currentTimeMillis() - 1000L * 60
				* 60 * 24 * 30);
		Date notAfter_Aux = new Date(System.currentTimeMillis() - 1L * 60 * 60
				* 24 * 30);
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_FINAL_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		X509Certificate finalCert_EXPIRED = null;
		try {
			finalCert_EXPIRED = _X509Utils.createV3Cert(
					ca2KeyPair.getPublicKey(),
					intermediateCAKeyPair.getPrivateKey(),
					BigInteger.valueOf(certificateSerial), notBefore_Aux,
					notAfter_Aux, (X509Certificate) intermediateCert,
					ca2CertificateInformationMap, keyUsageList, certType,
					algorithm);
			log.info("[" + primeSize + "] TEST CREATE CERTIFICATE " + algorithm
					+ ": " + certType + " = OK");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + primeSize + "] TEST CREATE CERTIFICATE " + algorithm
					+ ": " + certType + " = FAIL");
		}
		certificateSerial++;

		// Create FINAL_CA notvalidyet certificate signed by an OK
		// INTERMEDIATE_CA
		notBefore_Aux = new Date(System.currentTimeMillis() + 1L * 60 * 60 * 24
				* 30);
		notAfter_Aux = new Date(System.currentTimeMillis() + 1000L * 60 * 60
				* 24 * 30);
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_FINAL_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		X509Certificate finalCert_NOTVALIDYET = null;
		try {
			finalCert_NOTVALIDYET = _X509Utils.createV3Cert(
					ca2KeyPair.getPublicKey(),
					intermediateCAKeyPair.getPrivateKey(),
					BigInteger.valueOf(certificateSerial), notBefore_Aux,
					notAfter_Aux, (X509Certificate) intermediateCert,
					ca2CertificateInformationMap, keyUsageList, certType,
					algorithm);
			log.info("[" + primeSize + "] TEST CREATE CERTIFICATE " + algorithm
					+ ": " + certType + " = OK");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + primeSize + "] TEST CREATE CERTIFICATE " + algorithm
					+ ": " + certType + " = FAIL");
		}
		certificateSerial++;

		// Create an OK END_USER CERTIFICATE signed by CA1 Key using FINAL_CA
		// FULL Certificate
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_END_OWNER;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		X509Certificate endOwnerCert = null;
		try {
			endOwnerCert = _X509Utils.createV3Cert(key.getPublicKey(),
					ca1KeyPair.getPrivateKey(),
					BigInteger.valueOf(certificateSerial), notBefore, notAfter,
					(X509Certificate) finalCert_FULL,
					subjCertificateInformationMap, keyUsageList, certType,
					algorithm);
			log.info("[" + primeSize + "] TEST CREATE CERTIFICATE " + algorithm
					+ ": " + certType + " = OK");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + primeSize + "] TEST CREATE CERTIFICATE " + algorithm
					+ ": " + certType + " = FAIL");
		}
		certificateSerial++;

		// BEGIN ERROR TESTS

		// Intermediate CA certificate with an OK FINAL_CA, its expected and
		// exception
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_INTERMEDIATE_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		try {
			_X509Utils.createV3Cert(intermediateCAKeyPair.getPublicKey(),
					ca1KeyPair.getPrivateKey(),
					BigInteger.valueOf(certificateSerial), notBefore, notAfter,
					(X509Certificate) finalCert_FULL,
					rootCertificateInformationMap, keyUsageList, certType,
					algorithm);
			log.info("[" + primeSize + "] TEST CREATE CERTIFICATE ERROR "
					+ algorithm + ": " + certType
					+ " signed by FINAL_CA = FAIL");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + primeSize + "] TEST CREATE CERTIFICATE ERROR "
					+ algorithm + ": " + certType + " signed by FINAL_CA = OK");
			if (detailResult)
				log.info(e.getMessage());
		}
		certificateSerial++;

		// Intermediate CA certificate issue by an OK END_OWNER_CA, its expected
		// and exception
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_INTERMEDIATE_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		try {
			_X509Utils.createV3Cert(intermediateCAKeyPair.getPublicKey(),
					key.getPrivateKey(), BigInteger.valueOf(certificateSerial),
					notBefore, notAfter, (X509Certificate) endOwnerCert,
					rootCertificateInformationMap, keyUsageList, certType,
					algorithm);
			log.info("[" + primeSize + "] TEST CREATE CERTIFICATE ERROR "
					+ algorithm + ": " + certType
					+ " signed by FINAL_CA = FAIL");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + primeSize + "] TEST CREATE CERTIFICATE ERROR "
					+ algorithm + ": " + certType + " signed by END_OWNER = OK");
			if (detailResult)
				log.info(e.getMessage());
		}
		certificateSerial++;

		// FINAL_CA certificate issue by an OK END_OWNER_CA, its expected
		// and exception
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_FINAL_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		try {
			_X509Utils.createV3Cert(intermediateCAKeyPair.getPublicKey(),
					key.getPrivateKey(), BigInteger.valueOf(certificateSerial),
					notBefore, notAfter, (X509Certificate) endOwnerCert,
					rootCertificateInformationMap, keyUsageList, certType,
					algorithm);
			log.info("[" + primeSize + "] TEST CREATE CERTIFICATE ERROR "
					+ algorithm + ": " + certType
					+ " signed by FINAL_CA = FAIL");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + primeSize + "] TEST CREATE CERTIFICATE ERROR "
					+ algorithm + ": " + certType + " signed by END_OWNER = OK");
			if (detailResult)
				log.info(e.getMessage());
		}
		certificateSerial++;

		// Create an END_USER CERTIFICATE issue by expired FINAL_CA
		// certificate
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_END_OWNER;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		try {
			_X509Utils.createV3Cert(key.getPublicKey(),
					ca2KeyPair.getPrivateKey(),
					BigInteger.valueOf(certificateSerial), notBefore, notAfter,
					(X509Certificate) finalCert_EXPIRED,
					subjCertificateInformationMap, keyUsageList, certType,
					algorithm);
			log.info("[" + primeSize + "] TEST CREATE CERTIFICATE ERROR "
					+ algorithm + ": " + certType + " EXPIRED CA CERT= FAIL");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + primeSize + "] TEST CREATE CERTIFICATE ERROR "
					+ algorithm + ": " + certType + " EXPIRED CA CERT= OK");
			if (detailResult)
				log.info(e.getMessage());
		}
		certificateSerial++;

		// Create an END_USER CERTIFICATE issue by NOT VALID YET FINAL_CA
		// certificate
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_END_OWNER;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		try {
			_X509Utils.createV3Cert(key.getPublicKey(),
					ca2KeyPair.getPrivateKey(),
					BigInteger.valueOf(certificateSerial), notBefore, notAfter,
					(X509Certificate) finalCert_NOTVALIDYET,
					subjCertificateInformationMap, keyUsageList, certType,
					algorithm);
			log.info("[" + primeSize + "] TEST CREATE CERTIFICATE ERROR "
					+ algorithm + ": " + certType
					+ " NOT VALID YET CA CERT= FAIL");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + primeSize + "] TEST CREATE CERTIFICATE ERROR "
					+ algorithm + ": " + certType
					+ " NOT VALID YET CA CERT= OK");
			if (detailResult)
				log.info(e.getMessage());
		}
		certificateSerial++;

		// Create an END_USER CERTIFICATE issue by FINAL_CA
		// certificate with out KEY_CERT_SIGN key usage flag
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_END_OWNER;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		try {
			_X509Utils.createV3Cert(key.getPublicKey(),
					ca2KeyPair.getPrivateKey(),
					BigInteger.valueOf(certificateSerial), notBefore, notAfter,
					(X509Certificate) finalCert_NOSIGNCERT,
					subjCertificateInformationMap, keyUsageList, certType,
					algorithm);
			log.info("[" + primeSize + "] TEST CREATE CERTIFICATE ERROR "
					+ algorithm + ": " + certType
					+ " NO_SIGN_CERT CA CERT= FAIL");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + primeSize + "] TEST CREATE CERTIFICATE ERROR "
					+ algorithm + ": " + certType + " NO_SIGN_CERT CA CERT= OK");
			if (detailResult)
				log.info(e.getMessage());
		}
		certificateSerial++;

		X509Certificate[] chain = new X509Certificate[5];
		chain[0] = endOwnerCert;
		chain[1] = finalCert_FULL;
		chain[2] = intermediateCert;

		try {
			testX509CRL(ca2KeyPair, finalCert_NOSIGNCERT, chain, algorithm,
					primeSize, detailResult);
			log.info("[" + primeSize + "] TEST CREATE CRL ERROR " + algorithm
					+ ": " + certType + " NO_CRL_SIGN CA CERT= FAIL");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + primeSize + "] TEST CREATE CRL ERROR " + algorithm
					+ ": " + certType + " NO_CRL_SIGN CA CERT= OK");
			if (detailResult)
				log.info(e.getMessage());
		}
	}

	/**
	 * Test creation and saving for EC certificate, the test includes public
	 * certificates and PKCS12 files
	 * 
	 * @param masterRootCertificateInformationMap
	 * @param rootCertificateInformationMap
	 * @param ca1CertificateInformationMap
	 * @param ca2CertificateInformationMap
	 * @param subjCertificateInformationMap
	 * @param notBefore
	 * @param notAfter
	 * @param certificateSerial
	 * @param primeSize
	 * @param detailResult
	 * @throws CryptoUtilsException
	 * @throws CryptoUtilsX509ExtensionException
	 */
	private void testECCertificate(ECKeyPair masterRootKeyPair,
			ECKeyPair rootCAKeyPair, ECKeyPair ca1KeyPair,
			ECKeyPair ca2KeyPair, ECKeyPair key,
			HashMap<String, String> masterRootCertificateInformationMap,
			HashMap<String, String> rootCertificateInformationMap,
			HashMap<String, String> ca1CertificateInformationMap,
			HashMap<String, String> ca2CertificateInformationMap,
			HashMap<String, String> subjCertificateInformationMap,
			Date notBefore, Date notAfter, String algorithm,
			Integer certificateSerial, String curveName, Boolean detailResult)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException {

		String certFileName = Environment.getExternalStorageDirectory()
				+ "/cryptoTest/EC_X509_" + curveName + "_" + algorithm + "_";
		File f = new File(certFileName);
		if (!f.getParentFile().exists()) {
			f.getParentFile().mkdir();
		}
		if (detailResult)
			log.info("[" + curveName + "] Original KEY= "
					+ key.toString(defaultEncoder));

		List<Integer> keyUsageList;
		String certType;
		X509Certificate[] chain = new X509Certificate[5];

		// Creates Root CA self signed certificate
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		X509Certificate masterCert = _X509Utils.createV3Cert(
				masterRootKeyPair.getPublicKey(),
				masterRootKeyPair.getPrivateKey(),
				BigInteger.valueOf(certificateSerial), notBefore, notAfter,
				masterRootCertificateInformationMap, keyUsageList, certType,
				algorithm);
		certificateSerial++;
		chain[4] = masterCert;

		certType = X509UtilsDictionary.CERTIFICATE_TYPE_INTERMEDIATE_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		chain[3] = _X509Utils.createV3Cert(rootCAKeyPair.getPublicKey(),
				masterRootKeyPair.getPrivateKey(),
				BigInteger.valueOf(certificateSerial), notBefore, notAfter,
				(X509Certificate) chain[4], rootCertificateInformationMap,
				keyUsageList, certType, algorithm);

		// Create CA1 certificate signed by Root CA
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_FINAL_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		chain[2] = _X509Utils.createV3Cert(ca1KeyPair.getPublicKey(),
				rootCAKeyPair.getPrivateKey(),
				BigInteger.valueOf(certificateSerial), notBefore, notAfter,
				(X509Certificate) chain[3], ca1CertificateInformationMap,
				keyUsageList, certType, algorithm);

		certificateSerial++;
		// Create CA2 certificate signed by CA1
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_FINAL_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		chain[1] = _X509Utils.createV3Cert(ca2KeyPair.getPublicKey(),
				ca1KeyPair.getPrivateKey(),
				BigInteger.valueOf(certificateSerial), notBefore, notAfter,
				(X509Certificate) chain[2], ca2CertificateInformationMap,
				keyUsageList, certType, algorithm);

		certificateSerial++;

		// Create subject certificate signed by CA2
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_END_OWNER;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		chain[0] = _X509Utils.createV3Cert(key.getPublicKey(),
				ca2KeyPair.getPrivateKey(),
				BigInteger.valueOf(certificateSerial), notBefore, notAfter,
				(X509Certificate) chain[1], subjCertificateInformationMap,
				keyUsageList, certType, algorithm);

		// Saves each certificate of the chain in PEM and DER format
		for (int i = 0; i < chain.length; i++) {
			testX509Certificate(certFileName + "C" + i + "_", chain[i], "DER",
					curveName, detailResult, algorithm);
			testX509Certificate(certFileName + "C" + i + "_", chain[i], "PEM",
					curveName, detailResult, algorithm);
			testSeeCertificateDetails(chain[i], i);
		}
		testPKCS12(certFileName, key, chain, curveName, detailResult);

		testX509CRL(masterRootKeyPair, masterCert, chain, algorithm, curveName,
				detailResult);
	}

	/**
	 * Test RSA X509 certificate extensions constrains, checks key Usage and
	 * basicConstrain extensions, and that the CA certificate date. In order to
	 * do this, different kind of CA certificates are created and tries to
	 * create end user certificate with those certificates
	 * 
	 * @param masterRootCertificateInformationMap
	 * @param rootCertificateInformationMap
	 * @param ca1CertificateInformationMap
	 * @param ca2CertificateInformationMap
	 * @param subjCertificateInformationMap
	 * @param notBefore
	 * @param notAfter
	 * @param certificateSerial
	 * @param curveName
	 * @param detailResult
	 * @param intermediateCAKeyPair
	 * @throws CryptoUtilsException
	 * @throws CryptoUtilsX509ExtensionException
	 */
	private void testECCertificateExtensionConstrain(
			ECKeyPair masterRootKeyPair, ECKeyPair intermediateCAKeyPair,
			ECKeyPair ca1KeyPair, ECKeyPair ca2KeyPair, ECKeyPair key,
			HashMap<String, String> masterRootCertificateInformationMap,
			HashMap<String, String> rootCertificateInformationMap,
			HashMap<String, String> ca1CertificateInformationMap,
			HashMap<String, String> ca2CertificateInformationMap,
			HashMap<String, String> subjCertificateInformationMap,
			Date notBefore, Date notAfter, Integer certificateSerial,
			String curveName, Boolean detailResult, String algorithm)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException {

		List<Integer> keyUsageList;
		String certType;

		// Creates Root CA self signed certificate
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		X509Certificate rootCert = _X509Utils.createV3Cert(
				masterRootKeyPair.getPublicKey(),
				masterRootKeyPair.getPrivateKey(),
				BigInteger.valueOf(certificateSerial), notBefore, notAfter,
				masterRootCertificateInformationMap, keyUsageList, certType,
				algorithm);
		log.info("[" + curveName + "] TEST CREATE CERTIFICATE " + algorithm
				+ ": " + certType + " SELF-SIGN = OK");

		// Intermediate CA certificate with an OK Master certificate
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_INTERMEDIATE_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		X509Certificate intermediateCert = null;
		try {
			intermediateCert = _X509Utils.createV3Cert(
					intermediateCAKeyPair.getPublicKey(),
					masterRootKeyPair.getPrivateKey(),
					BigInteger.valueOf(certificateSerial), notBefore, notAfter,
					(X509Certificate) rootCert, rootCertificateInformationMap,
					keyUsageList, certType, algorithm);
			log.info("[" + curveName + "] TEST CREATE CERTIFICATE " + algorithm
					+ ": " + certType + " = OK");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + curveName + "] TEST CREATE CERTIFICATE " + algorithm
					+ ": " + certType + " = FAIL");
		}
		certificateSerial++;

		// Create FULL FINAL_CA certificate signed by an OK INTERMEDIATE_CA
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_FINAL_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		X509Certificate finalCert_FULL = null;
		try {
			finalCert_FULL = _X509Utils.createV3Cert(ca1KeyPair.getPublicKey(),
					intermediateCAKeyPair.getPrivateKey(),
					BigInteger.valueOf(certificateSerial), notBefore, notAfter,
					(X509Certificate) intermediateCert,
					ca1CertificateInformationMap, keyUsageList, certType,
					algorithm);
			log.info("[" + curveName + "] TEST CREATE CERTIFICATE " + algorithm
					+ ": " + certType + " = OK");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + curveName + "] TEST CREATE CERTIFICATE " + algorithm
					+ ": " + certType + " = FAIL");
		}
		certificateSerial++;

		// Create FINAL_CA without CRL_SIGN and KEY_CERT_SIGN keyusage flags
		// certificate signed by an OK INTERMEDIATE_CA
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_FINAL_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		X509Certificate finalCert_NOSIGNCERT = null;
		try {
			finalCert_NOSIGNCERT = _X509Utils.createV3Cert(
					ca2KeyPair.getPublicKey(),
					intermediateCAKeyPair.getPrivateKey(),
					BigInteger.valueOf(certificateSerial), notBefore, notAfter,
					(X509Certificate) intermediateCert,
					ca2CertificateInformationMap, keyUsageList, certType,
					algorithm);
			log.info("[" + curveName + "] TEST CREATE CERTIFICATE " + algorithm
					+ ": " + certType + " = OK");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + curveName + "] TEST CREATE CERTIFICATE " + algorithm
					+ ": " + certType + " = FAIL");
		}
		certificateSerial++;

		// Create FINAL_CA expired certificate signed by an OK INTERMEDIATE_CA
		Date notBefore_Aux = new Date(System.currentTimeMillis() - 1000L * 60
				* 60 * 24 * 30);
		Date notAfter_Aux = new Date(System.currentTimeMillis() - 1L * 60 * 60
				* 24 * 30);
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_FINAL_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		X509Certificate finalCert_EXPIRED = null;
		try {
			finalCert_EXPIRED = _X509Utils.createV3Cert(
					ca2KeyPair.getPublicKey(),
					intermediateCAKeyPair.getPrivateKey(),
					BigInteger.valueOf(certificateSerial), notBefore_Aux,
					notAfter_Aux, (X509Certificate) intermediateCert,
					ca2CertificateInformationMap, keyUsageList, certType,
					algorithm);
			log.info("[" + curveName + "] TEST CREATE CERTIFICATE " + algorithm
					+ ": " + certType + " = OK");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + curveName + "] TEST CREATE CERTIFICATE " + algorithm
					+ ": " + certType + " = FAIL");
		}
		certificateSerial++;

		// Create FINAL_CA notvalidyet certificate signed by an OK
		// INTERMEDIATE_CA
		notBefore_Aux = new Date(System.currentTimeMillis() + 1L * 60 * 60 * 24
				* 30);
		notAfter_Aux = new Date(System.currentTimeMillis() + 1000L * 60 * 60
				* 24 * 30);
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_FINAL_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		X509Certificate finalCert_NOTVALIDYET = null;
		try {
			finalCert_NOTVALIDYET = _X509Utils.createV3Cert(
					ca2KeyPair.getPublicKey(),
					intermediateCAKeyPair.getPrivateKey(),
					BigInteger.valueOf(certificateSerial), notBefore_Aux,
					notAfter_Aux, (X509Certificate) intermediateCert,
					ca2CertificateInformationMap, keyUsageList, certType,
					algorithm);
			log.info("[" + curveName + "] TEST CREATE CERTIFICATE " + algorithm
					+ ": " + certType + " = OK");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + curveName + "] TEST CREATE CERTIFICATE " + algorithm
					+ ": " + certType + " = FAIL");
		}
		certificateSerial++;

		// Create an OK END_USER CERTIFICATE signed by CA1 Key using FINAL_CA
		// FULL Certificate
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_END_OWNER;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		X509Certificate endOwnerCert = null;
		try {
			endOwnerCert = _X509Utils.createV3Cert(key.getPublicKey(),
					ca1KeyPair.getPrivateKey(),
					BigInteger.valueOf(certificateSerial), notBefore, notAfter,
					(X509Certificate) finalCert_FULL,
					subjCertificateInformationMap, keyUsageList, certType,
					algorithm);
			log.info("[" + curveName + "] TEST CREATE CERTIFICATE " + algorithm
					+ ": " + certType + " = OK");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + curveName + "] TEST CREATE CERTIFICATE " + algorithm
					+ ": " + certType + " = FAIL");
		}
		certificateSerial++;

		// BEGIN ERROR TESTS

		// Intermediate CA certificate with an OK FINAL_CA, its expected and
		// exception
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_INTERMEDIATE_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		try {
			_X509Utils.createV3Cert(intermediateCAKeyPair.getPublicKey(),
					ca1KeyPair.getPrivateKey(),
					BigInteger.valueOf(certificateSerial), notBefore, notAfter,
					(X509Certificate) finalCert_FULL,
					rootCertificateInformationMap, keyUsageList, certType,
					algorithm);
			log.info("[" + curveName + "] TEST CREATE CERTIFICATE ERROR "
					+ algorithm + ": " + certType
					+ " signed by FINAL_CA = FAIL");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + curveName + "] TEST CREATE CERTIFICATE ERROR "
					+ algorithm + ": " + certType + " signed by FINAL_CA = OK");
			if (detailResult)
				log.info(e.getMessage());
		}
		certificateSerial++;

		// Intermediate CA certificate issue by an OK END_OWNER_CA, its expected
		// and exception
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_INTERMEDIATE_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		try {
			_X509Utils.createV3Cert(intermediateCAKeyPair.getPublicKey(),
					key.getPrivateKey(), BigInteger.valueOf(certificateSerial),
					notBefore, notAfter, (X509Certificate) endOwnerCert,
					rootCertificateInformationMap, keyUsageList, certType,
					algorithm);
			log.info("[" + curveName + "] TEST CREATE CERTIFICATE ERROR "
					+ algorithm + ": " + certType
					+ " signed by FINAL_CA = FAIL");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + curveName + "] TEST CREATE CERTIFICATE ERROR "
					+ algorithm + ": " + certType + " signed by END_OWNER = OK");
			if (detailResult)
				log.info(e.getMessage());
		}
		certificateSerial++;

		// FINAL_CA certificate issue by an OK END_OWNER_CA, its expected
		// and exception
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_FINAL_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		try {
			_X509Utils.createV3Cert(intermediateCAKeyPair.getPublicKey(),
					key.getPrivateKey(), BigInteger.valueOf(certificateSerial),
					notBefore, notAfter, (X509Certificate) endOwnerCert,
					rootCertificateInformationMap, keyUsageList, certType,
					algorithm);
			log.info("[" + curveName + "] TEST CREATE CERTIFICATE ERROR "
					+ algorithm + ": " + certType
					+ " signed by FINAL_CA = FAIL");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + curveName + "] TEST CREATE CERTIFICATE ERROR "
					+ algorithm + ": " + certType + " signed by END_OWNER = OK");
			if (detailResult)
				log.info(e.getMessage());
		}
		certificateSerial++;

		// Create an END_USER CERTIFICATE issue by expired FINAL_CA
		// certificate
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_END_OWNER;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		try {
			_X509Utils.createV3Cert(key.getPublicKey(),
					ca2KeyPair.getPrivateKey(),
					BigInteger.valueOf(certificateSerial), notBefore, notAfter,
					(X509Certificate) finalCert_EXPIRED,
					subjCertificateInformationMap, keyUsageList, certType,
					algorithm);
			log.info("[" + curveName + "] TEST CREATE CERTIFICATE ERROR "
					+ algorithm + ": " + certType + " EXPIRED CA CERT= FAIL");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + curveName + "] TEST CREATE CERTIFICATE ERROR "
					+ algorithm + ": " + certType + " EXPIRED CA CERT= OK");
			if (detailResult)
				log.info(e.getMessage());
		}
		certificateSerial++;

		// Create an END_USER CERTIFICATE issue by NOT VALID YET FINAL_CA
		// certificate
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_END_OWNER;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		try {
			_X509Utils.createV3Cert(key.getPublicKey(),
					ca2KeyPair.getPrivateKey(),
					BigInteger.valueOf(certificateSerial), notBefore, notAfter,
					(X509Certificate) finalCert_NOTVALIDYET,
					subjCertificateInformationMap, keyUsageList, certType,
					algorithm);
			log.info("[" + curveName + "] TEST CREATE CERTIFICATE ERROR "
					+ algorithm + ": " + certType
					+ " NOT VALID YET CA CERT= FAIL");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + curveName + "] TEST CREATE CERTIFICATE ERROR "
					+ algorithm + ": " + certType
					+ " NOT VALID YET CA CERT= OK");
			if (detailResult)
				log.info(e.getMessage());
		}
		certificateSerial++;

		// Create an END_USER CERTIFICATE issue by FINAL_CA
		// certificate with out KEY_CERT_SIGN key usage flag
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_END_OWNER;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		try {
			_X509Utils.createV3Cert(key.getPublicKey(),
					ca2KeyPair.getPrivateKey(),
					BigInteger.valueOf(certificateSerial), notBefore, notAfter,
					(X509Certificate) finalCert_NOSIGNCERT,
					subjCertificateInformationMap, keyUsageList, certType,
					algorithm);
			log.info("[" + curveName + "] TEST CREATE CERTIFICATE ERROR "
					+ algorithm + ": " + certType
					+ " NO_SIGN_CERT CA CERT= FAIL");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + curveName + "] TEST CREATE CERTIFICATE ERROR "
					+ algorithm + ": " + certType + " NO_SIGN_CERT CA CERT= OK");
			if (detailResult)
				log.info(e.getMessage());
		}
		certificateSerial++;

		X509Certificate[] chain = new X509Certificate[5];
		chain[0] = endOwnerCert;
		chain[1] = finalCert_FULL;
		chain[2] = intermediateCert;

		try {
			testX509CRL(ca2KeyPair, finalCert_NOSIGNCERT, chain, algorithm,
					curveName, detailResult);
			log.info("[" + curveName + "] TEST CREATE CRL ERROR " + algorithm
					+ ": " + certType + " NO_CRL_SIGN CA CERT= FAIL");
		} catch (CryptoUtilsX509ExtensionException e) {
			log.info("[" + curveName + "] TEST CREATE CRL ERROR " + algorithm
					+ ": " + certType + " NO_CRL_SIGN CA CERT= OK");
			if (detailResult)
				log.info(e.getMessage());
		}
	}

	/**
	 * Test creation and saving for Mix EC-RSA certificate, the test includes
	 * public certificates and PKCS12 files
	 * 
	 * @param masterRootCertificateInformationMap
	 * @param rootCertificateInformationMap
	 * @param ca1CertificateInformationMap
	 * @param ca2CertificateInformationMap
	 * @param subjCertificateInformationMap
	 * @param notBefore
	 * @param notAfter
	 * @param certificateSerial
	 * @param primeSize
	 * @param detailResult
	 * @throws CryptoUtilsException
	 * @throws CryptoUtilsX509ExtensionException
	 */
	private void testCertificate(ECKeyPair masterRootKeyPair,
			RSAKeyPair rootCAKeyPair, ECKeyPair ca1KeyPair,
			RSAKeyPair ca2KeyPair, ECKeyPair key,
			HashMap<String, String> masterRootCertificateInformationMap,
			HashMap<String, String> rootCertificateInformationMap,
			HashMap<String, String> ca1CertificateInformationMap,
			HashMap<String, String> ca2CertificateInformationMap,
			HashMap<String, String> subjCertificateInformationMap,
			Date notBefore, Date notAfter, String algorithmEC,
			String algorithmRSA, Integer certificateSerial, String curveName,
			Integer primeSize, Boolean detailResult)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException {

		String certFileName = Environment.getExternalStorageDirectory()
				+ "/cryptoTest/MIX_X509_" + curveName + "_" + algorithmEC + "_"
				+ primeSize + "_" + algorithmRSA + "_";
		File f = new File(certFileName);
		if (!f.getParentFile().exists()) {
			f.getParentFile().mkdir();
		}
		if (detailResult)
			log.info("[" + curveName + "] Original KEY= "
					+ key.toString(defaultEncoder));

		List<Integer> keyUsageList;
		String certType;
		X509Certificate[] chain = new X509Certificate[5];

		// Creates Root CA self signed certificate
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		X509Certificate masterCert = _X509Utils.createV3Cert(
				masterRootKeyPair.getPublicKey(),
				masterRootKeyPair.getPrivateKey(),
				BigInteger.valueOf(certificateSerial), notBefore, notAfter,
				masterRootCertificateInformationMap, keyUsageList, certType,
				algorithmEC);
		certificateSerial++;
		chain[4] = masterCert;

		// Create Intermediate CA certificate, using CA-EC Keys and Owner RSA
		// keys
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_INTERMEDIATE_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		chain[3] = _X509Utils.createV3Cert(rootCAKeyPair.getPublicKey(),
				masterRootKeyPair.getPrivateKey(),
				BigInteger.valueOf(certificateSerial), notBefore, notAfter,
				(X509Certificate) chain[4], rootCertificateInformationMap,
				keyUsageList, certType, algorithmEC);

		// Create Final CA with EC Keys, issue by an intermediate CA using RSA
		// keys
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_FINAL_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		chain[2] = _X509Utils.createV3Cert(ca1KeyPair.getPublicKey(),
				rootCAKeyPair.getPrivateKey(),
				BigInteger.valueOf(certificateSerial), notBefore, notAfter,
				(X509Certificate) chain[3], ca1CertificateInformationMap,
				keyUsageList, certType, algorithmRSA);

		certificateSerial++;
		// Create FINAL_CA certificate (with RSA Keys), issue by CA (FINAL_CA
		// with EC Keys)
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_FINAL_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		chain[1] = _X509Utils.createV3Cert(ca2KeyPair.getPublicKey(),
				ca1KeyPair.getPrivateKey(),
				BigInteger.valueOf(certificateSerial), notBefore, notAfter,
				(X509Certificate) chain[2], ca2CertificateInformationMap,
				keyUsageList, certType, algorithmEC);

		certificateSerial++;

		// Create FINAL_OWNER certificate (with EC Keys) signed by final ca
		// using RSA keys
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_END_OWNER;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		chain[0] = _X509Utils.createV3Cert(key.getPublicKey(),
				ca2KeyPair.getPrivateKey(),
				BigInteger.valueOf(certificateSerial), notBefore, notAfter,
				(X509Certificate) chain[1], subjCertificateInformationMap,
				keyUsageList, certType, algorithmRSA);

		// Saves each certificate of the chain in PEM and DER format
		for (int i = 0; i < chain.length; i++) {
			testX509Certificate(certFileName + "C" + i + "_", chain[i], "DER",
					curveName, primeSize, detailResult, algorithmEC,
					algorithmRSA);
			testX509Certificate(certFileName + "C" + i + "_", chain[i], "PEM",
					curveName, primeSize, detailResult, algorithmEC,
					algorithmRSA);
			testSeeCertificateDetails(chain[i], i);
		}
		testPKCS12(certFileName, key, chain, curveName, detailResult);

		/*
		 * testX509CRL(masterRootKeyPair, masterCert, chain, algorithmEC,
		 * curveName, detailResult);
		 */
	}

	private void testX509SaveCRL(String fileName, X509CRL crl, String encoding,
			Integer primeSize, Boolean detailResult, String algorithm)
			throws CryptoUtilsException {
		String fileSufix = "";
		String res = "";
		fileSufix = "CRL_" + encoding + "." + encoding.toLowerCase();

		_X509Utils.saveCRL(fileName + fileSufix, crl, encoding);

		X509CRL crlRes = _X509Utils.loadCRL(fileName + fileSufix);

		res = crlRes.equals(crl) ? "OK" : "FAIL";
		log.info("[" + primeSize + "] Save CRL " + algorithm + " " + encoding
				+ " = " + res);
	}

	private void testX509SaveCRL(String fileName, X509CRL crl, String encoding,
			String curveName, Boolean detailResult, String algorithm)
			throws CryptoUtilsException {
		String fileSufix = "";
		String res = "";
		fileSufix = "CRL_" + encoding + "." + encoding.toLowerCase();

		_X509Utils.saveCRL(fileName + fileSufix, crl, encoding);

		X509CRL crlRes = _X509Utils.loadCRL(fileName + fileSufix);

		res = crlRes.equals(crl) ? "OK" : "FAIL";
		log.info("[" + curveName + "] Save CRL " + algorithm + " " + encoding
				+ " = " + res);
	}

	/**
	 * Test the creation, saving and loading of a X509 CRL using an specific RSA
	 * signing algorithm
	 * 
	 * @param issuerKeyPair
	 * @param issuerCertificate
	 * @param revokedTestCerts
	 * @param algorithm
	 * @param primeSize
	 * @param detailResult
	 * @throws CryptoUtilsException
	 * @throws CryptoUtilsX509ExtensionException
	 */
	private void testX509CRL(RSAKeyPair issuerKeyPair,
			X509Certificate issuerCertificate,
			X509Certificate[] revokedTestCerts, String algorithm,
			Integer primeSize, Boolean detailResult)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException {

		Date now = new Date();
		List<X509CRLRevokedCertificateEntry> revokedCertificates = new LinkedList<X509CRLRevokedCertificateEntry>();

		Date tomorrow = new Date(now.getTime() + 1000);
		Date yesterday = new Date(now.getTime() + 100);
		Date nextUpdate = new Date(now.getTime() + 10000);
		BigInteger crlNumber = new BigInteger("1");
		// Subject Revoked certificate entry
		X509CRLRevokedCertificateEntry entry = new X509CRLRevokedCertificateEntry(
				revokedTestCerts[0], tomorrow, yesterday,
				X509RevokedCertificateReason.CA_COMPROMISE);
		revokedCertificates.add(entry);

		// CA2 certificate entry
		entry = new X509CRLRevokedCertificateEntry(revokedTestCerts[1],
				tomorrow, yesterday,
				X509RevokedCertificateReason.KEY_COMPROMISE);
		revokedCertificates.add(entry);

		// CA1 certificate entry
		entry = new X509CRLRevokedCertificateEntry(revokedTestCerts[2],
				tomorrow, yesterday,
				X509RevokedCertificateReason.PRIVILEGE_WITHDRAWN);
		revokedCertificates.add(entry);

		X509CRL crl = _X509Utils.createCRL(issuerKeyPair, issuerCertificate,
				revokedCertificates, nextUpdate, crlNumber, algorithm);

		String crlFileName = Environment.getExternalStorageDirectory()
				+ "/cryptoTest/RSA_X509_" + primeSize + "_" + algorithm + "_";
		File f = new File(crlFileName);
		if (!f.getParentFile().exists()) {
			f.getParentFile().mkdir();
		}

		// Save the CRL using DER and PEM encodings
		testX509SaveCRL(crlFileName, crl, "DER", primeSize, detailResult,
				algorithm);
		testX509SaveCRL(crlFileName, crl, "PEM", primeSize, detailResult,
				algorithm);
	}

	/**
	 * Test the creation, saving and loading of a X509 CRL using an specific EC
	 * signing algorithm
	 * 
	 * @param issuerKeyPair
	 * @param issuerCertificate
	 * @param revokedTestCerts
	 * @param algorithm
	 * @param curveName
	 * @param detailResult
	 * @throws CryptoUtilsException
	 * @throws CryptoUtilsX509ExtensionException
	 */
	private void testX509CRL(ECKeyPair issuerKeyPair,
			X509Certificate issuerCertificate,
			X509Certificate[] revokedTestCerts, String algorithm,
			String curveName, Boolean detailResult)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException {

		Date now = new Date();
		List<X509CRLRevokedCertificateEntry> revokedCertificates = new LinkedList<X509CRLRevokedCertificateEntry>();

		Date tomorrow = new Date(now.getTime() + 1000);
		Date yesterday = new Date(now.getTime() + 100);
		Date nextUpdate = new Date(now.getTime() + 10000);
		BigInteger crlNumber = new BigInteger("1");
		// Subject Revoked certificate entry
		X509CRLRevokedCertificateEntry entry = new X509CRLRevokedCertificateEntry(
				revokedTestCerts[0], tomorrow, yesterday,
				X509RevokedCertificateReason.CA_COMPROMISE);
		revokedCertificates.add(entry);

		// CA2 certificate entry
		entry = new X509CRLRevokedCertificateEntry(revokedTestCerts[1],
				tomorrow, yesterday,
				X509RevokedCertificateReason.KEY_COMPROMISE);
		revokedCertificates.add(entry);

		// CA1 certificate entry
		entry = new X509CRLRevokedCertificateEntry(revokedTestCerts[2],
				tomorrow, yesterday,
				X509RevokedCertificateReason.PRIVILEGE_WITHDRAWN);
		revokedCertificates.add(entry);

		X509CRL crl = _X509Utils.createCRL(issuerKeyPair, issuerCertificate,
				revokedCertificates, nextUpdate, crlNumber, algorithm);

		String crlFileName = Environment.getExternalStorageDirectory()
				+ "/cryptoTest/RSA_X509_" + curveName + "_" + algorithm + "_";
		File f = new File(crlFileName);
		if (!f.getParentFile().exists()) {
			f.getParentFile().mkdir();
		}

		// Save the CRL using DER and PEM encodings
		testX509SaveCRL(crlFileName, crl, "DER", curveName, detailResult,
				algorithm);
		testX509SaveCRL(crlFileName, crl, "PEM", curveName, detailResult,
				algorithm);
	}

	/**
	 * Timing the X509 certificate and CRL test for RSA
	 * 
	 * @param primeSize
	 */
	private void testX509CertificateV3Timing(Integer primeSize) {

		try {
			// Certificate Parameters
			Date notBefore = new Date();
			// - 1000L * 60 * 60 * 24 * 30);
			Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60
					* 60 * 24 * 30);
			HashMap<String, String> rootCertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> masterRootCertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> subjCertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> ca2CertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> ca1CertificateInformationMap = new HashMap<String, String>();

			log.info("Fill certificate");
			fillCertificateHashMaps(masterRootCertificateInformationMap,
					rootCertificateInformationMap,
					ca1CertificateInformationMap, ca2CertificateInformationMap,
					subjCertificateInformationMap);

			log.info("Generating keys");
			RSAKeyPair key;
			// Generate Key and random input data
			key = asymmetricCryptoUtils.generateKeys(primeSize);

			// Generates CAs keys
			RSAKeyPair rootCAKeyPair = asymmetricCryptoUtils
					.generateKeys(primeSize);
			RSAKeyPair ca1KeyPair = asymmetricCryptoUtils
					.generateKeys(primeSize);
			RSAKeyPair ca2KeyPair = asymmetricCryptoUtils
					.generateKeys(primeSize);
			RSAKeyPair masterRootKeyPair = asymmetricCryptoUtils
					.generateKeys(primeSize);

			RSAKeyPair[] availableKeys = { key, rootCAKeyPair, ca1KeyPair,
					ca2KeyPair, masterRootKeyPair };
			List<HashMap<String, String>> availableCertsMaps = new LinkedList<HashMap<String, String>>();
			availableCertsMaps.add(masterRootCertificateInformationMap);
			availableCertsMaps.add(rootCertificateInformationMap);
			availableCertsMaps.add(ca1CertificateInformationMap);
			availableCertsMaps.add(ca2CertificateInformationMap);
			availableCertsMaps.add(subjCertificateInformationMap);

			Integer certificateSerial = 1;
			String[] availableSignAlgorithm = {
					X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_SHA256withRSA,
					X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_MD5withRSA,
					X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_RIPEMD160withRSA };

			log.info("Running test...");
			for (int selectedDigest = 0; selectedDigest < availableSignAlgorithm.length; selectedDigest++) {
				// Timing the RSA certificate Timing using different signing
				// algorithms
				testRSACertificateTiming(availableKeys, availableCertsMaps,
						notBefore, notAfter, certificateSerial,
						availableSignAlgorithm[selectedDigest]);
			}

		} catch (CryptoUtilsException e) {
			e.printStackTrace();
			log.error("CREATE CERTIFICATE TIMING= " + e.getMessage(),
					e.getCause());
			log.toFile("CREATE CERTIFICATE TIMING= " + e.getMessage(),
					logFileName);
		}
	}

	/**
	 * Timing the X509 certificate and CRL test for EC
	 * 
	 * @param curveName
	 */
	private void testX509CertificateV3Timing(String curveName) {

		try {
			// Certificate Parameters
			Date notBefore = new Date();
			// - 1000L * 60 * 60 * 24 * 30);
			Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60
					* 60 * 24 * 30);
			HashMap<String, String> rootCertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> masterRootCertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> subjCertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> ca2CertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> ca1CertificateInformationMap = new HashMap<String, String>();

			log.info("Fill certificate");
			fillCertificateHashMaps(masterRootCertificateInformationMap,
					rootCertificateInformationMap,
					ca1CertificateInformationMap, ca2CertificateInformationMap,
					subjCertificateInformationMap);

			log.info("Generating keys");
			ECKeyPair key;
			// Generate Key and random input data
			key = asymmetricCryptoUtils.generateKeys(curveName);

			// Generates CAs keys
			ECKeyPair rootCAKeyPair = asymmetricCryptoUtils
					.generateKeys(curveName);
			ECKeyPair ca1KeyPair = asymmetricCryptoUtils
					.generateKeys(curveName);
			ECKeyPair ca2KeyPair = asymmetricCryptoUtils
					.generateKeys(curveName);
			ECKeyPair masterRootKeyPair = asymmetricCryptoUtils
					.generateKeys(curveName);

			ECKeyPair[] availableKeys = { key, rootCAKeyPair, ca1KeyPair,
					ca2KeyPair, masterRootKeyPair };
			List<HashMap<String, String>> availableCertsMaps = new LinkedList<HashMap<String, String>>();
			availableCertsMaps.add(masterRootCertificateInformationMap);
			availableCertsMaps.add(rootCertificateInformationMap);
			availableCertsMaps.add(ca1CertificateInformationMap);
			availableCertsMaps.add(ca2CertificateInformationMap);
			availableCertsMaps.add(subjCertificateInformationMap);

			Integer certificateSerial = 1;
			String[] availableSignAlgorithm = {
					X509UtilsDictionary.EC_X509_SIGN_ALGORITHM_SHA1withECDSA,
					X509UtilsDictionary.EC_X509_SIGN_ALGORITHM_SHA256withECDSA,
					X509UtilsDictionary.EC_X509_SIGN_ALGORITHM_SHA512withECDSA };

			log.info("Running test...");
			for (int selectedDigest = 0; selectedDigest < availableSignAlgorithm.length; selectedDigest++) {
				// Timing the RSA certificate Timing using different signing
				// algorithms
				testECCertificateTiming(availableKeys, availableCertsMaps,
						notBefore, notAfter, certificateSerial,
						availableSignAlgorithm[selectedDigest]);
			}

		} catch (CryptoUtilsException e) {
			e.printStackTrace();
			log.error("CREATE CERTIFICATE TIMING= " + e.getMessage(),
					e.getCause());
			log.toFile("CREATE CERTIFICATE TIMING= " + e.getMessage(),
					logFileName);
		}
	}

	/**
	 * Timing the X509 certificate and CRL test for MIX certificates
	 * 
	 * @param primeSize
	 */
	private void testX509CertificateV3Timing(Integer primeSize, String curveName) {

		try {
			// Certificate Parameters
			Date notBefore = new Date();
			// - 1000L * 60 * 60 * 24 * 30);
			Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60
					* 60 * 24 * 30);
			HashMap<String, String> rootCertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> masterRootCertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> subjCertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> ca2CertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> ca1CertificateInformationMap = new HashMap<String, String>();

			log.info("Fill certificate");
			fillCertificateHashMaps(masterRootCertificateInformationMap,
					rootCertificateInformationMap,
					ca1CertificateInformationMap, ca2CertificateInformationMap,
					subjCertificateInformationMap);

			log.info("Generating keys RSA");
			RSAKeyPair key;
			// Generate Key and random input data
			key = asymmetricCryptoUtils.generateKeys(primeSize);

			// Generates CAs keys
			RSAKeyPair rootCAKeyPair = asymmetricCryptoUtils
					.generateKeys(primeSize);
			RSAKeyPair ca1KeyPair = asymmetricCryptoUtils
					.generateKeys(primeSize);
			RSAKeyPair ca2KeyPair = asymmetricCryptoUtils
					.generateKeys(primeSize);
			RSAKeyPair masterRootKeyPair = asymmetricCryptoUtils
					.generateKeys(primeSize);

			log.info("Generating keys EC");
			ECKeyPair keyEC;
			// Generate Key and random input data
			keyEC = asymmetricCryptoUtils.generateKeys(curveName);

			// Generates CAs keys
			ECKeyPair rootCAKeyPairEC = asymmetricCryptoUtils
					.generateKeys(curveName);
			ECKeyPair ca1KeyPairEC = asymmetricCryptoUtils
					.generateKeys(curveName);
			ECKeyPair ca2KeyPairEC = asymmetricCryptoUtils
					.generateKeys(curveName);
			ECKeyPair masterRootKeyPairEC = asymmetricCryptoUtils
					.generateKeys(curveName);

			ECKeyPair[] availableKeysEC = { keyEC, rootCAKeyPairEC,
					ca1KeyPairEC, ca2KeyPairEC, masterRootKeyPairEC };

			RSAKeyPair[] availableKeys = { key, rootCAKeyPair, ca1KeyPair,
					ca2KeyPair, masterRootKeyPair };
			List<HashMap<String, String>> availableCertsMaps = new LinkedList<HashMap<String, String>>();
			availableCertsMaps.add(masterRootCertificateInformationMap);
			availableCertsMaps.add(rootCertificateInformationMap);
			availableCertsMaps.add(ca1CertificateInformationMap);
			availableCertsMaps.add(ca2CertificateInformationMap);
			availableCertsMaps.add(subjCertificateInformationMap);

			Integer certificateSerial = 1;
			String[] availableSignAlgorithm = {
					X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_SHA256withRSA,
					X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_MD5withRSA,
					X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_RIPEMD160withRSA };

			log.info("Running test RSA...");
			for (int selectedDigest = 0; selectedDigest < availableSignAlgorithm.length; selectedDigest++) {
				// Timing the RSA MIXcertificate Timing using different signing
				// algorithms
				testMIXCertificateTiming(availableKeys, availableKeysEC,
						availableCertsMaps, notBefore, notAfter,
						certificateSerial,
						availableSignAlgorithm[selectedDigest]);
			}

			String[] availableSignAlgorithmEC = {
					X509UtilsDictionary.EC_X509_SIGN_ALGORITHM_SHA1withECDSA,
					X509UtilsDictionary.EC_X509_SIGN_ALGORITHM_SHA256withECDSA,
					X509UtilsDictionary.EC_X509_SIGN_ALGORITHM_SHA512withECDSA };

			log.info("Running test EC...");
			for (int selectedDigest = 0; selectedDigest < availableSignAlgorithmEC.length; selectedDigest++) {
				// Timing the EC MIX certificate Timing using different signing
				// algorithms
				testMIXCertificateTiming(availableKeysEC, availableKeys,
						availableCertsMaps, notBefore, notAfter,
						certificateSerial,
						availableSignAlgorithmEC[selectedDigest]);
			}

		} catch (CryptoUtilsException e) {
			e.printStackTrace();
			log.error("CREATE CERTIFICATE TIMING= " + e.getMessage(),
					e.getCause());
			log.toFile("CREATE CERTIFICATE TIMING= " + e.getMessage(),
					logFileName);
		}
	}

	/**
	 * Timing creation and saving for RSA certificate, the test includes public
	 * certificates and PKCS12 files
	 * 
	 * @param availableKeys
	 * @param availableCertsMap
	 * @param notBefore
	 * @param notAfter
	 * @param certificateSerial
	 * @param algorithm
	 * @throws CryptoUtilsException
	 * @throws CryptoUtilsX509ExtensionException
	 */
	private void testRSACertificateTiming(RSAKeyPair[] availableKeys,
			List<HashMap<String, String>> availableCertsMap, Date notBefore,
			Date notAfter, Integer certificateSerial, String algorithm) {

		List<Integer> keyUsageList;
		String certType;
		X509Certificate[] chain = new X509Certificate[2];

		// Timing RSA Self-signed certificate
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);

		long startnow = 0;
		long endnow = 0;
		long total = 0;

		long startnowAux = 0;
		long endnowAux = 0;
		long totalAux = 0;
		int totalRounds = 30;

		X509Certificate masterCert;
		X509Certificate certAux;
		RSAKeyPair masterRootKeyPair = availableKeys[rand
				.nextInt(availableKeys.length)];
		RSAKeyPair keyAux = availableKeys[rand.nextInt(availableKeys.length)];
		X509CRL crlAux;

		HashMap<String, String> masterRootCertificateInformationMap = availableCertsMap
				.get(rand.nextInt(availableCertsMap.size()));
		try {
			BigInteger crlNumber = new BigInteger("1");
			// create a final certificate for sign the other things like
			// certificates and testing CRLs
			masterCert = _X509Utils.createV3Cert(keyAux.getPublicKey(),
					keyAux.getPrivateKey(),
					BigInteger.valueOf(certificateSerial), notBefore, notAfter,
					masterRootCertificateInformationMap, keyUsageList,
					certType, algorithm);
			chain[1] = masterCert;
			// Create a test CRL entry, for create a dummy crl for verify the
			// certificates
			List<X509CRLRevokedCertificateEntry> revokedCertificates = new LinkedList<X509CRLRevokedCertificateEntry>();

			Date now = new Date();
			Date tomorrow = new Date(now.getTime() + 1000);
			Date yesterday = new Date(now.getTime() + 100);
			Date nextUpdate = new Date(now.getTime() + 10000);
			// Subject Revoked certificate entry
			X509CRLRevokedCertificateEntry entry;

			certAux = _X509Utils
					.createV3Cert(availableKeys[rand
							.nextInt(availableKeys.length)].getPublicKey(),
							keyAux.getPrivateKey(), BigInteger
									.valueOf(certificateSerial), notBefore,
							notAfter, (X509Certificate) chain[1],
							availableCertsMap.get(rand
									.nextInt(availableCertsMap.size())),
							keyUsageList, certType, algorithm);

			entry = new X509CRLRevokedCertificateEntry(certAux, tomorrow,
					yesterday, X509RevokedCertificateReason.CA_COMPROMISE);
			revokedCertificates.add(entry);
			crlAux = _X509Utils.createCRL(keyAux, masterCert,
					revokedCertificates, nextUpdate, crlNumber, algorithm);

			for (int i = 0; i < totalRounds; i++) {
				// change certificate parameters throw the test
				certificateSerial++;
				masterRootKeyPair = availableKeys[rand
						.nextInt(availableKeys.length)];
				masterRootCertificateInformationMap = availableCertsMap
						.get(rand.nextInt(availableCertsMap.size()));

				for (int j = 0; j < totalRounds; j++) {
					try {
						startnow = java.lang.System.nanoTime();
						_X509Utils.createV3Cert(
								masterRootKeyPair.getPublicKey(),
								masterRootKeyPair.getPrivateKey(),
								BigInteger.valueOf(certificateSerial),
								notBefore, notAfter,
								masterRootCertificateInformationMap,
								keyUsageList, certType, algorithm);
						endnow = java.lang.System.nanoTime();
						total += (endnow - startnow);

						startnowAux = java.lang.System.nanoTime();
						_X509Utils.verifyCertificate(certAux, masterCert,
								crlAux);
						endnowAux = java.lang.System.nanoTime();
						totalAux += (endnowAux - startnowAux);
					} catch (CryptoUtilsException e) {
						e.printStackTrace();
						log.error(
								"[RSA SelfSigned " + algorithm
										+ "] CREATE CERTIFICATE" + "= "
										+ e.getMessage(), e.getCause());
						log.toFile(
								"[RSA SelfSigned " + algorithm
										+ "] CREATE CERTIFICATE" + "= "
										+ e.getMessage(), logFileName);
					} catch (CryptoUtilsX509ExtensionException e) {
						log.error(
								"[RSA SelfSigned " + algorithm
										+ "] CREATE CERTIFICATE" + "= "
										+ e.getMessage(), e.getCause());
						log.toFile(
								"[RSA SelfSigned " + algorithm
										+ "] CREATE CERTIFICATE" + "= "
										+ e.getMessage(), logFileName);
					}
				}
			}

			String totalStr = "[RSA SELF " + algorithm + "] CREATE CERTIFICATE"
					+ "= " + (total / (totalRounds * totalRounds * 1.0));
			log.info(totalStr);
			log.toFile(totalStr, logFileName);

			String totalStrAux = "[RSA SELF " + algorithm
					+ "] VERIFY CERTIFICATE" + "= "
					+ (totalAux / (totalRounds * totalRounds * 1.0));
			log.info(totalStrAux);
			log.toFile(totalStrAux, logFileName);

			// Restart counters
			startnow = 0;
			endnow = 0;
			total = 0;

			startnowAux = 0;
			endnowAux = 0;
			totalAux = 0;

			// Timing RSA signed by CA certificate
			certType = X509UtilsDictionary.CERTIFICATE_TYPE_INTERMEDIATE_CA;
			keyUsageList = new LinkedList<Integer>();
			keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
			keyUsageList
					.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
			keyUsageList
					.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
			keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
			keyUsageList
					.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);

			RSAKeyPair rootCAKeyPair;
			HashMap<String, String> rootCertificateInformationMap;
			for (int i = 0; i < totalRounds; i++) {
				// change certificate parameters throw the test
				certificateSerial++;
				rootCAKeyPair = availableKeys[rand
						.nextInt(availableKeys.length)];
				rootCertificateInformationMap = availableCertsMap.get(rand
						.nextInt(availableCertsMap.size()));

				for (int j = 0; j < totalRounds; j++) {
					try {
						startnow = java.lang.System.nanoTime();
						certAux = _X509Utils.createV3Cert(
								rootCAKeyPair.getPublicKey(),
								keyAux.getPrivateKey(),
								BigInteger.valueOf(certificateSerial),
								notBefore, notAfter,
								(X509Certificate) chain[1],
								rootCertificateInformationMap, keyUsageList,
								certType, algorithm);
						endnow = java.lang.System.nanoTime();
						total += (endnow - startnow);

						startnowAux = java.lang.System.nanoTime();
						_X509Utils.verifyCertificate(certAux, masterCert,
								crlAux);
						endnowAux = java.lang.System.nanoTime();
						totalAux += (endnowAux - startnowAux);
					} catch (CryptoUtilsException e) {
						e.printStackTrace();
						log.error(
								"[RSA - RSA " + algorithm
										+ "] CREATE CERTIFICATE" + "= "
										+ e.getMessage(), e.getCause());
						log.toFile(
								"[RSA - RSA " + algorithm
										+ "] CREATE CERTIFICATE" + "= "
										+ e.getMessage(), logFileName);
					} catch (CryptoUtilsX509ExtensionException e) {
						log.error(
								"[RSA - RSA " + algorithm
										+ "] CREATE CERTIFICATE" + "= "
										+ e.getMessage(), e.getCause());
						log.toFile(
								"[RSA - RSA " + algorithm
										+ "] CREATE CERTIFICATE" + "= "
										+ e.getMessage(), logFileName);
					}
				}
			}

			totalStr = "[RSA - RSA " + algorithm + "] CREATE CERTIFICATE"
					+ "= " + (total / (totalRounds * totalRounds * 1.0));
			log.info(totalStr);
			log.toFile(totalStr, logFileName);

			totalStrAux = "[RSA - RSA " + algorithm + "] VERIFY CERTIFICATE"
					+ "= " + (totalAux / (totalRounds * totalRounds * 1.0));
			log.info(totalStrAux);
			log.toFile(totalStrAux, logFileName);

			chain[0] = certAux;
			testX509CRLTiming(keyAux, masterCert, chain, algorithm);

		} catch (CryptoUtilsException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			log.error("RSA ERROR: " + e1.getMessage(), e1.getCause());
		} catch (CryptoUtilsX509ExtensionException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			log.error("RSA ERROR: " + e1.getMessage(), e1.getCause());
		}
	}

	/**
	 * Timing the PKCS12 SAVE and LOAD process for RSA
	 * 
	 * @param primeSize
	 */
	private void testPKCS12Timing(Integer primeSize) {

		try {
			// Certificate Parameters
			Date notBefore = new Date();
			// - 1000L * 60 * 60 * 24 * 30);
			Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60
					* 60 * 24 * 30);
			HashMap<String, String> rootCertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> masterRootCertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> subjCertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> ca2CertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> ca1CertificateInformationMap = new HashMap<String, String>();

			log.info("Fill certificate");
			fillCertificateHashMaps(masterRootCertificateInformationMap,
					rootCertificateInformationMap,
					ca1CertificateInformationMap, ca2CertificateInformationMap,
					subjCertificateInformationMap);

			log.info("Generating keys RSA");
			RSAKeyPair key;
			// Generate Key and random input data
			key = asymmetricCryptoUtils.generateKeys(primeSize);

			String keyFileName = Environment.getExternalStorageDirectory()
					+ "/cryptoTest/RSAkey" + primeSize;
			File f = new File(keyFileName);
			if (!f.getParentFile().exists()) {
				f.getParentFile().mkdir();
			}

			List<Integer> keyUsageList;
			String certType;
			X509Certificate[] chain = new X509Certificate[1];

			// Timing RSA Self-signed certificate
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

			chain[0] = _X509Utils.createV3Cert(key.getPublicKey(),
					key.getPrivateKey(), BigInteger.valueOf(1), notBefore,
					notAfter, masterRootCertificateInformationMap,
					keyUsageList, certType,
					X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_SHA1withRSA);

			testPKCS12Timing(keyFileName, key, chain, primeSize);
		} catch (CryptoUtilsException e) {
			e.printStackTrace();
			log.error("PKCS12 TIMING= " + e.getMessage(), e.getCause());
			log.toFile("PKCS12 TIMING= " + e.getMessage(), logFileName);
		} catch (CryptoUtilsX509ExtensionException e) {
			e.printStackTrace();
			log.error("PKCS12 TIMING= " + e.getMessage(), e.getCause());
			log.toFile("PKCS12 TIMING= " + e.getMessage(), logFileName);
		}
	}
	
	/**
	 * Timing the PKCS12 SAVE and LOAD process for RSA
	 * 
	 * @param curveName
	 */
	private void testPKCS12Timing(String curveName) {

		try {
			// Certificate Parameters
			Date notBefore = new Date();
			// - 1000L * 60 * 60 * 24 * 30);
			Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60
					* 60 * 24 * 30);
			HashMap<String, String> rootCertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> masterRootCertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> subjCertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> ca2CertificateInformationMap = new HashMap<String, String>();
			HashMap<String, String> ca1CertificateInformationMap = new HashMap<String, String>();

			log.info("Fill certificate");
			fillCertificateHashMaps(masterRootCertificateInformationMap,
					rootCertificateInformationMap,
					ca1CertificateInformationMap, ca2CertificateInformationMap,
					subjCertificateInformationMap);

			log.info("Generating keys EC");
			ECKeyPair key;
			// Generate Key and random input data
			key = asymmetricCryptoUtils.generateKeys(curveName);

			String keyFileName = Environment.getExternalStorageDirectory()
					+ "/cryptoTest/ECkey" + curveName;
			File f = new File(keyFileName);
			if (!f.getParentFile().exists()) {
				f.getParentFile().mkdir();
			}

			List<Integer> keyUsageList;
			String certType;
			X509Certificate[] chain = new X509Certificate[1];

			// Timing RSA Self-signed certificate
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

			chain[0] = _X509Utils.createV3Cert(key.getPublicKey(),
					key.getPrivateKey(), BigInteger.valueOf(1), notBefore,
					notAfter, masterRootCertificateInformationMap,
					keyUsageList, certType,
					X509UtilsDictionary.EC_X509_SIGN_ALGORITHM_SHA1withECDSA);

			testPKCS12Timing(keyFileName, key, chain, curveName);
		} catch (CryptoUtilsException e) {
			e.printStackTrace();
			log.error("PKCS12 TIMING= " + e.getMessage(), e.getCause());
			log.toFile("PKCS12 TIMING= " + e.getMessage(), logFileName);
		} catch (CryptoUtilsX509ExtensionException e) {
			e.printStackTrace();
			log.error("PKCS12 TIMING= " + e.getMessage(), e.getCause());
			log.toFile("PKCS12 TIMING= " + e.getMessage(), logFileName);
		}
	}


	/**
	 * Timing the creation, saving and loading of a X509 CRL using an specific
	 * RSA signing algorithm
	 * 
	 * @param issuerKeyPair
	 * @param issuerCertificate
	 * @param revokedTestCerts
	 * @param algorithm
	 * @param detailResult
	 * @throws CryptoUtilsException
	 * @throws CryptoUtilsX509ExtensionException
	 */
	private void testX509CRLTiming(RSAKeyPair issuerKeyPair,
			X509Certificate issuerCertificate,
			X509Certificate[] revokedTestCerts, String algorithm) {

		long startnow = 0;
		long endnow = 0;
		long total = 0;
		long startnowAux = 0;
		long endnowAux = 0;
		long totalAux = 0;
		int totalRounds = 30;

		Date now = new Date();
		List<X509CRLRevokedCertificateEntry> revokedCertificates = new LinkedList<X509CRLRevokedCertificateEntry>();

		Date tomorrow = new Date(now.getTime() + 1000);
		Date yesterday = new Date(now.getTime() + 100);
		Date nextUpdate = new Date(now.getTime() + 10000);
		BigInteger crlNumber = new BigInteger("1");
		X509CRL crlAux;
		// Subject Revoked certificate entry
		X509CRLRevokedCertificateEntry entry;
		try {
			entry = new X509CRLRevokedCertificateEntry(revokedTestCerts[0],
					tomorrow, yesterday,
					X509RevokedCertificateReason.CA_COMPROMISE);
			revokedCertificates.add(entry);
			for (int i = 0; i < totalRounds; i++) {
				crlNumber = crlNumber.add(new BigInteger("1"));
				for (int j = 0; j < totalRounds; j++) {
					try {
						startnow = java.lang.System.nanoTime();
						crlAux = _X509Utils.createCRL(issuerKeyPair,
								issuerCertificate, revokedCertificates,
								nextUpdate, crlNumber, algorithm);
						endnow = java.lang.System.nanoTime();
						total += (endnow - startnow);

						startnowAux = java.lang.System.nanoTime();
						_X509Utils.verifyCRL(crlAux, issuerCertificate);
						endnowAux = java.lang.System.nanoTime();
						totalAux += (endnowAux - startnowAux);
					} catch (CryptoUtilsException e) {
						e.printStackTrace();
						log.error("[RSA " + algorithm + "] CREATE CRL" + "= "
								+ e.getMessage(), e.getCause());
						log.toFile("[RSA " + algorithm + "] CREATE CRL" + "= "
								+ e.getMessage(), logFileName);
					} catch (CryptoUtilsX509ExtensionException e) {
						log.error("[RSA " + algorithm + "] CREATE CRL" + "= "
								+ e.getMessage(), e.getCause());
						log.toFile("[RSA " + algorithm + "] CREATE CRL" + "= "
								+ e.getMessage(), logFileName);
					}
				}
			}

			String totalStr = "[RSA " + algorithm + "] CREATE CRL" + "= "
					+ (total / (totalRounds * totalRounds * 1.0));
			log.info(totalStr);
			log.toFile(totalStr, logFileName);

			String totalStrAux = "[RSA " + algorithm + "] VERIFY CRL" + "= "
					+ (totalAux / (totalRounds * totalRounds * 1.0));
			log.info(totalStrAux);
			log.toFile(totalStrAux, logFileName);

		} catch (CryptoUtilsException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			log.error("RSA CRL ERROR: " + e.getMessage(), e.getCause());
		}

	}

	/**
	 * Timing creation and saving for EC certificate and CRL
	 * 
	 * @param availableKeys
	 * @param availableCertsMap
	 * @param notBefore
	 * @param notAfter
	 * @param certificateSerial
	 * @param detailResult
	 * @param rootCAKeyPair
	 * @throws CryptoUtilsException
	 * @throws CryptoUtilsX509ExtensionException
	 */
	private void testECCertificateTiming(ECKeyPair[] availableKeys,
			List<HashMap<String, String>> availableCertsMap, Date notBefore,
			Date notAfter, Integer certificateSerial, String algorithm) {

		List<Integer> keyUsageList;
		String certType;
		X509Certificate[] chain = new X509Certificate[2];

		// Timing RSA Self-signed certificate
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);

		long startnow = 0;
		long endnow = 0;
		long total = 0;

		long startnowAux = 0;
		long endnowAux = 0;
		long totalAux = 0;
		int totalRounds = 30;

		X509Certificate masterCert;
		X509Certificate certAux;
		ECKeyPair masterRootKeyPair = availableKeys[rand
				.nextInt(availableKeys.length)];
		ECKeyPair keyAux = availableKeys[rand.nextInt(availableKeys.length)];
		X509CRL crlAux;

		HashMap<String, String> masterRootCertificateInformationMap = availableCertsMap
				.get(rand.nextInt(availableCertsMap.size()));
		try {
			BigInteger crlNumber = new BigInteger("1");
			// create a final certificate for sign the other things like
			// certificates and testing CRLs
			masterCert = _X509Utils.createV3Cert(keyAux.getPublicKey(),
					keyAux.getPrivateKey(),
					BigInteger.valueOf(certificateSerial), notBefore, notAfter,
					masterRootCertificateInformationMap, keyUsageList,
					certType, algorithm);
			chain[1] = masterCert;
			// Create a test CRL entry, for create a dummy crl for verify the
			// certificates
			List<X509CRLRevokedCertificateEntry> revokedCertificates = new LinkedList<X509CRLRevokedCertificateEntry>();

			Date now = new Date();
			Date tomorrow = new Date(now.getTime() + 1000);
			Date yesterday = new Date(now.getTime() + 100);
			Date nextUpdate = new Date(now.getTime() + 10000);
			// Subject Revoked certificate entry
			X509CRLRevokedCertificateEntry entry;

			certAux = _X509Utils
					.createV3Cert(availableKeys[rand
							.nextInt(availableKeys.length)].getPublicKey(),
							keyAux.getPrivateKey(), BigInteger
									.valueOf(certificateSerial), notBefore,
							notAfter, (X509Certificate) chain[1],
							availableCertsMap.get(rand
									.nextInt(availableCertsMap.size())),
							keyUsageList, certType, algorithm);

			entry = new X509CRLRevokedCertificateEntry(certAux, tomorrow,
					yesterday, X509RevokedCertificateReason.CA_COMPROMISE);
			revokedCertificates.add(entry);
			crlAux = _X509Utils.createCRL(keyAux, masterCert,
					revokedCertificates, nextUpdate, crlNumber, algorithm);

			for (int i = 0; i < totalRounds; i++) {
				// change certificate parameters throw the test
				certificateSerial++;
				masterRootKeyPair = availableKeys[rand
						.nextInt(availableKeys.length)];
				masterRootCertificateInformationMap = availableCertsMap
						.get(rand.nextInt(availableCertsMap.size()));

				for (int j = 0; j < totalRounds; j++) {
					try {
						startnow = java.lang.System.nanoTime();
						_X509Utils.createV3Cert(
								masterRootKeyPair.getPublicKey(),
								masterRootKeyPair.getPrivateKey(),
								BigInteger.valueOf(certificateSerial),
								notBefore, notAfter,
								masterRootCertificateInformationMap,
								keyUsageList, certType, algorithm);
						endnow = java.lang.System.nanoTime();
						total += (endnow - startnow);

						startnowAux = java.lang.System.nanoTime();
						_X509Utils.verifyCertificate(certAux, masterCert,
								crlAux);
						endnowAux = java.lang.System.nanoTime();
						totalAux += (endnowAux - startnowAux);
					} catch (CryptoUtilsException e) {
						e.printStackTrace();
						log.error(
								"[EC SelfSigned " + algorithm
										+ "] CREATE CERTIFICATE" + "= "
										+ e.getMessage(), e.getCause());
						log.toFile(
								"[EC SelfSigned " + algorithm
										+ "] CREATE CERTIFICATE" + "= "
										+ e.getMessage(), logFileName);
					} catch (CryptoUtilsX509ExtensionException e) {
						log.error(
								"[EC SelfSigned " + algorithm
										+ "] CREATE CERTIFICATE" + "= "
										+ e.getMessage(), e.getCause());
						log.toFile(
								"[EC SelfSigned " + algorithm
										+ "] CREATE CERTIFICATE" + "= "
										+ e.getMessage(), logFileName);
					}
				}
			}

			String totalStr = "[EC SELF " + algorithm + "] CREATE CERTIFICATE"
					+ "= " + (total / (totalRounds * totalRounds * 1.0));
			log.info(totalStr);
			log.toFile(totalStr, logFileName);

			String totalStrAux = "[EC SELF " + algorithm
					+ "] VERIFY CERTIFICATE" + "= "
					+ (totalAux / (totalRounds * totalRounds * 1.0));
			log.info(totalStrAux);
			log.toFile(totalStrAux, logFileName);

			// Restart counters
			startnow = 0;
			endnow = 0;
			total = 0;

			startnowAux = 0;
			endnowAux = 0;
			totalAux = 0;

			// Timing RSA signed by CA certificate
			certType = X509UtilsDictionary.CERTIFICATE_TYPE_INTERMEDIATE_CA;
			keyUsageList = new LinkedList<Integer>();
			keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
			keyUsageList
					.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
			keyUsageList
					.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
			keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
			keyUsageList
					.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);

			ECKeyPair rootCAKeyPair;
			HashMap<String, String> rootCertificateInformationMap;
			for (int i = 0; i < totalRounds; i++) {
				// change certificate parameters throw the test
				certificateSerial++;
				rootCAKeyPair = availableKeys[rand
						.nextInt(availableKeys.length)];
				rootCertificateInformationMap = availableCertsMap.get(rand
						.nextInt(availableCertsMap.size()));

				for (int j = 0; j < totalRounds; j++) {
					try {
						startnow = java.lang.System.nanoTime();
						certAux = _X509Utils.createV3Cert(
								rootCAKeyPair.getPublicKey(),
								keyAux.getPrivateKey(),
								BigInteger.valueOf(certificateSerial),
								notBefore, notAfter,
								(X509Certificate) chain[1],
								rootCertificateInformationMap, keyUsageList,
								certType, algorithm);
						endnow = java.lang.System.nanoTime();
						total += (endnow - startnow);

						startnowAux = java.lang.System.nanoTime();
						_X509Utils.verifyCertificate(certAux, masterCert,
								crlAux);
						endnowAux = java.lang.System.nanoTime();
						totalAux += (endnowAux - startnowAux);
					} catch (CryptoUtilsException e) {
						e.printStackTrace();
						log.error(
								"[EC - EC " + algorithm
										+ "] CREATE CERTIFICATE" + "= "
										+ e.getMessage(), e.getCause());
						log.toFile(
								"[EC - EC " + algorithm
										+ "] CREATE CERTIFICATE" + "= "
										+ e.getMessage(), logFileName);
					} catch (CryptoUtilsX509ExtensionException e) {
						log.error(
								"[EC - EC " + algorithm
										+ "] CREATE CERTIFICATE" + "= "
										+ e.getMessage(), e.getCause());
						log.toFile(
								"[EC - EC " + algorithm
										+ "] CREATE CERTIFICATE" + "= "
										+ e.getMessage(), logFileName);
					}
				}
			}

			totalStr = "[EC - EC " + algorithm + "] CREATE CERTIFICATE" + "= "
					+ (total / (totalRounds * totalRounds * 1.0));
			log.info(totalStr);
			log.toFile(totalStr, logFileName);

			totalStrAux = "[EC - EC " + algorithm + "] VERIFY CERTIFICATE"
					+ "= " + (totalAux / (totalRounds * totalRounds * 1.0));
			log.info(totalStrAux);
			log.toFile(totalStrAux, logFileName);

			chain[0] = certAux;
			testX509CRLTiming(keyAux, masterCert, chain, algorithm);

		} catch (CryptoUtilsException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			log.error("EC ERROR: " + e1.getMessage(), e1.getCause());
		} catch (CryptoUtilsX509ExtensionException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			log.error("EC ERROR: " + e1.getMessage(), e1.getCause());
		}
	}

	/**
	 * Timing the creation, saving and loading of a X509 CRL using an specific
	 * EC signing algorithm
	 * 
	 * @param issuerKeyPair
	 * @param issuerCertificate
	 * @param revokedTestCerts
	 * @param algorithm
	 * @param detailResult
	 * @throws CryptoUtilsException
	 * @throws CryptoUtilsX509ExtensionException
	 */
	private void testX509CRLTiming(ECKeyPair issuerKeyPair,
			X509Certificate issuerCertificate,
			X509Certificate[] revokedTestCerts, String algorithm) {

		long startnow = 0;
		long endnow = 0;
		long total = 0;
		long startnowAux = 0;
		long endnowAux = 0;
		long totalAux = 0;
		int totalRounds = 30;

		Date now = new Date();
		List<X509CRLRevokedCertificateEntry> revokedCertificates = new LinkedList<X509CRLRevokedCertificateEntry>();

		Date tomorrow = new Date(now.getTime() + 1000);
		Date yesterday = new Date(now.getTime() + 100);
		Date nextUpdate = new Date(now.getTime() + 10000);
		BigInteger crlNumber = new BigInteger("1");
		X509CRL crlAux;
		// Subject Revoked certificate entry
		X509CRLRevokedCertificateEntry entry;
		try {
			entry = new X509CRLRevokedCertificateEntry(revokedTestCerts[0],
					tomorrow, yesterday,
					X509RevokedCertificateReason.CA_COMPROMISE);
			revokedCertificates.add(entry);
			for (int i = 0; i < totalRounds; i++) {
				crlNumber = crlNumber.add(new BigInteger("1"));
				for (int j = 0; j < totalRounds; j++) {
					try {
						startnow = java.lang.System.nanoTime();
						crlAux = _X509Utils.createCRL(issuerKeyPair,
								issuerCertificate, revokedCertificates,
								nextUpdate, crlNumber, algorithm);
						endnow = java.lang.System.nanoTime();
						total += (endnow - startnow);

						startnowAux = java.lang.System.nanoTime();
						_X509Utils.verifyCRL(crlAux, issuerCertificate);
						endnowAux = java.lang.System.nanoTime();
						totalAux += (endnowAux - startnowAux);
					} catch (CryptoUtilsException e) {
						e.printStackTrace();
						log.error("[EC " + algorithm + "] CREATE CRL" + "= "
								+ e.getMessage(), e.getCause());
						log.toFile("[EC " + algorithm + "] CREATE CRL" + "= "
								+ e.getMessage(), logFileName);
					} catch (CryptoUtilsX509ExtensionException e) {
						log.error("[EC " + algorithm + "] CREATE CRL" + "= "
								+ e.getMessage(), e.getCause());
						log.toFile("[EC " + algorithm + "] CREATE CRL" + "= "
								+ e.getMessage(), logFileName);
					}
				}
			}

			String totalStr = "[EC " + algorithm + "] CREATE CRL" + "= "
					+ (total / (totalRounds * totalRounds * 1.0));
			log.info(totalStr);
			log.toFile(totalStr, logFileName);

			String totalStrAux = "[EC " + algorithm + "] VERIFY CRL" + "= "
					+ (totalAux / (totalRounds * totalRounds * 1.0));
			log.info(totalStrAux);
			log.toFile(totalStrAux, logFileName);

		} catch (CryptoUtilsException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			log.error("EC CRL ERROR: " + e.getMessage(), e.getCause());
		}

	}

	/**
	 * Timing creation and saving for EC certificate and CRL
	 * 
	 * @param availableKeys
	 * @param availableCertsMap
	 * @param notBefore
	 * @param notAfter
	 * @param certificateSerial
	 * @param detailResult
	 * @param rootCAKeyPair
	 * @throws CryptoUtilsException
	 * @throws CryptoUtilsX509ExtensionException
	 */
	private void testMIXCertificateTiming(ECKeyPair[] availableECKeys,
			RSAKeyPair[] availableRSAKeys,
			List<HashMap<String, String>> availableCertsMap, Date notBefore,
			Date notAfter, Integer certificateSerial, String algorithm) {

		List<Integer> keyUsageList;
		String certType;
		X509Certificate[] chain = new X509Certificate[2];

		// Timing RSA Self-signed certificate
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);

		long startnow = 0;
		long endnow = 0;
		long total = 0;

		long startnowAux = 0;
		long endnowAux = 0;
		long totalAux = 0;
		int totalRounds = 30;

		X509Certificate masterCert;
		X509Certificate certAux;

		ECKeyPair keyAux = availableECKeys[rand.nextInt(availableECKeys.length)];
		X509CRL crlAux;

		HashMap<String, String> masterRootCertificateInformationMap = availableCertsMap
				.get(rand.nextInt(availableCertsMap.size()));
		try {
			BigInteger crlNumber = new BigInteger("1");
			// create a final certificate for sign the other things like
			// certificates and testing CRLs
			masterCert = _X509Utils.createV3Cert(keyAux.getPublicKey(),
					keyAux.getPrivateKey(),
					BigInteger.valueOf(certificateSerial), notBefore, notAfter,
					masterRootCertificateInformationMap, keyUsageList,
					certType, algorithm);
			chain[1] = masterCert;
			// Create a test CRL entry, for create a dummy crl for verify the
			// certificates
			List<X509CRLRevokedCertificateEntry> revokedCertificates = new LinkedList<X509CRLRevokedCertificateEntry>();

			Date now = new Date();
			Date tomorrow = new Date(now.getTime() + 1000);
			Date yesterday = new Date(now.getTime() + 100);
			Date nextUpdate = new Date(now.getTime() + 10000);
			// Subject Revoked certificate entry
			X509CRLRevokedCertificateEntry entry;

			certAux = _X509Utils
					.createV3Cert(availableECKeys[rand
							.nextInt(availableECKeys.length)].getPublicKey(),
							keyAux.getPrivateKey(), BigInteger
									.valueOf(certificateSerial), notBefore,
							notAfter, (X509Certificate) chain[1],
							availableCertsMap.get(rand
									.nextInt(availableCertsMap.size())),
							keyUsageList, certType, algorithm);

			entry = new X509CRLRevokedCertificateEntry(certAux, tomorrow,
					yesterday, X509RevokedCertificateReason.CA_COMPROMISE);
			revokedCertificates.add(entry);
			crlAux = _X509Utils.createCRL(keyAux, masterCert,
					revokedCertificates, nextUpdate, crlNumber, algorithm);

			// Create certificate parameters
			certType = X509UtilsDictionary.CERTIFICATE_TYPE_INTERMEDIATE_CA;
			keyUsageList = new LinkedList<Integer>();
			keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
			keyUsageList
					.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
			keyUsageList
					.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
			keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
			keyUsageList
					.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);

			RSAKeyPair rootCAKeyPair;
			HashMap<String, String> rootCertificateInformationMap;
			for (int i = 0; i < totalRounds; i++) {
				// change certificate parameters throw the test
				certificateSerial++;
				rootCAKeyPair = availableRSAKeys[rand
						.nextInt(availableRSAKeys.length)];
				rootCertificateInformationMap = availableCertsMap.get(rand
						.nextInt(availableCertsMap.size()));

				for (int j = 0; j < totalRounds; j++) {
					try {
						startnow = java.lang.System.nanoTime();
						certAux = _X509Utils.createV3Cert(
								rootCAKeyPair.getPublicKey(),
								keyAux.getPrivateKey(),
								BigInteger.valueOf(certificateSerial),
								notBefore, notAfter,
								(X509Certificate) chain[1],
								rootCertificateInformationMap, keyUsageList,
								certType, algorithm);
						endnow = java.lang.System.nanoTime();
						total += (endnow - startnow);

						startnowAux = java.lang.System.nanoTime();
						_X509Utils.verifyCertificate(certAux, masterCert,
								crlAux);
						endnowAux = java.lang.System.nanoTime();
						totalAux += (endnowAux - startnowAux);
					} catch (CryptoUtilsException e) {
						e.printStackTrace();
						log.error(
								"[EC - RSA " + algorithm
										+ "] CREATE CERTIFICATE" + "= "
										+ e.getMessage(), e.getCause());
						log.toFile(
								"[EC - RSA " + algorithm
										+ "] CREATE CERTIFICATE" + "= "
										+ e.getMessage(), logFileName);
					} catch (CryptoUtilsX509ExtensionException e) {
						log.error(
								"[EC - RSA " + algorithm
										+ "] CREATE CERTIFICATE" + "= "
										+ e.getMessage(), e.getCause());
						log.toFile(
								"[EC - RSA " + algorithm
										+ "] CREATE CERTIFICATE" + "= "
										+ e.getMessage(), logFileName);
					}
				}
			}

			String totalStr = "[EC - RSA " + algorithm + "] CREATE CERTIFICATE"
					+ "= " + (total / (totalRounds * totalRounds * 1.0));
			log.info(totalStr);
			log.toFile(totalStr, logFileName);

			String totalStrAux = "[EC - RSA " + algorithm
					+ "] VERIFY CERTIFICATE" + "= "
					+ (totalAux / (totalRounds * totalRounds * 1.0));
			log.info(totalStrAux);
			log.toFile(totalStrAux, logFileName);
		} catch (CryptoUtilsException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			log.error("EC ERROR: " + e1.getMessage(), e1.getCause());
		} catch (CryptoUtilsX509ExtensionException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			log.error("EC ERROR: " + e1.getMessage(), e1.getCause());
		}
	}

	/**
	 * Timing creation and saving for EC certificate and CRL
	 * 
	 * @param availableKeys
	 * @param availableCertsMap
	 * @param notBefore
	 * @param notAfter
	 * @param certificateSerial
	 * @param detailResult
	 * @param rootCAKeyPair
	 * @throws CryptoUtilsException
	 * @throws CryptoUtilsX509ExtensionException
	 */
	private void testMIXCertificateTiming(RSAKeyPair[] availableRSAKeys,
			ECKeyPair[] availableECKeys,
			List<HashMap<String, String>> availableCertsMap, Date notBefore,
			Date notAfter, Integer certificateSerial, String algorithm) {

		List<Integer> keyUsageList;
		String certType;
		X509Certificate[] chain = new X509Certificate[2];

		// Timing RSA Self-signed certificate
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);

		long startnow = 0;
		long endnow = 0;
		long total = 0;

		long startnowAux = 0;
		long endnowAux = 0;
		long totalAux = 0;
		int totalRounds = 30;

		X509Certificate masterCert;
		X509Certificate certAux;

		RSAKeyPair keyAux = availableRSAKeys[rand
				.nextInt(availableRSAKeys.length)];
		X509CRL crlAux;

		HashMap<String, String> masterRootCertificateInformationMap = availableCertsMap
				.get(rand.nextInt(availableCertsMap.size()));
		try {
			BigInteger crlNumber = new BigInteger("1");
			// create a final certificate for sign the other things like
			// certificates and testing CRLs
			masterCert = _X509Utils.createV3Cert(keyAux.getPublicKey(),
					keyAux.getPrivateKey(),
					BigInteger.valueOf(certificateSerial), notBefore, notAfter,
					masterRootCertificateInformationMap, keyUsageList,
					certType, algorithm);
			chain[1] = masterCert;
			// Create a test CRL entry, for create a dummy crl for verify the
			// certificates
			List<X509CRLRevokedCertificateEntry> revokedCertificates = new LinkedList<X509CRLRevokedCertificateEntry>();

			Date now = new Date();
			Date tomorrow = new Date(now.getTime() + 1000);
			Date yesterday = new Date(now.getTime() + 100);
			Date nextUpdate = new Date(now.getTime() + 10000);
			// Subject Revoked certificate entry
			X509CRLRevokedCertificateEntry entry;

			certAux = _X509Utils
					.createV3Cert(availableECKeys[rand
							.nextInt(availableECKeys.length)].getPublicKey(),
							keyAux.getPrivateKey(), BigInteger
									.valueOf(certificateSerial), notBefore,
							notAfter, (X509Certificate) chain[1],
							availableCertsMap.get(rand
									.nextInt(availableCertsMap.size())),
							keyUsageList, certType, algorithm);

			entry = new X509CRLRevokedCertificateEntry(certAux, tomorrow,
					yesterday, X509RevokedCertificateReason.CA_COMPROMISE);
			revokedCertificates.add(entry);
			crlAux = _X509Utils.createCRL(keyAux, masterCert,
					revokedCertificates, nextUpdate, crlNumber, algorithm);

			// Create certificate parameters
			certType = X509UtilsDictionary.CERTIFICATE_TYPE_INTERMEDIATE_CA;
			keyUsageList = new LinkedList<Integer>();
			keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
			keyUsageList
					.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
			keyUsageList
					.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
			keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
			keyUsageList
					.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);

			ECKeyPair rootCAKeyPair;
			HashMap<String, String> rootCertificateInformationMap;
			for (int i = 0; i < totalRounds; i++) {
				// change certificate parameters throw the test
				certificateSerial++;
				rootCAKeyPair = availableECKeys[rand
						.nextInt(availableECKeys.length)];
				rootCertificateInformationMap = availableCertsMap.get(rand
						.nextInt(availableCertsMap.size()));

				for (int j = 0; j < totalRounds; j++) {
					try {
						startnow = java.lang.System.nanoTime();
						certAux = _X509Utils.createV3Cert(
								rootCAKeyPair.getPublicKey(),
								keyAux.getPrivateKey(),
								BigInteger.valueOf(certificateSerial),
								notBefore, notAfter,
								(X509Certificate) chain[1],
								rootCertificateInformationMap, keyUsageList,
								certType, algorithm);
						endnow = java.lang.System.nanoTime();
						total += (endnow - startnow);

						startnowAux = java.lang.System.nanoTime();
						_X509Utils.verifyCertificate(certAux, masterCert,
								crlAux);
						endnowAux = java.lang.System.nanoTime();
						totalAux += (endnowAux - startnowAux);
					} catch (CryptoUtilsException e) {
						e.printStackTrace();
						log.error(
								"[RSA - EC " + algorithm
										+ "] CREATE CERTIFICATE" + "= "
										+ e.getMessage(), e.getCause());
						log.toFile(
								"[RSA - EC " + algorithm
										+ "] CREATE CERTIFICATE" + "= "
										+ e.getMessage(), logFileName);
					} catch (CryptoUtilsX509ExtensionException e) {
						log.error(
								"[RSA - EC " + algorithm
										+ "] CREATE CERTIFICATE" + "= "
										+ e.getMessage(), e.getCause());
						log.toFile(
								"[RSA - EC " + algorithm
										+ "] CREATE CERTIFICATE" + "= "
										+ e.getMessage(), logFileName);
					}
				}
			}

			String totalStr = "[RSA - EC " + algorithm + "] CREATE CERTIFICATE"
					+ "= " + (total / (totalRounds * totalRounds * 1.0));
			log.info(totalStr);
			log.toFile(totalStr, logFileName);

			String totalStrAux = "[RSA - EC " + algorithm
					+ "] VERIFY CERTIFICATE" + "= "
					+ (totalAux / (totalRounds * totalRounds * 1.0));
			log.info(totalStrAux);
			log.toFile(totalStrAux, logFileName);
		} catch (CryptoUtilsException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			log.error("RSA ERROR: " + e1.getMessage(), e1.getCause());
		} catch (CryptoUtilsX509ExtensionException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			log.error("RSA ERROR: " + e1.getMessage(), e1.getCause());
		}
	}

	/**
	 * Timing save and load EC PKCS file
	 * 
	 * @param fileName
	 * @param subjectKeyPair
	 * @param chain
	 * @param curveName
	 * @param detailResult
	 */
	private void testPKCS12Timing(String fileName, ECKeyPair subjectKeyPair,
			X509Certificate[] chain, String curveName) {

		long startnow = 0;
		long endnow = 0;
		long total = 0;

		long startnowAux = 0;
		long endnowAux = 0;
		long totalAux = 0;
		int totalRounds = 20;
		String fileSufix = "";
		String password = "PASSWORD";

		// Start Plain PEM Private Key test
		fileSufix = "pkcs12.p12";

		for (int i = 0; i < totalRounds; i++) {
			// change certificate parameters throw the test

			for (int j = 0; j < totalRounds; j++) {
				try {
					startnow = java.lang.System.nanoTime();
					subjectKeyPair.savePKCS12(fileName + fileSufix, password,
							password, chain);
					endnow = java.lang.System.nanoTime();
					total += (endnow - startnow);
				} catch (CryptoUtilsException e) {
					e.printStackTrace();
					log.error(
							"[PKCS12 " + curveName + "] SAVE/LOAD" + "= "
									+ e.getMessage(), e.getCause());
					log.toFile("[PKCS12 " + curveName + "] SAVE/LOAD" + "= "
							+ e.getMessage(), logFileName);
				}
				try {
					startnowAux = java.lang.System.nanoTime();
					ECKeyPair.loadPKCS12(fileName + fileSufix, password,
							password);
					endnowAux = java.lang.System.nanoTime();
					totalAux += (endnowAux - startnowAux);
				} catch (CryptoUtilsException e) {
					e.printStackTrace();
					log.error(
							"[PKCS12 " + curveName + "] SAVE/LOAD" + "= "
									+ e.getMessage(), e.getCause());
					log.toFile("[PKCS12 " + curveName + "] SAVE/LOAD" + "= "
							+ e.getMessage(), logFileName);
				}
			}
		}

		String totalStr = "[PKCS12 " + curveName + "] SAVE/LOAD" + "= "
				+ (total / (totalRounds * totalRounds * 1.0));
		log.info(totalStr);
		log.toFile(totalStr, logFileName);

		String totalStrAux = "[PKCS12 " + curveName + "] SAVE/LOAD" + "= "
				+ (totalAux / (totalRounds * totalRounds * 1.0));
		log.info(totalStrAux);
		log.toFile(totalStrAux, logFileName);
	}

	/**
	 * Timing save and load EC PKCS file
	 * 
	 * @param fileName
	 * @param subjectKeyPair
	 * @param chain
	 * @param curveName
	 * @param detailResult
	 */
	private void testPKCS12Timing(String fileName, RSAKeyPair subjectKeyPair,
			X509Certificate[] chain, Integer primeSize) {

		long startnow = 0;
		long endnow = 0;
		long total = 0;

		long startnowAux = 0;
		long endnowAux = 0;
		long totalAux = 0;
		int totalRounds = 20;
		String fileSufix = "";
		String password = "PASSWORD";

		// Start Plain PEM Private Key test
		fileSufix = "pkcs12.p12";

		for (int i = 0; i < totalRounds; i++) {
			// change certificate parameters throw the test

			for (int j = 0; j < totalRounds; j++) {
				try {
					startnow = java.lang.System.nanoTime();
					subjectKeyPair.savePKCS12(fileName + fileSufix, password,
							password, chain);
					endnow = java.lang.System.nanoTime();
					total += (endnow - startnow);
				} catch (CryptoUtilsException e) {
					e.printStackTrace();
					log.error(
							"[PKCS12 " + primeSize + "] SAVE/LOAD" + "= "
									+ e.getMessage(), e.getCause());
					log.toFile("[PKCS12 " + primeSize + "] SAVE/LOAD" + "= "
							+ e.getMessage(), logFileName);
				}
				try {
					startnowAux = java.lang.System.nanoTime();
					RSAKeyPair.loadPKCS12(fileName + fileSufix, password,
							password);
					endnowAux = java.lang.System.nanoTime();
					totalAux += (endnowAux - startnowAux);
				} catch (CryptoUtilsException e) {
					e.printStackTrace();
					log.error(
							"[PKCS12 " + primeSize + "] SAVE/LOAD" + "= "
									+ e.getMessage(), e.getCause());
					log.toFile("[PKCS12 " + primeSize + "] SAVE/LOAD" + "= "
							+ e.getMessage(), logFileName);
				}
			}
		}

		String totalStr = "[PKCS12 " + primeSize + "] SAVE/LOAD" + "= "
				+ (total / (totalRounds * totalRounds * 1.0));
		log.info(totalStr);
		log.toFile(totalStr, logFileName);

		String totalStrAux = "[PKCS12 " + primeSize + "] SAVE/LOAD" + "= "
				+ (totalAux / (totalRounds * totalRounds * 1.0));
		log.info(totalStrAux);
		log.toFile(totalStrAux, logFileName);
	}
}
