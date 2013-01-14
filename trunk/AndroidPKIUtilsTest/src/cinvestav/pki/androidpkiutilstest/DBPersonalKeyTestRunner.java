package cinvestav.pki.androidpkiutilstest;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase.CursorFactory;
import cinvestav.android.pki.cryptography.cert.CertificateInformationKeys;
import cinvestav.android.pki.cryptography.ec.ECDomainParameters;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsX509ExtensionException;
import cinvestav.android.pki.cryptography.key.ECKeyPair;
import cinvestav.android.pki.cryptography.key.RSAKeyPair;
import cinvestav.android.pki.cryptography.utils.AsymmetricCryptoUtils;
import cinvestav.android.pki.cryptography.utils.CryptoUtils;
import cinvestav.android.pki.cryptography.utils.DigestCryptoUtils;
import cinvestav.android.pki.cryptography.utils.X509Utils;
import cinvestav.android.pki.cryptography.utils.X509UtilsDictionary;
import cinvestav.android.pki.db.controller.PersonalKeyController;
import cinvestav.android.pki.db.controller.SubjectController;
import cinvestav.android.pki.db.dao.PersonalKeyDAO;
import cinvestav.android.pki.db.dao.SubjectDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.android.pki.utils.DataBaseDictionary;
import cinvestav.android.pki.utils.LogUtil;

/**
 *  Created on  : 09/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	
 */

/**
 * This class contains all the test corresponding to PersonalKey DB
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 09/08/2012
 * @version 1.0
 */
public class DBPersonalKeyTestRunner {

	protected static LogUtil log = new LogUtil("ANDROID_PKI_UTILS");
	private PersonalKeyController personalKeyController;
	private SubjectController subjectController;
	private AsymmetricCryptoUtils asymmetricCryptoUtils;
	private DigestCryptoUtils digestCryptoUtils;
	private X509Utils _X509Utils;

	/**
	 * 
	 * @param context
	 * @param name
	 * @param factory
	 * @param version
	 * @throws CryptoUtilsException
	 */
	public DBPersonalKeyTestRunner(Context context, String name,
			CursorFactory factory, int version) throws CryptoUtilsException {
		this.personalKeyController = new PersonalKeyController(context, name,
				factory, version);
		this.subjectController = new SubjectController(context, name, factory,
				version);
		asymmetricCryptoUtils = new AsymmetricCryptoUtils();
		digestCryptoUtils = new DigestCryptoUtils();

		try {
			_X509Utils = new X509Utils();
		} catch (CryptoUtilsException e) {
			e.printStackTrace();
			log.error("testX509CertificateV3 = " + e.getMessage(), e.getCause());
		}
	}

	/**
	 * Constructor that inits the data base connection using application context
	 * 
	 * @param context
	 * @throws CryptoUtilsException
	 */
	public DBPersonalKeyTestRunner(Context context) throws CryptoUtilsException {
		this.personalKeyController = new PersonalKeyController(context);
		this.subjectController = new SubjectController(context);
		asymmetricCryptoUtils = new AsymmetricCryptoUtils();
		digestCryptoUtils = new DigestCryptoUtils();
		try {
			_X509Utils = new X509Utils();
		} catch (CryptoUtilsException e) {
			e.printStackTrace();
			log.error("testX509CertificateV3 = " + e.getMessage(), e.getCause());
		}
	}

	public void testPersonalKeyDB(Integer testNumber, Boolean details)
			throws DBException {
		log.info(" ********* PersonalKey DB-Controller Test Begin *********");
		List<SubjectDAO> allSubjectList = subjectController.getAll();
		Random rand = new Random(System.currentTimeMillis());

		List<SubjectDAO> dummySubjectList = new LinkedList<SubjectDAO>();
		// Select 5 subject randomly
		for (int i = 0; i < 5; i++) {
			Integer subID = rand.nextInt(allSubjectList.size());
			dummySubjectList.add(allSubjectList.get(subID));
		}

		fillDummySubjectWithPersonalKeyList(dummySubjectList);
		log.info(" ********* INSERT *********");
		for (SubjectDAO subject : dummySubjectList) {
			for (PersonalKeyDAO personalKey : subject.getKeyList()) {
				performPersonalKeyInsert(personalKey, subject.getId(), details);
			}
		}
		
		log.info(" ********* GET CURRENT ID *********");
		for (int i = 0; i <= testNumber; i++) {
			performPersonalKeyGetCurrentId(details);
		}

		log.info(" ********* GET ALL *********");
		List<PersonalKeyDAO> dbList = performPersonalKeyGetAll(details);

		Integer id;
		log.info(" ********* GET BY ID *********");
		for (int i = 0; i <= testNumber; i++) {
			do {
				id = rand.nextInt(dbList.size());
			} while (id == 0);
			performPersonalKeyGetByID(dbList.get(id).getId(), details);
		}

		log.info(" ********* GET BY SUBJECT ID *********");
		for (int i = 0; i <= testNumber; i++) {
			do {
				id = rand.nextInt(allSubjectList.size());
			} while (id == 0);
			performPersonalKeyGetBySubjectID(id, details);
		}

		log.info(" ********* GET BY UNIQUE ID *********");
		for (int i = 0; i <= testNumber; i++) {
			do {
				id = rand.nextInt(dbList.size());
			} while (id == 0);
			performPersonalKeyGetUniqueID(dbList.get(id).getKeyID(), details);
		}

		log.info(" ********* GET BY TYPE *********");
		for (int i = 0; i <= testNumber; i++) {
			do {
				id = rand.nextInt(dbList.size());
			} while (id == 0);
			performPersonalKeyGetByType(dbList.get(id).getKeyType(), details);
		}

		log.info(" ********* GET BY ADV FILTER *********");
		for (int i = 0; i <= testNumber; i++) {
			do {
				id = rand.nextInt(dbList.size());
			} while (id == 0);
			/*
			 * Filter map where: Key = Tag of the filter to be used, should be
			 * define in "DataBaseDictionary" Class, this tags must be written
			 * as a SQL WHERE clause using a PreparedStament form for example:
			 * 'DBfield = ?' or 'DBfield LIKE ?' Value = Must be a string array
			 * of 3 positions where: [0] = Value to be searched in the data base
			 * [1] = Data type, according to this, the PreparedStatemen will be
			 * constructed, the valid DataTypes are defined in the
			 * "DataBaseDictionary"
			 */
			Map<String, String[]> filterMap = new HashMap<String, String[]>();
			String[] value = new String[3];
			/*
			 * Establish filter properties
			 */
			// Filter value
			value[0] = dbList.get(id).getKeyID() + "";
			// Filter type
			value[1] = DataBaseDictionary.FILTER_TYPE_PERSONALKEY_UNIQUE_KEY;
			filterMap.put(DataBaseDictionary.FILTER_PERSONALKEY_UNIQUE_KEY,
					value);

			value = new String[3];
			/*
			 * Establish filter properties
			 */
			// Filter value
			value[0] = dbList.get(id).getId() + "";
			// Filter type
			value[1] = DataBaseDictionary.FILTER_TYPE_PERSONALKEY_ID;
			filterMap.put(DataBaseDictionary.FILTER_PERSONALKEY_ID, value);

			value = new String[3];
			/*
			 * Establish filter properties
			 */
			// Filter value
			value[0] = dbList.get(id).getKeyType() + "";
			// Filter type
			value[1] = DataBaseDictionary.FILTER_TYPE_PERSONALKEY_TYPE;
			filterMap.put(DataBaseDictionary.FILTER_PERSONALKEY_TYPE, value);

			performPersonalKeyGetByAdvanced(filterMap, details);
		}

		log.info(" ********* UPDATE *********");
		for (int i = 0; i <= testNumber; i++) {
			do {
				id = rand.nextInt(dummySubjectList.size());
			} while (id == 0);
			SubjectDAO subject = dummySubjectList.get(id);
			int idKey = 0;
			do {
				idKey = rand.nextInt(dbList.size());
			} while (idKey == 0);
			PersonalKeyDAO key = dbList.get(idKey);
			key.setComment(key.getComment() + "_X");
			// sub.setName(sub.getName() + "X");
			performPersonalKeyUpdate(key, subject.getId(), details);
		}

		log.info(" ********* DELETE *********");
		for (int i = 0; i <= testNumber; i++) {
			do {
				id = rand.nextInt(dbList.size());
			} while (id == 0);
			PersonalKeyDAO del = dbList.get(id);
			performPersonalKeyDelete(del, details);
		}

	}

	private void fillCertificateHashMaps(
			HashMap<String, String> subject1CertificateInformationMap,
			HashMap<String, String> subject2CertificateInformationMap,
			HashMap<String, String> subject3CertificateInformationMap) {

		subject1CertificateInformationMap.put(
				CertificateInformationKeys.FRIENDLY_NAME, "Subject1");
		subject1CertificateInformationMap.put(
				CertificateInformationKeys.COUNTRY, "MX");
		subject1CertificateInformationMap.put(
				CertificateInformationKeys.EmailAddress, "subject1@gmail.com");
		subject1CertificateInformationMap.put(
				CertificateInformationKeys.FULL_COMMON_NAME,
				"Subject1 Name Master");
		subject1CertificateInformationMap.put(
				CertificateInformationKeys.LOCALITY, "GAM");
		subject1CertificateInformationMap.put(CertificateInformationKeys.STATE,
				"DF");
		subject1CertificateInformationMap.put(
				CertificateInformationKeys.ORGANIZATION, "Cinvestav");
		subject1CertificateInformationMap.put(
				CertificateInformationKeys.DEVICE_ID,
				SCCipherTestActivity.ANDROID_ID);

		subject2CertificateInformationMap.put(
				CertificateInformationKeys.FRIENDLY_NAME, "Subject2");
		subject2CertificateInformationMap.put(
				CertificateInformationKeys.COUNTRY, "MX");
		subject2CertificateInformationMap.put(
				CertificateInformationKeys.EmailAddress, "subject2@gmail.com");
		subject2CertificateInformationMap.put(
				CertificateInformationKeys.FULL_COMMON_NAME,
				"Subject2 Name Master");
		subject2CertificateInformationMap.put(
				CertificateInformationKeys.LOCALITY, "GAM");
		subject2CertificateInformationMap.put(CertificateInformationKeys.STATE,
				"DF");
		subject2CertificateInformationMap.put(
				CertificateInformationKeys.ORGANIZATION, "Cinvestav");
		subject2CertificateInformationMap.put(
				CertificateInformationKeys.DEVICE_ID,
				SCCipherTestActivity.ANDROID_ID);

		subject3CertificateInformationMap.put(
				CertificateInformationKeys.FRIENDLY_NAME, "Subject3");
		subject3CertificateInformationMap.put(
				CertificateInformationKeys.COUNTRY, "MX");
		subject3CertificateInformationMap.put(
				CertificateInformationKeys.EmailAddress, "subject3@gmail.com");
		subject3CertificateInformationMap.put(
				CertificateInformationKeys.FULL_COMMON_NAME,
				"Subject3 Name Master");
		subject3CertificateInformationMap.put(
				CertificateInformationKeys.LOCALITY, "GAM");
		subject3CertificateInformationMap.put(CertificateInformationKeys.STATE,
				"DF");
		subject3CertificateInformationMap.put(
				CertificateInformationKeys.ORGANIZATION, "Cinvestav");
		subject3CertificateInformationMap.put(
				CertificateInformationKeys.DEVICE_ID,
				SCCipherTestActivity.ANDROID_ID);

	}

	private void fillDummySubjectWithPersonalKeyList(
			List<SubjectDAO> dummySubjectList) throws DBException {

		HashMap<String, String> subject0CertificateInformationMap = new HashMap<String, String>();
		HashMap<String, String> subject1CertificateInformationMap = new HashMap<String, String>();
		HashMap<String, String> subject2CertificateInformationMap = new HashMap<String, String>();

		fillCertificateHashMaps(subject0CertificateInformationMap,
				subject1CertificateInformationMap,
				subject2CertificateInformationMap);

		Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60
				* 24 * 30);
		Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60 * 60
				* 24 * 30);

		Certificate[] chain;

		List<Integer> keyUsageList;
		String certType;
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);

		List<PersonalKeyDAO> dummySubjectPersonalKeyList;

		String password = "p";
		String encodedKeyStr;
		// Generates test keys
		ECKeyPair ecKeyPair;
		RSAKeyPair rsaKeyPair;

		PersonalKeyDAO personalKeyTest;
		try {
			/******************* SUBJECT[0] ********************************/
			// Create an RSA Key pair, and add the keys to a list, then add this
			// list to the subject[0]
			rsaKeyPair = asymmetricCryptoUtils.generateKeys(1024);
			dummySubjectPersonalKeyList = new LinkedList<PersonalKeyDAO>();
			// ADD RSA Private key
			personalKeyTest = new PersonalKeyDAO();
			personalKeyTest.setKeyType(PersonalKeyDAO.PRIVATE_RSA);
			encodedKeyStr = new String(rsaKeyPair.getPrivateKey().encode(
					password));
			personalKeyTest.setKeyStr(encodedKeyStr);
			personalKeyTest.setKeyID(digestCryptoUtils.getDigest(encodedKeyStr,
					CryptoUtils.DIGEST_FUNCTION_SHA_1,
					CryptoUtils.ENCODER_BASE64));
			dummySubjectPersonalKeyList.add(personalKeyTest);

			// ADD RSA Public key
			personalKeyTest = new PersonalKeyDAO();
			personalKeyTest.setKeyType(PersonalKeyDAO.PUBLIC_RSA);
			encodedKeyStr = new String(rsaKeyPair.getPublicKey().encode());
			personalKeyTest.setKeyStr(encodedKeyStr);
			personalKeyTest.setKeyID(digestCryptoUtils.getDigest(encodedKeyStr,
					CryptoUtils.DIGEST_FUNCTION_SHA_1,
					CryptoUtils.ENCODER_BASE64));
			dummySubjectPersonalKeyList.add(personalKeyTest);

			// ADD RSA PKCS12
			personalKeyTest = new PersonalKeyDAO();
			personalKeyTest.setKeyType(PersonalKeyDAO.PKCS12_RSA);

			// Creates Root CA self signed certificate
			chain = new Certificate[1];
			chain[0] = _X509Utils.createV3Cert(rsaKeyPair.getPublicKey(),
					rsaKeyPair.getPrivateKey(), BigInteger.valueOf(1),
					notBefore, notAfter, subject0CertificateInformationMap,
					keyUsageList, certType,
					X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_SHA1withRSA);
			encodedKeyStr = new String(rsaKeyPair.encodePKCS12(password,
					password, chain));
			personalKeyTest.setKeyStr(encodedKeyStr);
			personalKeyTest.setKeyID(digestCryptoUtils.getDigest(encodedKeyStr,
					CryptoUtils.DIGEST_FUNCTION_SHA_1,
					CryptoUtils.ENCODER_BASE64));
			dummySubjectPersonalKeyList.add(personalKeyTest);
			dummySubjectList.get(0).setKeyList(dummySubjectPersonalKeyList);

			/******************* SUBJECT[1] ********************************/
			// Create an EC Key pair, and add the keys to a list, then add this
			// list to the subject[1]
			ecKeyPair = asymmetricCryptoUtils
					.generateKeys(ECDomainParameters.NIST_CURVE_P_192);
			dummySubjectPersonalKeyList = new LinkedList<PersonalKeyDAO>();
			// ADD EC Private key
			personalKeyTest = new PersonalKeyDAO();
			personalKeyTest.setKeyType(PersonalKeyDAO.PRIVATE_EC);
			encodedKeyStr = new String(ecKeyPair.getPrivateKey().encode(
					password));
			personalKeyTest.setKeyStr(encodedKeyStr);
			personalKeyTest.setKeyID(digestCryptoUtils.getDigest(encodedKeyStr,
					CryptoUtils.DIGEST_FUNCTION_SHA_1,
					CryptoUtils.ENCODER_BASE64));
			dummySubjectPersonalKeyList.add(personalKeyTest);

			// ADD EC Public key
			personalKeyTest = new PersonalKeyDAO();
			personalKeyTest.setKeyType(PersonalKeyDAO.PUBLIC_EC);
			encodedKeyStr = new String(ecKeyPair.getPublicKey().encode());
			personalKeyTest.setKeyStr(encodedKeyStr);
			personalKeyTest.setKeyID(digestCryptoUtils.getDigest(encodedKeyStr,
					CryptoUtils.DIGEST_FUNCTION_SHA_1,
					CryptoUtils.ENCODER_BASE64));
			dummySubjectPersonalKeyList.add(personalKeyTest);

			// ADD EC PKCS12
			personalKeyTest = new PersonalKeyDAO();
			personalKeyTest.setKeyType(PersonalKeyDAO.PKCS12_EC);

			// Creates Root CA self signed certificate
			chain = new Certificate[1];
			chain[0] = _X509Utils.createV3Cert(ecKeyPair.getPublicKey(),
					ecKeyPair.getPrivateKey(), BigInteger.valueOf(1),
					notBefore, notAfter, subject1CertificateInformationMap,
					keyUsageList, certType,
					X509UtilsDictionary.EC_X509_SIGN_ALGORITHM_SHA1withECDSA);
			encodedKeyStr = new String(ecKeyPair.encodePKCS12(password,
					password, chain));
			personalKeyTest.setKeyStr(encodedKeyStr);
			personalKeyTest.setKeyID(digestCryptoUtils.getDigest(encodedKeyStr,
					CryptoUtils.DIGEST_FUNCTION_SHA_1,
					CryptoUtils.ENCODER_BASE64));
			dummySubjectPersonalKeyList.add(personalKeyTest);
			dummySubjectList.get(1).setKeyList(dummySubjectPersonalKeyList);

			/******************* SUBJECT[2] ********************************/
			// Create an RSA Key pair, and add the keys to a list, then add this
			// list to the subject[2]
			rsaKeyPair = asymmetricCryptoUtils.generateKeys(1024);
			dummySubjectPersonalKeyList = new LinkedList<PersonalKeyDAO>();
			// ADD RSA Private key
			personalKeyTest = new PersonalKeyDAO();
			personalKeyTest.setKeyType(PersonalKeyDAO.PRIVATE_RSA);
			encodedKeyStr = new String(rsaKeyPair.getPrivateKey().encode(
					password));
			personalKeyTest.setKeyStr(encodedKeyStr);
			personalKeyTest.setKeyID(digestCryptoUtils.getDigest(encodedKeyStr,
					CryptoUtils.DIGEST_FUNCTION_SHA_1,
					CryptoUtils.ENCODER_BASE64));
			dummySubjectPersonalKeyList.add(personalKeyTest);

			// ADD RSA Public key
			personalKeyTest = new PersonalKeyDAO();
			personalKeyTest.setKeyType(PersonalKeyDAO.PUBLIC_RSA);
			encodedKeyStr = new String(rsaKeyPair.getPublicKey().encode());
			personalKeyTest.setKeyStr(encodedKeyStr);
			personalKeyTest.setKeyID(digestCryptoUtils.getDigest(encodedKeyStr,
					CryptoUtils.DIGEST_FUNCTION_SHA_1,
					CryptoUtils.ENCODER_BASE64));
			dummySubjectPersonalKeyList.add(personalKeyTest);
			dummySubjectList.get(2).setKeyList(dummySubjectPersonalKeyList);

			/******************* SUBJECT[3] ********************************/
			// Create an EC Key pair, and add the keys to a list, then add this
			// list to the subject[3]
			ecKeyPair = asymmetricCryptoUtils
					.generateKeys(ECDomainParameters.NIST_CURVE_P_192);
			dummySubjectPersonalKeyList = new LinkedList<PersonalKeyDAO>();
			// ADD EC Private key
			personalKeyTest = new PersonalKeyDAO();
			personalKeyTest.setKeyType(PersonalKeyDAO.PRIVATE_EC);
			encodedKeyStr = new String(ecKeyPair.getPrivateKey().encode(
					password));
			personalKeyTest.setKeyStr(encodedKeyStr);
			personalKeyTest.setKeyID(digestCryptoUtils.getDigest(encodedKeyStr,
					CryptoUtils.DIGEST_FUNCTION_SHA_1,
					CryptoUtils.ENCODER_BASE64));
			dummySubjectPersonalKeyList.add(personalKeyTest);

			// ADD EC Public key
			personalKeyTest = new PersonalKeyDAO();
			personalKeyTest.setKeyType(PersonalKeyDAO.PUBLIC_EC);
			encodedKeyStr = new String(ecKeyPair.getPublicKey().encode());
			personalKeyTest.setKeyStr(encodedKeyStr);
			personalKeyTest.setKeyID(digestCryptoUtils.getDigest(encodedKeyStr,
					CryptoUtils.DIGEST_FUNCTION_SHA_1,
					CryptoUtils.ENCODER_BASE64));
			dummySubjectPersonalKeyList.add(personalKeyTest);
			dummySubjectList.get(3).setKeyList(dummySubjectPersonalKeyList);

			/******************* SUBJECT[4] ********************************/
			// Create an EC Key pair, and add the keys to a list, then add this
			// list to the subject[4]
			ecKeyPair = asymmetricCryptoUtils
					.generateKeys(ECDomainParameters.NIST_CURVE_P_192);
			dummySubjectPersonalKeyList = new LinkedList<PersonalKeyDAO>();
			// ADD EC Public key
			personalKeyTest = new PersonalKeyDAO();
			personalKeyTest.setKeyType(PersonalKeyDAO.PUBLIC_EC);
			encodedKeyStr = new String(ecKeyPair.getPublicKey().encode());
			personalKeyTest.setKeyStr(encodedKeyStr);
			personalKeyTest.setKeyID(digestCryptoUtils.getDigest(encodedKeyStr,
					CryptoUtils.DIGEST_FUNCTION_SHA_1,
					CryptoUtils.ENCODER_BASE64));
			dummySubjectPersonalKeyList.add(personalKeyTest);
			dummySubjectList.get(4).setKeyList(dummySubjectPersonalKeyList);

		} catch (CryptoUtilsException e) {
			e.printStackTrace();
		} catch (CryptoUtilsX509ExtensionException e) {
			e.printStackTrace();
		}
	}

	private void performPersonalKeyInsert(PersonalKeyDAO personalKey,
			Integer ownerID, Boolean details) {
		try {
			Integer subID = personalKeyController.insert(personalKey, ownerID);
			PersonalKeyDAO resPersonalKey = personalKeyController
					.getById(subID);

			personalKey.setId(subID);
			String res = resPersonalKey.equals(personalKey) ? "OK" : "FAIL";
			log.info("[PERSONAL_KEY] INSERT= " + res);

			if (details) {
				log.info("[PERSONAL_KEY] PERSONAL_KEY ORG= " + personalKey);
				log.info("[PERSONAL_KEY] PERSONAL_KEY DB = " + resPersonalKey);
			}

		} catch (DBException e) {
			log.error("[PERSONAL_KEY] INSERT Error: " + e);
		}
	}

	private void performPersonalKeyUpdate(PersonalKeyDAO personalKey,
			Integer ownerID, Boolean details) {
		try {
			personalKeyController.update(personalKey, ownerID);
			PersonalKeyDAO resPersonalKey = personalKeyController
					.getById(personalKey.getId());

			String res = resPersonalKey.equals(personalKey) ? "OK" : "FAIL";
			log.info("[PERSONAL_KEY] UPDATE [" + personalKey.getId() + "]= "
					+ res);

			if (details) {
				log.info("[PERSONAL_KEY] PERSONAL_KEY= " + personalKey);
			}

		} catch (DBException e) {
			log.error("[PERSONAL_KEY] UPDATE Error: " + e);
		}

	}

	private void performPersonalKeyDelete(PersonalKeyDAO personalKeyDAO,
			Boolean details) {
		try {
			Integer countBefore = personalKeyController.getCount();
			personalKeyController.delete(personalKeyDAO);
			Integer countAfter = personalKeyController.getCount();

			String res = countBefore.equals(countAfter + 1) ? "OK" : "FAIL";
			log.info("[PERSONAL_KEY] DELETE [" + personalKeyDAO.getId() + "]= "
					+ res);

			if (details) {
				log.info("[PERSONAL_KEY] PERSONAL_KEY= " + personalKeyDAO);
			}

		} catch (DBException e) {
			log.error("[PERSONAL_KEY] DELETE Error: " + e);
		}
	}

	/**
	 * Perform the personalKey getAll search test, if the result list is not
	 * empty, the test is OK otherwise the test FAIL
	 * 
	 * @param details
	 */
	private List<PersonalKeyDAO> performPersonalKeyGetAll(Boolean details) {
		try {
			List<PersonalKeyDAO> resList = personalKeyController.getAll();
			if (details) {
				log.info("COUNT= " + resList.size());
				for (PersonalKeyDAO sub : resList) {
					log.info("[PERSONAL_KEY] = " + sub);
				}
			}
			String res = resList.size() != 0 ? "OK" : "FAIL";
			log.info("[PERSONAL_KEY] GET ALL = " + res);
			return resList;
		} catch (DBException e) {
			log.error("[PERSONAL_KEY] GET_ALLError: " + e);
		}
		return new LinkedList<PersonalKeyDAO>();
	}

	/**
	 * Perform the personalKey search by uniqueKey test, if the result list is
	 * not empty, the test is OK otherwise the test FAIL
	 * 
	 * @param name
	 *            Name to be searched
	 * @param details
	 */
	private void performPersonalKeyGetUniqueID(String uniqueKey, Boolean details) {
		try {
			PersonalKeyDAO resPersonalKey = personalKeyController
					.getByUniqueKey(uniqueKey);
			if (details) {
				log.info("PersonalKey= " + resPersonalKey);
			}
			String res = resPersonalKey.getId() != 0 ? "OK" : "FAIL";
			log.info("[PERSONAL_KEY] GET BY UNIQUE_KEY [" + uniqueKey + "]= "
					+ res);
		} catch (DBException e) {
			log.error("[PERSONAL_KEY] GET BY UNIQUE_KEY Error: " + e);
		}
	}

	/**
	 * Perform the personalKey search by subjectID test, if the result list is
	 * not empty, the test is OK otherwise the test FAIL
	 * 
	 * @param details
	 * @param subjectID
	 */
	private List<PersonalKeyDAO> performPersonalKeyGetBySubjectID(
			Integer subjectID, Boolean details) {
		try {
			List<PersonalKeyDAO> resList = personalKeyController
					.getBySubjectId(subjectID);
			if (details) {
				log.info("COUNT= " + resList.size());
				for (PersonalKeyDAO sub : resList) {
					log.info("[PERSONAL_KEY] = " + sub);
				}
			}
			String res = resList.size() != 0 ? "OK" : "FAIL";
			log.info("[PERSONAL_KEY] GET BY SubjectID [" + subjectID + "]= "
					+ res);
			return resList;
		} catch (DBException e) {
			log.error("[PERSONAL_KEY] GET BY SubjectID Error: " + e);
		}
		return new LinkedList<PersonalKeyDAO>();
	}

	/**
	 * Perform the personalKey search by type test, if the result list is not
	 * empty, the test is OK otherwise the test FAIL
	 * 
	 * @param details
	 * @param type
	 */
	private List<PersonalKeyDAO> performPersonalKeyGetByType(Integer type,
			Boolean details) {
		try {
			List<PersonalKeyDAO> resList = personalKeyController
					.getByType(type);
			if (details) {
				log.info("COUNT= " + resList.size());
				for (PersonalKeyDAO sub : resList) {
					log.info("[PERSONAL_KEY] = " + sub);
				}
			}
			String res = resList.size() != 0 ? "OK" : "FAIL";
			log.info("[PERSONAL_KEY] GET BY Type [" + type + "]= " + res);
			return resList;
		} catch (DBException e) {
			log.error("[PERSONAL_KEY] GET BY Type Error: " + e);
		}
		return new LinkedList<PersonalKeyDAO>();
	}

	/**
	 * Perform the personalKey search by ID test, if the result personalKey has
	 * its id!=0, the test is OK otherwise the test FAIL
	 * 
	 * @param personalKeyID
	 *            Id to be searched
	 * @param details
	 */
	private void performPersonalKeyGetByID(Integer personalKeyID,
			Boolean details) {
		try {
			PersonalKeyDAO resPersonalKey = personalKeyController
					.getById(personalKeyID);
			if (details) {
				log.info("PersonalKey= " + resPersonalKey);
			}

			String res = resPersonalKey.getId() != 0 ? "OK" : "FAIL";
			log.info("[PERSONAL_KEY] GET BY ID [" + personalKeyID + "]= " + res);
		} catch (DBException e) {
			log.error("[PERSONAL_KEY] GET BY ID Error: " + e);
		}
	}

	/**
	 * Test the search of personalKey using a filter map as parameter, if the
	 * result list is not empty, the test is OK otherwise the test FAIL
	 * 
	 * @param filterMap
	 *            It's a Map which has the following structure:
	 *            <ul>
	 *            <li>Key = Tag of the filter to be used, should be define in
	 *            {@link DataBaseDictionary}, this tags must be written as a SQL
	 *            WHERE clause using PreparedStament form for example: 'DBfield
	 *            = ?' or 'DBfield LIKE ?'
	 *            <li>Value = Must be a string array of 2 positions where:
	 *            <ul>
	 *            <li>[0] = Value to be searched in the data base
	 *            <li>[1] = Data type, according to this, the PreparedStatemen
	 *            will be constructed, the valid DataTypes are defined in the
	 *            {@link DataBaseDictionary} (e.g
	 *            DataBaseDictionary.FILTER_TYPE_TABLENAME_FIELDNAME)
	 *            </ul>
	 *            </ul>
	 * @param details
	 */
	private void performPersonalKeyGetByAdvanced(
			Map<String, String[]> filterMap, Boolean details) {
		try {

			List<PersonalKeyDAO> resList = personalKeyController
					.getByAdvancedFilter(filterMap);
			if (details) {
				log.info("COUNT= " + resList.size());
				for (PersonalKeyDAO sub : resList) {
					log.info("[PERSONAL_KEY] GET BY ADVANCED FILTER = " + sub);
				}
			}
			String res = resList.size() != 0 ? "OK" : "FAIL";
			log.info("[PERSONAL_KEY] GET BY ADVANCED FILTER = " + res);
		} catch (DBException e) {
			log.error("[PERSONAL_KEY] GET BY ADVANCED FILTER Error: " + e);
		}
	}
	
	/**
	 * Perform the test for get the current id, if the result is not 0, the test
	 * is OK otherwise the test FAIL
	 * 
	 * @param details
	 */
	private void performPersonalKeyGetCurrentId(Boolean details) {
		Integer currentID = personalKeyController.getCurrentId();
		if (details) {
			log.info("[PERSONAL_KEY] CURRENT ID= " + currentID);
		}

		String res = !currentID.equals(0) ? "OK" : "FAIL";
		log.info("[PERSONAL_KEY] CURRENT ID = " + res);
	}
}
