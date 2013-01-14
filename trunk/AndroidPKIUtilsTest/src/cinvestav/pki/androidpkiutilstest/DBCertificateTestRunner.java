/**
 *  Created on  : 13/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	
 */
package cinvestav.pki.androidpkiutilstest;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.spongycastle.util.encoders.Base64;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase.CursorFactory;
import cinvestav.android.pki.cryptography.cert.CertificateInformationKeys;
import cinvestav.android.pki.cryptography.ec.ECDomainParameters;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsX509ExtensionException;
import cinvestav.android.pki.cryptography.key.ECKeyPair;
import cinvestav.android.pki.cryptography.key.RSAKeyPair;
import cinvestav.android.pki.cryptography.utils.AsymmetricCryptoUtils;
import cinvestav.android.pki.cryptography.utils.X509Utils;
import cinvestav.android.pki.cryptography.utils.X509UtilsDictionary;
import cinvestav.android.pki.db.controller.CertificateController;
import cinvestav.android.pki.db.controller.SubjectController;
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.android.pki.db.dao.SubjectDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.android.pki.utils.DataBaseDictionary;
import cinvestav.android.pki.utils.LogUtil;

/**
 * 
 * This class contains all the test corresponding to Certificate DB
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 13/08/2012
 * @version 1.0
 */
public class DBCertificateTestRunner {
	protected static LogUtil log = new LogUtil("ANDROID_PKI_UTILS");
	private CertificateController certificateController;
	private SubjectController subjectController;
	private AsymmetricCryptoUtils asymmetricCryptoUtils;
	private X509Utils _X509Utils;
	private Double[][] positions = { { 17.0883, -96.7126 },
			{ 19.4239, -99.1669 }, { 19.4225, -99.1407 },
			{ 19.4191, -99.1302 }, { 19.4744, -98.9147 },
			{ 19.6528, -99.2613 }, { 21.484, -102.173 },
			{ 21.4981, -102.1840 }, { 21.2839, -89.6601 },
			{ 39.0869, -94.584 }, { -37.8141, 144.972 }, { 35.6754, 139.7607 },
			{ 42.5698, 12.6542 }, { 53.4081, -2.9770 } };

	private String[] documents = { "IFE", "Cartilla", "Pasaporte", "Visa",
			"Cedula", "Drivers license", "Acta de Nacimiento",
			"Credecial empresarial", "Personal" };

	/**
	 * 
	 * @param context
	 * @param name
	 * @param factory
	 * @param version
	 * @throws CryptoUtilsException
	 */
	public DBCertificateTestRunner(Context context, String name,
			CursorFactory factory, int version) throws CryptoUtilsException {
		this.certificateController = new CertificateController(context, name,
				factory, version);
		this.subjectController = new SubjectController(context, name, factory,
				version);
		asymmetricCryptoUtils = new AsymmetricCryptoUtils();

		try {
			_X509Utils = new X509Utils();
		} catch (CryptoUtilsException e) {
			// TODO Auto-generated catch block
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
	public DBCertificateTestRunner(Context context) throws CryptoUtilsException {
		this.certificateController = new CertificateController(context);
		this.subjectController = new SubjectController(context);
		asymmetricCryptoUtils = new AsymmetricCryptoUtils();
		try {
			_X509Utils = new X509Utils();
		} catch (CryptoUtilsException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			log.error("testX509CertificateV3 = " + e.getMessage(), e.getCause());
		}
	}

	public void testCertificateDB(Integer testNumber, Boolean details)
			throws DBException {
		log.info(" ********* Certificate DB-Controller Test Begin *********");
		List<SubjectDAO> allSubjectList = subjectController.getAll();
		Random rand = new Random(System.currentTimeMillis());

		List<SubjectDAO> dummySubjectList = new LinkedList<SubjectDAO>();
		// Select 5 subject randomly
		for (int i = 0; i < 10; i++) {
			Integer subId = rand.nextInt(allSubjectList.size());
			dummySubjectList.add(allSubjectList.get(subId));
		}

		/*
		log.info(" ********* GET ALL *********");
		Integer certTotal = certificateController.getCount();

		List<CertificateDAO> dummyCertificateList = createDummyCertificateList(
				dummySubjectList, certTotal + 1);
		log.info(" ********* INSERT *********");
		for (CertificateDAO certificate : dummyCertificateList) {
			performCertificateInsert(certificate, details);
		}

		log.info(" ********* GET CURRENT ID *********");
		for (int i = 0; i <= testNumber; i++) {
			performCertificateGetCurrentId(details);
		}*/

		log.info(" ********* GET ALL *********");
		List<CertificateDAO> dbList = performCertificateGetAll(details);
		for (CertificateDAO certificate : dbList) {
			performCertificateGetDetails(certificate, details);
		}
		
		performUpdateSubjectKeyIdInDataBase(dbList);

		Integer id;
		log.info(" ********* GET BY Id *********");
		for (int i = 0; i <= testNumber; i++) {
			do {
				id = rand.nextInt(dbList.size());
			} while (id == 0);
			performCertificateGetById(dbList.get(id).getId(), details);
		}

		log.info(" ********* GET BY CA Certificate Id *********");
		for (int i = 0; i <= testNumber; i++) {
			do {
				id = rand.nextInt(dbList.size());
			} while (id == 0);
			performCertificateGetByCACertificateId(dbList.get(id)
					.getCaCertificate().getId(), details);
		}

		log.info(" ********* GET BY CA Certificate SerialNumber*********");
		for (int i = 0; i <= testNumber; i++) {
			do {
				id = rand.nextInt(dbList.size());
			} while (id == 0);
			performCertificateGetByCACertificateSerialNumber(dbList.get(id)
					.getCaCertificate().getSerialNumber(), details);
		}

		log.info(" ********* GET BY CA Subject Id *********");
		for (int i = 0; i <= testNumber; i++) {
			do {
				id = rand.nextInt(dbList.size());
			} while (id == 0);
			performCertificateGetByCASubjectId(dbList.get(id)
					.getCaCertificate().getOwner().getId(), details);
		}

		log.info(" ********* GET BY Owner Id*********");
		for (int i = 0; i <= testNumber; i++) {
			do {
				id = rand.nextInt(dbList.size());
			} while (id == 0);
			performCertificateGetByOwnerId(dbList.get(id).getOwner().getId(),
					details);
		}

		log.info(" ********* GET BY Serial Number*********");
		for (int i = 0; i <= testNumber; i++) {
			do {
				id = rand.nextInt(dbList.size());
			} while (id == 0);
			performCertificateGetBySerialNumber(dbList.get(id)
					.getSerialNumber(), details);
		}

		log.info(" ********* GET BY Status*********");
		for (int i = 0; i <= testNumber; i++) {
			do {
				id = rand.nextInt(dbList.size());
			} while (id == 0);
			performCertificateGetByStatus(dbList.get(id).getStatus(), details);
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
			value[0] = dbList.get(id).getId() + "";
			// Filter type
			value[1] = DataBaseDictionary.FILTER_TYPE_CERTIFICATE_ID;
			filterMap.put(DataBaseDictionary.FILTER_CERTIFICATE_ID, value);

			value = new String[3];
			/*
			 * Establish filter properties
			 */
			// Filter value
			value[0] = dbList.get(id).getSerialNumber() + "";
			// Filter type
			value[1] = DataBaseDictionary.FILTER_TYPE_CERTIFICATE_SERIAL_NUMBER;
			filterMap.put(DataBaseDictionary.FILTER_CERTIFICATE_SERIAL_NUMBER,
					value);

			value = new String[3];
			/*
			 * Establish filter properties
			 */
			// Filter value
			value[0] = dbList.get(id).getStatus() + "";
			// Filter type
			value[1] = DataBaseDictionary.FILTER_TYPE_CERTIFICATE_STATUS;
			filterMap.put(DataBaseDictionary.FILTER_CERTIFICATE_STATUS, value);

			performCertificateGetByAdvanced(filterMap, details);
		}
/*
		log.info(" ********* UPDATE *********");
		for (int i = 0; i <= testNumber; i++) {
			do {
				id = rand.nextInt(dbList.size());
			} while (id == 0);
			CertificateDAO certificate = dbList.get(id);
			certificate
					.setStatus(X509UtilsDictionary.X509_CERTIFICATE_STATUS_INVALID);
			performCertificateUpdate(certificate, details);
		}*/
	}

	/**
	 * Fill a list of certificate information maps with dummy information for
	 * testing proposes
	 * 
	 * @param subjectCertificateInformationMapList
	 */
	private void fillCertificateHashMaps(
			List<HashMap<String, String>> subjectCertificateInformationMapList,
			List<SubjectDAO> dummySubjectList) {

		Integer cont = 0;
		for (HashMap<String, String> subjectCertificateInformationMap : subjectCertificateInformationMapList) {
			SubjectDAO subject = dummySubjectList.get(cont);
			subjectCertificateInformationMap
					.put(CertificateInformationKeys.FRIENDLY_NAME,
							subject.getName());
			subjectCertificateInformationMap.put(
					CertificateInformationKeys.COUNTRY, "MX");
			subjectCertificateInformationMap.put(
					CertificateInformationKeys.EmailAddress, "em."
							+ subject.getName().trim().toLowerCase()
							+ "@gmail.com");
			subjectCertificateInformationMap.put(
					CertificateInformationKeys.FULL_COMMON_NAME,
					subject.getName());
			subjectCertificateInformationMap.put(
					CertificateInformationKeys.LOCALITY, "TENAYO");
			subjectCertificateInformationMap.put(
					CertificateInformationKeys.STATE, "TLALNEPANTLA");
			subjectCertificateInformationMap.put(
					CertificateInformationKeys.ORGANIZATION, "Cinvestav");
			subjectCertificateInformationMap.put(
					CertificateInformationKeys.DEVICE_ID,
					SCCipherTestActivity.ANDROID_ID);
			subjectCertificateInformationMap.put(
					CertificateInformationKeys.SIGN_DEVICE_ID,
					SCCipherTestActivity.ANDROID_ID);
			Random rand = new Random(System.currentTimeMillis());
			int position = rand.nextInt(positions.length);

			subjectCertificateInformationMap.put(
					CertificateInformationKeys.CREATION_POSITION_LATITUDE,
					positions[position][0] + "");
			subjectCertificateInformationMap.put(
					CertificateInformationKeys.CREATION_POSITION_LONGITUDE,
					positions[position][1] + "");
			subjectCertificateInformationMap.put(
					CertificateInformationKeys.USER_ID, subject.getId() + "");
			subjectCertificateInformationMap.put(
					CertificateInformationKeys.USER_PERMISSION_ID, "23");
			int document = rand.nextInt(documents.length);
			subjectCertificateInformationMap.put(
					CertificateInformationKeys.IDENTIFICATION_DOCUMENT,
					documents[document]);
			cont++;
		}
	}

	/**
	 * Create a list of dummy certificates for testing proposes
	 * 
	 * @param dummySubjectList
	 *            List of subject, which represents the owners of the
	 *            certificates
	 * @throws DBException
	 */
	private List<CertificateDAO> createDummyCertificateList(
			List<SubjectDAO> dummySubjectList, Integer serialNumber)
			throws DBException {

		// Create a list of dummy certificate information list and initialize it
		// with empty hash maps
		List<HashMap<String, String>> subjectCertificateInformationMapList = new LinkedList<HashMap<String, String>>();
		for (int i = 0; i < dummySubjectList.size(); i++) {
			subjectCertificateInformationMapList
					.add(new HashMap<String, String>());
		}

		// Fill the list of dummy certificates with dummy information
		fillCertificateHashMaps(subjectCertificateInformationMapList,
				dummySubjectList);

		// Test valid dates
		Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60
				* 24 * 30);
		Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60 * 60
				* 24 * 30);

		X509Certificate cert;

		// In this map will be saved a set of certificate types and the
		// corresponding key usages to be used
		// int the certificate creation process
		Map<String, List<Integer>> keyUsageMap = new HashMap<String, List<Integer>>();
		List<Integer> keyUsageList;
		String certType;
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		keyUsageMap.put(certType, keyUsageList);

		certType = X509UtilsDictionary.CERTIFICATE_TYPE_INTERMEDIATE_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		keyUsageMap.put(certType, keyUsageList);

		// Create CA1 certificate signed by Root CA
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_FINAL_CA;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		keyUsageMap.put(certType, keyUsageList);

		// Create subject certificate signed by CA2
		certType = X509UtilsDictionary.CERTIFICATE_TYPE_END_OWNER;
		keyUsageList = new LinkedList<Integer>();
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE);
		keyUsageList.add(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT);
		keyUsageMap.put(certType, keyUsageList);

		// Resulting certificate DAO dummy list
		List<CertificateDAO> dummyCertificateList = new LinkedList<CertificateDAO>();

		// Generates test keys
		ECKeyPair ecKeyPair;
		ECKeyPair ecKeyPairCA;
		RSAKeyPair rsaKeyPair;

		CertificateDAO certificateTest;

		try {
			Random rand = new Random(System.currentTimeMillis());

			// Create an CA EC Key pair
			ecKeyPairCA = asymmetricCryptoUtils
					.generateKeys(ECDomainParameters.NIST_CURVE_P_192);

			// add CA certificate DAO
			Integer ownerId = rand.nextInt(dummySubjectList.size());
			certificateTest = new CertificateDAO();
			certificateTest.setId(serialNumber);
			certificateTest.setOwner(dummySubjectList.get(ownerId));
			certificateTest.setSerialNumber(serialNumber);
			certificateTest
					.setStatus(X509UtilsDictionary.X509_CERTIFICATE_STATUS_VALID);
			certificateTest.setCaCertificate(certificateTest);

			Certificate certCA = _X509Utils.createV3Cert(ecKeyPairCA
					.getPublicKey(), ecKeyPairCA.getPrivateKey(), BigInteger
					.valueOf(serialNumber), notBefore, notAfter,
					subjectCertificateInformationMapList.get(ownerId),
					keyUsageMap
							.get(X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA),
					X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA);
			certificateTest.setCertificateStr(new String(Base64.encode(certCA
					.getEncoded())));
			// The first certificate of the list will be the CA
			dummyCertificateList.add(certificateTest);
			serialNumber++;

			// Create an EC Key pair
			ecKeyPair = asymmetricCryptoUtils
					.generateKeys(ECDomainParameters.NIST_CURVE_P_192);
			ownerId = rand.nextInt(dummySubjectList.size());
			// add certificate DAO
			certificateTest = new CertificateDAO();
			certificateTest.setOwner(dummySubjectList.get(ownerId));
			certificateTest.setSerialNumber(serialNumber);
			certificateTest
					.setStatus(X509UtilsDictionary.X509_CERTIFICATE_STATUS_VALID);
			certificateTest.setCaCertificate(dummyCertificateList.get(0));

			cert = _X509Utils
					.createV3Cert(
							ecKeyPair.getPublicKey(),
							ecKeyPairCA.getPrivateKey(),
							BigInteger.valueOf(serialNumber),
							notBefore,
							notAfter,
							(X509Certificate) certCA,
							subjectCertificateInformationMapList.get(ownerId),
							keyUsageMap
									.get(X509UtilsDictionary.CERTIFICATE_TYPE_INTERMEDIATE_CA),
							X509UtilsDictionary.CERTIFICATE_TYPE_INTERMEDIATE_CA);
			certificateTest.setCertificateStr(new String(Base64.encode(cert
					.getEncoded())));
			dummyCertificateList.add(certificateTest);
			serialNumber++;

			// Create an RSA Key pair
			rsaKeyPair = asymmetricCryptoUtils.generateKeys(1024);
			ownerId = rand.nextInt(dummySubjectList.size());
			// add certificate DAO
			certificateTest = new CertificateDAO();
			certificateTest.setOwner(dummySubjectList.get(ownerId));
			certificateTest.setSerialNumber(serialNumber);
			certificateTest
					.setStatus(X509UtilsDictionary.X509_CERTIFICATE_STATUS_VALID);
			certificateTest.setCaCertificate(dummyCertificateList.get(0));

			cert = _X509Utils
					.createV3Cert(
							rsaKeyPair.getPublicKey(),
							ecKeyPairCA.getPrivateKey(),
							BigInteger.valueOf(serialNumber),
							notBefore,
							notAfter,
							(X509Certificate) certCA,
							subjectCertificateInformationMapList.get(ownerId),
							keyUsageMap
									.get(X509UtilsDictionary.CERTIFICATE_TYPE_FINAL_CA),
							X509UtilsDictionary.CERTIFICATE_TYPE_FINAL_CA);
			certificateTest.setCertificateStr(new String(_X509Utils
					.encode(cert)));
			dummyCertificateList.add(certificateTest);
			serialNumber++;

			// Create an RSA Key pair
			rsaKeyPair = asymmetricCryptoUtils.generateKeys(1024);
			ownerId = rand.nextInt(dummySubjectList.size());
			// add certificate DAO
			certificateTest = new CertificateDAO();
			certificateTest.setOwner(dummySubjectList.get(ownerId));
			certificateTest.setSerialNumber(serialNumber);
			certificateTest
					.setStatus(X509UtilsDictionary.X509_CERTIFICATE_STATUS_VALID);
			certificateTest.setCaCertificate(dummyCertificateList.get(0));

			cert = _X509Utils
					.createV3Cert(
							rsaKeyPair.getPublicKey(),
							ecKeyPairCA.getPrivateKey(),
							BigInteger.valueOf(serialNumber),
							notBefore,
							notAfter,
							(X509Certificate) certCA,
							subjectCertificateInformationMapList.get(ownerId),
							keyUsageMap
									.get(X509UtilsDictionary.CERTIFICATE_TYPE_END_OWNER),
							X509UtilsDictionary.CERTIFICATE_TYPE_END_OWNER);
			certificateTest.setCertificateStr(new String(Base64.encode(cert
					.getEncoded())));
			dummyCertificateList.add(certificateTest);
			serialNumber++;

			return dummyCertificateList;

		} catch (CryptoUtilsException e) {
			e.printStackTrace();
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		} catch (CryptoUtilsX509ExtensionException e) {
			e.printStackTrace();
		}
		return new LinkedList<CertificateDAO>();
	}

	private void performCertificateInsert(CertificateDAO certificate,
			Boolean details) {
		try {
			Integer subId = certificateController.insert(certificate);
			CertificateDAO resCertificate = certificateController
					.getById(subId);

			certificate.setId(subId);
			certificate.setLastStatusUpdateDate(resCertificate
					.getLastStatusUpdateDate());
			String res = resCertificate.equals(certificate) ? "OK" : "FAIL";
			log.info("[CERTIFICATE] INSERT= " + res);

			if (details) {
				log.info("[CERTIFICATE] CERTIFICATE ORG= " + certificate);
				log.info("[CERTIFICATE] CERTIFICATE DB = " + resCertificate);
			}

		} catch (DBException e) {
			log.error("[CERTIFICATE] INSERT Error: " + e);
		}
	}

	private void performCertificateGetDetails(CertificateDAO certificate,
			Boolean details) {
		if (details) {
			log.info("[CERTIFICATE] CERTIFICATE ORG= " + certificate);
		}

		certificateController.getCertificateDetails(certificate);
		String res = !certificate.getOwner().getId().equals(0)
				&& !certificate.getCaCertificate().getId().equals(0) ? "OK"
				: "FAIL";
		log.info("[CERTIFICATE] GET DETAILS= " + res);

		if (details) {
			log.info("[CERTIFICATE] CERTIFICATE DETAIL = " + certificate);
		}
	}

	private void performCertificateUpdate(CertificateDAO certificate,
			Boolean details) {
		try {
			certificateController.update(certificate);
			CertificateDAO resCertificate = certificateController
					.getById(certificate.getId());

			String res = resCertificate.equals(certificate) ? "OK" : "FAIL";
			log.info("[CERTIFICATE] UPDATE [" + certificate.getId() + "]= "
					+ res);

			if (details) {
				log.info("[CERTIFICATE] CERTIFICATE= " + certificate);
			}

		} catch (DBException e) {
			log.error("[CERTIFICATE] UPDATE Error: " + e);
		}

	}

	/**
	 * Perform the certificate getAll search test, if the result list is not
	 * empty, the test is OK otherwise the test FAIL
	 * 
	 * @param details
	 */
	private List<CertificateDAO> performCertificateGetAll(Boolean details) {
		try {
			List<CertificateDAO> resList = certificateController.getAll();
			if (details) {
				log.info("COUNT= " + resList.size());
				for (CertificateDAO sub : resList) {
					log.info("[CERTIFICATE] = " + sub);
				}
			}
			String res = resList.size() != 0 ? "OK" : "FAIL";
			log.info("[CERTIFICATE] GET ALL = " + res);
			return resList;
		} catch (DBException e) {
			log.error("[CERTIFICATE] GET_ALLError: " + e);
		}
		return new LinkedList<CertificateDAO>();
	}

	/**
	 * Perform the certificate search by serial number test, if the result list
	 * is not empty, the test is OK otherwise the test FAIL
	 * 
	 * @param serialNumber
	 *            serial number to be searched
	 * @param details
	 */
	private void performCertificateGetBySerialNumber(Integer serialNumber,
			Boolean details) {
		try {
			CertificateDAO resCertificate = certificateController
					.getBySerialNumber(serialNumber);
			if (details) {
				log.info("Certificate= " + resCertificate);
			}
			String res = resCertificate.getId() != 0 ? "OK" : "FAIL";
			log.info("[CERTIFICATE] GET BY SERIAL NUMBER [" + serialNumber
					+ "]= " + res);
		} catch (DBException e) {
			log.error("[CERTIFICATE] GET BY SERIAL NUMBER Error: " + e);
		}
	}

	/**
	 * Perform the certificate search by ownerId test, if the result list is not
	 * empty, the test is OK otherwise the test FAIL
	 * 
	 * @param details
	 * @param ownerId
	 */
	private List<CertificateDAO> performCertificateGetByOwnerId(
			Integer ownerId, Boolean details) {
		try {
			List<CertificateDAO> resList = certificateController
					.getByOwnerId(ownerId);
			if (details) {
				log.info("COUNT= " + resList.size());
				for (CertificateDAO sub : resList) {
					log.info("[CERTIFICATE] = " + sub);
				}
			}
			String res = resList.size() != 0 ? "OK" : "FAIL";
			log.info("[CERTIFICATE] GET BY OwnerId [" + ownerId + "]= " + res);
			return resList;
		} catch (DBException e) {
			log.error("[CERTIFICATE] GET BY OwnerId Error: " + e);
		}
		return new LinkedList<CertificateDAO>();
	}

	/**
	 * Perform the certificate search by caSubjectId test, if the result list is
	 * not empty, the test is OK otherwise the test FAIL
	 * 
	 * @param details
	 * @param caSubjectId
	 */
	private List<CertificateDAO> performCertificateGetByCASubjectId(
			Integer caSubjectId, Boolean details) {
		try {
			List<CertificateDAO> resList = certificateController
					.getByCASubjectId(caSubjectId);
			if (details) {
				log.info("COUNT= " + resList.size());
				for (CertificateDAO sub : resList) {
					log.info("[CERTIFICATE] = " + sub);
				}
			}
			String res = resList.size() != 0 ? "OK" : "FAIL";
			log.info("[CERTIFICATE] GET BY CA SUBJECT Id [" + caSubjectId
					+ "]= " + res);
			return resList;
		} catch (DBException e) {
			log.error("[CERTIFICATE] GET BY CA SUBJECT Id Error: " + e);
		}
		return new LinkedList<CertificateDAO>();
	}

	/**
	 * Perform the certificate search by caCertificateId test, if the result
	 * list is not empty, the test is OK otherwise the test FAIL
	 * 
	 * @param details
	 * @param caCertificateId
	 */
	private List<CertificateDAO> performCertificateGetByCACertificateId(
			Integer caCertificateId, Boolean details) {
		try {
			List<CertificateDAO> resList = certificateController
					.getByCACertificateId(caCertificateId);
			if (details) {
				log.info("COUNT= " + resList.size());
				for (CertificateDAO sub : resList) {
					log.info("[CERTIFICATE] = " + sub);
				}
			}
			String res = resList.size() != 0 ? "OK" : "FAIL";
			log.info("[CERTIFICATE] GET BY CA CERTIFICATE Id ["
					+ caCertificateId + "]= " + res);
			return resList;
		} catch (DBException e) {
			log.error("[CERTIFICATE] GET BY CA CERTIFICATE Id Error: " + e);
		}
		return new LinkedList<CertificateDAO>();
	}

	/**
	 * Perform the certificate search by caCertificateSerialNumber test, if the
	 * result list is not empty, the test is OK otherwise the test FAIL
	 * 
	 * @param details
	 * @param caCertificateSerialNumber
	 */
	private List<CertificateDAO> performCertificateGetByCACertificateSerialNumber(
			Integer caCertificateSerialNumber, Boolean details) {
		try {
			List<CertificateDAO> resList = certificateController
					.getByCACertificateSerialNumber(caCertificateSerialNumber);
			if (details) {
				log.info("COUNT= " + resList.size());
				for (CertificateDAO sub : resList) {
					log.info("[CERTIFICATE] = " + sub);
				}
			}
			String res = resList.size() != 0 ? "OK" : "FAIL";
			log.info("[CERTIFICATE] GET BY CA CERTIFICATE SERIAL NUMBER ["
					+ caCertificateSerialNumber + "]= " + res);
			return resList;
		} catch (DBException e) {
			log.error("[CERTIFICATE] GET BY CA CERTIFICATE SERIAL NUMBER Error: "
					+ e);
		}
		return new LinkedList<CertificateDAO>();
	}

	/**
	 * Perform the certificate search by Id test, if the result certificate has
	 * its id!=0, the test is OK otherwise the test FAIL
	 * 
	 * @param certificateId
	 *            Id to be searched
	 * @param details
	 */
	private void performCertificateGetById(Integer certificateId,
			Boolean details) {
		try {
			CertificateDAO resCertificate = certificateController
					.getById(certificateId);
			if (details) {
				log.info("Certificate= " + resCertificate);
			}

			String res = resCertificate.getId() != 0 ? "OK" : "FAIL";
			log.info("[CERTIFICATE] GET BY Id [" + certificateId + "]= " + res);
		} catch (DBException e) {
			log.error("[CERTIFICATE] GET BY Id Error: " + e);
		}
	}

	/**
	 * Perform the test for get the current id, if the result is not 0, the test
	 * is OK otherwise the test FAIL
	 * 
	 * @param details
	 */
	private void performCertificateGetCurrentId(Boolean details) {
		Integer currentID = certificateController.getCurrentId();
		if (details) {
			log.info("[CERTIFICATE] CURRENT ID= " + currentID);
		}

		String res = !currentID.equals(0) ? "OK" : "FAIL";
		log.info("[CERTIFICATE] CURRENT ID = " + res);
	}

	/**
	 * Perform the certificate search by status test, if the result list is not
	 * empty, the test is OK otherwise the test FAIL
	 * 
	 * @param details
	 * @param status
	 */
	private List<CertificateDAO> performCertificateGetByStatus(Integer status,
			Boolean details) {
		try {
			List<CertificateDAO> resList = certificateController
					.getByStatus(status);
			if (details) {
				log.info("COUNT= " + resList.size());
				for (CertificateDAO sub : resList) {
					log.info("[CERTIFICATE] = " + sub);
				}
			}
			String res = resList.size() != 0 ? "OK" : "FAIL";
			log.info("[CERTIFICATE] GET BY STATUS [" + status + "]= " + res);
			return resList;
		} catch (DBException e) {
			log.error("[CERTIFICATE] GET BY STATUS Error: " + e);
		}
		return new LinkedList<CertificateDAO>();
	}

	/**
	 * Test the search of certificate using a filter map as parameter, if the
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
	private void performCertificateGetByAdvanced(
			Map<String, String[]> filterMap, Boolean details) {
		try {

			List<CertificateDAO> resList = certificateController
					.getByAdvancedFilter(filterMap);
			if (details) {
				log.info("COUNT= " + resList.size());
				for (CertificateDAO sub : resList) {
					log.info("[CERTIFICATE] GET BY ADVANCED FILTER = " + sub);
				}
			}
			String res = resList.size() != 0 ? "OK" : "FAIL";
			log.info("[CERTIFICATE] GET BY ADVANCED FILTER = " + res);
		} catch (DBException e) {
			log.error("[CERTIFICATE] GET BY ADVANCED FILTER Error: " + e);
		}
	}

	private void performUpdateSubjectKeyIdInDataBase(
			List<CertificateDAO> certificates) throws DBException {
		try {
			for (CertificateDAO certificate : certificates) {

				X509Certificate x509Certificate = _X509Utils.decode(certificate
						.getCertificateStr().getBytes());
				
				byte[] subKeyId = _X509Utils.getSubjectKeyIdentifier(x509Certificate);
				
				certificate.setSubjectKeyId(new String(Base64.encode(subKeyId)));
				
				certificateController.update(certificate);

			}
		} catch (CryptoUtilsException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
