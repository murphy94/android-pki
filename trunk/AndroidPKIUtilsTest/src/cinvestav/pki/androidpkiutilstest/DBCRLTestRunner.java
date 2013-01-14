/**
 *  Created on  : 15/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	
 */
package cinvestav.pki.androidpkiutilstest;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
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
import cinvestav.android.pki.db.controller.CRLController;
import cinvestav.android.pki.db.controller.CertificateController;
import cinvestav.android.pki.db.controller.SubjectController;
import cinvestav.android.pki.db.dao.CRLDAO;
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.android.pki.db.dao.SubjectDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.android.pki.utils.DataBaseDictionary;
import cinvestav.android.pki.utils.LogUtil;

/**
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 15/08/2012
 * @version 1.0
 */
public class DBCRLTestRunner {
	protected static LogUtil log = new LogUtil("ANDROID_PKI_UTILS");
	private CRLController crlController;
	private CertificateController certificateController;
	private AsymmetricCryptoUtils asymmetricCryptoUtils;
	private X509Utils _X509Utils;
	private SubjectController subjectController;

	/**
	 * 
	 * @param context
	 * @param name
	 * @param factory
	 * @param version
	 * @throws CryptoUtilsException
	 */
	public DBCRLTestRunner(Context context, String name, CursorFactory factory,
			int version) throws CryptoUtilsException {
		this.crlController = new CRLController(context, name, factory, version);
		this.certificateController = new CertificateController(context, name,
				factory, version);
		asymmetricCryptoUtils = new AsymmetricCryptoUtils();
		this.subjectController = new SubjectController(context, name, factory,
				version);

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
	public DBCRLTestRunner(Context context) throws CryptoUtilsException {
		this.crlController = new CRLController(context);
		this.certificateController = new CertificateController(context);
		asymmetricCryptoUtils = new AsymmetricCryptoUtils();
		this.subjectController = new SubjectController(context);
		try {
			_X509Utils = new X509Utils();
		} catch (CryptoUtilsException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			log.error("testX509CertificateV3 = " + e.getMessage(), e.getCause());
		}
	}

	public void testCRLDB(Integer testNumber, Boolean details)
			throws DBException {
		log.info(" ********* CRL DB-Controller Test Begin *********");
		List<SubjectDAO> allSubjectList = subjectController.getAll();
		Random rand = new Random(System.currentTimeMillis());

		// Select a subject randomly
		Integer subID = 0;
		do {
			subID = rand.nextInt(allSubjectList.size());
		} while (subID == 0);

		List<CertificateDAO> allCertificatesList = certificateController
				.getAll();
		for (CertificateDAO certificate : allCertificatesList) {
			certificateController.getCertificateDetails(certificate);
		}

		Integer id;

		List<CertificateDAO> revokedCertificateList = new LinkedList<CertificateDAO>();
		// Select 3 subject randomly
		for (int i = 0; i < 3; i++) {
			Integer cerID = rand.nextInt(allCertificatesList.size());
			revokedCertificateList.add(allCertificatesList.get(cerID));
		}

		log.info(" ********* GET Count *********");
		Integer crlCount = crlController.getCount();
		Integer cerCount = certificateController.getCount();
		crlCount++;
		cerCount++;
		List<CRLDAO> dummyCRLList = createDummyCRLList(revokedCertificateList,
				allSubjectList.get(subID), crlCount, cerCount);
		log.info(" ********* INSERT *********");
		for (CRLDAO crl : dummyCRLList) {
			performCRLInsert(crl, details);
		}

		log.info(" ********* GET CURRENT ID *********");
		for (int i = 0; i <= testNumber; i++) {
			performCRLGetCurrentId(details);
		}

		log.info(" ********* GET ALL *********");
		List<CRLDAO> dbList = performCRLGetAll(details);

		log.info(" ********* GET BY ID *********");
		for (int i = 0; i <= testNumber; i++) {
			do {
				id = rand.nextInt(dbList.size());
			} while (id == 0);
			performCRLGetByID(dbList.get(id).getId(), details);
		}

		log.info(" ********* GET BY SERIAL NUMBER *********");
		for (int i = 0; i <= testNumber; i++) {
			do {
				id = rand.nextInt(dbList.size());
			} while (id == 0);
			performCRLGetSerialNumber(dbList.get(id).getSerialNumber(), details);
		}

		log.info(" ********* GET BY ISSUER CERTIFICATE ID *********");
		for (int i = 0; i <= testNumber; i++) {
			do {
				id = rand.nextInt(dbList.size());
			} while (id == 0);
			performCRLGetByIssuerCertificateId(dbList.get(id)
					.getIssuerCertificate().getId(), details);
		}

		log.info(" ********* GET BY ISSUER CERTIFICATE SERIAL NUMBER *********");
		for (int i = 0; i <= testNumber; i++) {
			do {
				id = rand.nextInt(dbList.size());
			} while (id == 0);
			performCRLGetByIssuerCertificateSerialNumber(dbList.get(id)
					.getIssuerCertificate().getSerialNumber(), details);
		}

		log.info(" ********* GET BY ISSUER SUBJECT ID *********");
		for (int i = 0; i <= testNumber; i++) {
			do {
				id = rand.nextInt(dbList.size());
			} while (id == 0);
			certificateController.getCertificateDetails(dbList.get(id)
					.getIssuerCertificate());
			performCRLGetByIssuerSubjecID(dbList.get(id).getIssuerCertificate()
					.getOwner().getId(), details);
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
			value[1] = DataBaseDictionary.FILTER_TYPE_CRL_ID;
			filterMap.put(DataBaseDictionary.FILTER_CRL_ID, value);

			value = new String[3];
			/*
			 * Establish filter properties
			 */
			// Filter value
			value[0] = dbList.get(id).getSerialNumber() + "";
			// Filter type
			value[1] = DataBaseDictionary.FILTER_TYPE_CRL_SERIAL_NUMBER;
			filterMap.put(DataBaseDictionary.FILTER_CRL_SERIAL_NUMBER, value);

			performCRLGetByAdvanced(filterMap, details);
		}

		log.info(" ********* DELETE *********");
		// for (int i = 0; i <= testNumber; i++) {
		do {
			id = rand.nextInt(dbList.size());
		} while (id == 0);
		performCRLDelete(dbList.get(id), details);
		// }
	}

	/**
	 * Create a list of dummy CRLs for testing proposes, in this function two
	 * certificates will be created, this certificates representes the
	 * certificates and the keypairs that must be used for create a new CRL
	 * 
	 * 
	 * @param revokedCertificatesDAO
	 *            List of at least 3 certificates that will appear in the CRL
	 * @param issuer
	 *            SubjectDAO object of the issuer
	 * @param crlSerialNumber
	 *            Corresponding crl Serial Number
	 * @param certificateSerialNumber
	 *            serial number that corresponds to the first certificate to be
	 *            created and inserted to the DB in this function
	 * @return a List of 2 CRL
	 */
	private List<CRLDAO> createDummyCRLList(
			List<CertificateDAO> revokedCertificatesDAO, SubjectDAO issuer,
			Integer crlSerialNumber, Integer certificateSerialNumber) {

		// Resulting crl DAO dummy list
		List<CRLDAO> dummyCRLList = new LinkedList<CRLDAO>();
		CertificateFactory fact;
		try {
			fact = CertificateFactory
					.getInstance("X.509", CryptoUtils.PROVIDER);

			ByteArrayInputStream bIn;
			// Certificate object for revoked certificates
			Certificate revokedCert;

			// Create dummy key pairs
			RSAKeyPair rsaIssuerKeyPair = asymmetricCryptoUtils
					.generateKeys(1024);
			ECKeyPair ecIssuerKeyPair = asymmetricCryptoUtils
					.generateKeys(ECDomainParameters.NIST_CURVE_P_192);

			// Create a certificate for the RSA and EC keyPairs with the issuer
			// subject information and add it to the data base
			List<Integer> keyUsageList;
			String certType;
			// Test valid dates
			Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60
					* 60 * 24 * 30);
			Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60
					* 60 * 24 * 30);
			HashMap<String, String> subjectCertificateInformationMap = new HashMap<String, String>();
			// Creates CRL Issuer self signed certificate
			subjectCertificateInformationMap.put(
					CertificateInformationKeys.FRIENDLY_NAME, "SubjectCRL"
							+ issuer.getName());
			subjectCertificateInformationMap.put(
					CertificateInformationKeys.COUNTRY, "MX");
			subjectCertificateInformationMap.put(
					CertificateInformationKeys.EmailAddress, "subjectCRL"
							+ "@gmail.com");
			subjectCertificateInformationMap.put(
					CertificateInformationKeys.FULL_COMMON_NAME, "SubjectCRL"
							+ issuer.getName());
			subjectCertificateInformationMap.put(
					CertificateInformationKeys.LOCALITY, "GAM");
			subjectCertificateInformationMap.put(
					CertificateInformationKeys.STATE, "DF");
			subjectCertificateInformationMap.put(
					CertificateInformationKeys.ORGANIZATION, "Cinvestav");
			subjectCertificateInformationMap.put(
					CertificateInformationKeys.DEVICE_ID,
					SCCipherTestActivity.ANDROID_ID);
			subjectCertificateInformationMap.put(
					CertificateInformationKeys.SIGN_DEVICE_ID,
					SCCipherTestActivity.ANDROID_ID);

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
			X509Certificate issuerRSACert = _X509Utils.createV3Cert(
					rsaIssuerKeyPair.getPublicKey(),
					rsaIssuerKeyPair.getPrivateKey(),
					BigInteger.valueOf(certificateSerialNumber), notBefore,
					notAfter, subjectCertificateInformationMap, keyUsageList,
					certType);
			// Create and insert certificate DAO for RSA keyPair
			CertificateDAO certificateRSA = new CertificateDAO();
			certificateRSA.setId(certificateSerialNumber);
			certificateRSA.setOwner(issuer);
			certificateRSA.setSerialNumber(certificateSerialNumber);
			certificateRSA
					.setStatus(X509UtilsDictionary.X509_CERTIFICATE_STATUS_VALID);
			certificateRSA.setCaCertificate(certificateRSA);
			certificateRSA.setCertificateStr(new String(Base64
					.encode(issuerRSACert.getEncoded())));
			// Insert the new dummy certificate that will be used for sign the
			// CRL using RSA
			Integer certID = certificateController.insert(certificateRSA);
			certificateRSA.setId(certID);
			certificateSerialNumber++;

			X509Certificate issuerECCert = _X509Utils.createV3Cert(
					ecIssuerKeyPair.getPublicKey(),
					ecIssuerKeyPair.getPrivateKey(),
					BigInteger.valueOf(certificateSerialNumber), notBefore,
					notAfter, subjectCertificateInformationMap, keyUsageList,
					certType);

			// Create and insert certificate DAO for EC keyPair
			CertificateDAO certificateEC = new CertificateDAO();
			certificateEC.setId(certificateSerialNumber);
			certificateEC.setOwner(issuer);
			certificateEC.setSerialNumber(certificateSerialNumber);
			certificateEC
					.setStatus(X509UtilsDictionary.X509_CERTIFICATE_STATUS_VALID);
			certificateEC.setCaCertificate(certificateEC);
			certificateEC.setCertificateStr(new String(Base64
					.encode(issuerECCert.getEncoded())));
			// Insert the new dummy certificate that will be used for sign the
			// CRL using EC
			certID = certificateController.insert(certificateEC);
			certificateEC.setId(certID);

			// Create a new CRL and fill it
			Date now = new Date();
			List<X509CRLRevokedCertificateEntry> revokedCertificates = new LinkedList<X509CRLRevokedCertificateEntry>();

			Date tomorrow = new Date(now.getTime() + 1000);
			Date yesterday = new Date(now.getTime() + 100);
			Date nextUpdate = new Date(now.getTime() + 10000);
			BigInteger crlNumber = BigInteger.valueOf(crlSerialNumber);

			// Revoked certificate entry
			bIn = new ByteArrayInputStream(Base64.decode(revokedCertificatesDAO
					.get(0).getCertificateStr()));
			revokedCert = fact.generateCertificate(bIn);
			X509CRLRevokedCertificateEntry entry = new X509CRLRevokedCertificateEntry(
					revokedCert, tomorrow, yesterday,
					X509RevokedCertificateReason.CA_COMPROMISE);
			revokedCertificates.add(entry);

			// Revoked certificate entry
			bIn = new ByteArrayInputStream(Base64.decode(revokedCertificatesDAO
					.get(1).getCertificateStr()));
			revokedCert = fact.generateCertificate(bIn);
			entry = new X509CRLRevokedCertificateEntry(revokedCert, tomorrow,
					yesterday, X509RevokedCertificateReason.KEY_COMPROMISE);
			revokedCertificates.add(entry);

			// Revoked certificate entry
			bIn = new ByteArrayInputStream(Base64.decode(revokedCertificatesDAO
					.get(2).getCertificateStr()));
			revokedCert = fact.generateCertificate(bIn);
			entry = new X509CRLRevokedCertificateEntry(revokedCert, tomorrow,
					yesterday, X509RevokedCertificateReason.PRIVILEGE_WITHDRAWN);
			revokedCertificates.add(entry);

			X509CRL crlRSA = _X509Utils.createCRL(rsaIssuerKeyPair,
					issuerRSACert, revokedCertificates, nextUpdate, crlNumber,
					X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_SHA1withRSA);

			X509CRL crlEC = _X509Utils.createCRL(ecIssuerKeyPair, issuerECCert,
					revokedCertificates, nextUpdate, crlNumber,
					X509UtilsDictionary.EC_X509_SIGN_ALGORITHM_SHA1withECDSA);

			String crlDataStr = "";

			// Create the RSA CRL and add it to the CRL dummy list
			CRLDAO crlDAO = new CRLDAO();
			crlDataStr = new String(Base64.encode(crlRSA.getEncoded()));
			crlDAO.setCrlDataStr(crlDataStr);
			crlDAO.setDescription("Dummy CRL RSA");
			crlDAO.setIssuerCertificate(certificateRSA);
			crlDAO.setPublishDate(new Date());
			crlDAO.setSerialNumber(crlSerialNumber);
			dummyCRLList.add(crlDAO);
			crlSerialNumber++;

			// Create the EC CRL and add it to the CRL dummy list
			crlDAO = new CRLDAO();
			crlDataStr = new String(Base64.encode(crlEC.getEncoded()));
			crlDAO.setCrlDataStr(crlDataStr);
			crlDAO.setDescription("Dummy CRL EC");
			crlDAO.setIssuerCertificate(certificateEC);
			crlDAO.setPublishDate(new Date());
			crlDAO.setSerialNumber(crlSerialNumber);
			dummyCRLList.add(crlDAO);

			return dummyCRLList;
		} catch (CertificateException e) {
			log.error("[CRL] CREATE DUMMY CRL Error: " + e);
		} catch (NoSuchProviderException e) {
			log.error("[CRL] CREATE DUMMY CRL Error: " + e);
		} catch (CRLException e) {
			log.error("[CRL] CREATE DUMMY CRL Error: " + e);
		} catch (CryptoUtilsException e) {
			log.error("[CRL] CREATE DUMMY CRL Error: " + e);
		} catch (CryptoUtilsX509ExtensionException e) {
			log.error("[CRL] CREATE DUMMY CRL Error: " + e);
		} catch (DBException e) {
			log.error("[CRL] CREATE DUMMY CRL Error: " + e);
		}

		return new LinkedList<CRLDAO>();
	}

	/**
	 * Perform the insertion test to the data base, the test will be OK if the
	 * inserted values are the same that the ones in the object
	 * 
	 * @param crl
	 * @param details
	 */
	private void performCRLInsert(CRLDAO crl, Boolean details) {
		try {
			Integer trcID = crlController.insert(crl);
			CRLDAO resCRL = crlController.getById(trcID);

			crl.setId(trcID);
			String res = resCRL.equals(crl) ? "OK" : "FAIL";
			log.info("[CRL] INSERT= " + res);

			if (details) {
				log.info("[CRL] CRL ORG= " + crl);
				log.info("[CRL] CRL DB = " + resCRL);
			}

		} catch (DBException e) {
			log.error("[CRL] INSERT Error: " + e);
		}
	}

	/**
	 * Perform the delete test to the data base, the test will be OK if the
	 * total count of trusted certificates in the data base is altered, FAIL
	 * other wise
	 * 
	 * @param subjectDAO
	 * @param details
	 */
	private void performCRLDelete(CRLDAO crlDAO, Boolean details) {
		try {
			Integer countBefore = crlController.getCount();
			crlController.delete(crlDAO);
			Integer countAfter = crlController.getCount();

			String res = countBefore.equals(countAfter + 1) ? "OK" : "FAIL";
			log.info("[CRL] DELETE [" + crlDAO.getId() + "]= " + res);

			if (details) {
				log.info("[CRL] CRL= " + crlDAO);
			}

		} catch (DBException e) {
			log.error("[CRL] DELETE Error: " + e);
		}

	}

	/**
	 * Perform the crl getAll search test, if the result list is not empty, the
	 * test is OK otherwise the test FAIL
	 * 
	 * @param details
	 */
	private List<CRLDAO> performCRLGetAll(Boolean details) {
		try {
			List<CRLDAO> resList = crlController.getAll();
			if (details) {
				log.info("COUNT= " + resList.size());
				for (CRLDAO sub : resList) {
					log.info("[CRL] = " + sub);
				}
			}
			String res = resList.size() != 0 ? "OK" : "FAIL";
			log.info("[CRL] GET ALL = " + res);
			return resList;
		} catch (DBException e) {
			log.error("[CRL] GET_ALLError: " + e);
		}
		return new LinkedList<CRLDAO>();
	}

	/**
	 * Perform the crl search by subjectID test, if the result list is not
	 * empty, the test is OK otherwise the test FAIL
	 * 
	 * @param subjectID
	 *            subject id to be searched
	 * @param details
	 */
	private void performCRLGetByIssuerSubjecID(Integer subjectID,
			Boolean details) {
		try {
			List<CRLDAO> resList = crlController
					.getByIssuerSubjectId(subjectID);
			if (details) {
				log.info("COUNT= " + resList.size());
				for (CRLDAO sub : resList) {
					log.info("[CRL] = " + sub);
				}
			}
			String res = resList.size() != 0 ? "OK" : "FAIL";
			log.info("[CRL] GET BY SUBJECT ID [" + subjectID + "]= " + res);
		} catch (DBException e) {
			log.error("[CRL] GET BY SUBJECT ID Error: " + e);
		}
	}

	/**
	 * Perform the crl search by issuerCertificateId test, if the result list is
	 * not empty, the test is OK otherwise the test FAIL
	 * 
	 * @param issuerCertificateId
	 *            issuerCertificateId to be searched
	 * @param details
	 */
	private void performCRLGetByIssuerCertificateId(
			Integer issuerCertificateId, Boolean details) {
		try {
			List<CRLDAO> resList = crlController
					.getByIssuerCertificateId(issuerCertificateId);
			if (details) {
				log.info("COUNT= " + resList.size());
				for (CRLDAO sub : resList) {
					log.info("[CRL] = " + sub);
				}
			}
			String res = resList.size() != 0 ? "OK" : "FAIL";
			log.info("[CRL] GET BY ISSUER CERTIFICATE ID ["
					+ issuerCertificateId + "]= " + res);
		} catch (DBException e) {
			log.error("[CRL] GET BY ISSUER CERTIFICATE ID Error: " + e);
		}
	}

	/**
	 * Perform the crl search by issuerCertificate Serial Number test, if the
	 * result list is not empty, the test is OK otherwise the test FAIL
	 * 
	 * @param issuerCertificateSerialNumber
	 *            issuerCertificate Serial Number to be searched
	 * @param details
	 */
	private void performCRLGetByIssuerCertificateSerialNumber(
			Integer issuerCertificateSerialNumber, Boolean details) {
		try {
			List<CRLDAO> resList = crlController
					.getByIssuerCertificateSerialNumber(issuerCertificateSerialNumber);
			if (details) {
				log.info("COUNT= " + resList.size());
				for (CRLDAO sub : resList) {
					log.info("[CRL] = " + sub);
				}
			}
			String res = resList.size() != 0 ? "OK" : "FAIL";
			log.info("[CRL] GET BY ISSUER CERTIFICATE SERIAL NUMBER ["
					+ issuerCertificateSerialNumber + "]= " + res);
		} catch (DBException e) {
			log.error("[CRL] GET BY ISSUER CERTIFICATE SERIAL NUMBER  Error: "
					+ e);
		}
	}

	/**
	 * Perform the crl search by ID test, if the result crl has its id!=0, the
	 * test is OK otherwise the test FAIL
	 * 
	 * @param crlID
	 *            Id to be searched
	 * @param details
	 */
	private void performCRLGetByID(Integer crlID, Boolean details) {
		try {
			CRLDAO resCRL = crlController.getById(crlID);
			if (details) {
				log.info("CRL= " + resCRL);
			}

			String res = resCRL.getId() != 0 ? "OK" : "FAIL";
			log.info("[CRL] GET BY ID [" + crlID + "]= " + res);
		} catch (DBException e) {
			log.error("[CRL] GET BY ID Error: " + e);
		}
	}

	/**
	 * Perform the crl search by serialNumber test, if the result crl has its
	 * id!=0, the test is OK otherwise the test FAIL
	 * 
	 * @param serialNumber
	 *            serialNumber to be searched
	 * @param details
	 */
	private void performCRLGetSerialNumber(Integer serialNumber, Boolean details) {
		try {
			CRLDAO resCRL = crlController.getBySerialNumber(serialNumber);
			if (details) {
				log.info("CRL= " + resCRL);
			}

			String res = resCRL.getId() != 0 ? "OK" : "FAIL";
			log.info("[CRL] GET BY CRL SERIAL NUMBER [" + serialNumber + "]= "
					+ res);
		} catch (DBException e) {
			log.error("[CRL] GET BY CRL SERIAL NUMBER Error: " + e);
		}
	}

	/**
	 * Test the search of crl using a filter map as parameter, if the result
	 * list is not empty, the test is OK otherwise the test FAIL
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
	private void performCRLGetByAdvanced(Map<String, String[]> filterMap,
			Boolean details) {
		try {

			List<CRLDAO> resList = crlController.getByAdvancedFilter(filterMap);
			if (details) {
				log.info("COUNT= " + resList.size());
				for (CRLDAO sub : resList) {
					log.info("[CRL] GET BY ADVANCED FILTER = " + sub);
				}
			}
			String res = resList.size() != 0 ? "OK" : "FAIL";
			log.info("[CRL] GET BY ADVANCED FILTER = " + res);
		} catch (DBException e) {
			log.error("[CRL] GET BY ADVANCED FILTER Error: " + e);
		}
	}

	/**
	 * Perform the test for get the current id, if the result is not 0, the test
	 * is OK otherwise the test FAIL
	 * 
	 * @param details
	 */
	private void performCRLGetCurrentId(Boolean details) {
		Integer currentID = crlController.getCurrentId();
		if (details) {
			log.info("[CRL] CURRENT ID= " + currentID);
		}

		String res = !currentID.equals(0) ? "OK" : "FAIL";
		log.info("[CRL] CURRENT ID = " + res);
	}
}
