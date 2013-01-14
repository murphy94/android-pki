/**
 *  Created on  : 15/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	
 */
package cinvestav.pki.androidpkiutilstest;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase.CursorFactory;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.db.controller.CertificateController;
import cinvestav.android.pki.db.controller.SubjectController;
import cinvestav.android.pki.db.controller.TrustedCertificateController;
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.android.pki.db.dao.SubjectDAO;
import cinvestav.android.pki.db.dao.TrustedCertificateDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.android.pki.utils.DataBaseDictionary;
import cinvestav.android.pki.utils.LogUtil;

/**
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 15/08/2012
 * @version 1.0
 */
public class DBTrustedCertificateTestRunner {
	protected static LogUtil log = new LogUtil("ANDROID_PKI_UTILS");
	private TrustedCertificateController trustedCertificateController;
	private SubjectController subjectController;
	private CertificateController certificateController;

	/**
	 * 
	 * @param context
	 * @param name
	 * @param factory
	 * @param version
	 * @throws CryptoUtilsException
	 */
	public DBTrustedCertificateTestRunner(Context context, String name,
			CursorFactory factory, int version) throws CryptoUtilsException {
		this.trustedCertificateController = new TrustedCertificateController(
				context, name, factory, version);
		this.subjectController = new SubjectController(context, name, factory,
				version);
		this.certificateController = new CertificateController(context, name,
				factory, version);
	}

	/**
	 * Constructor that inits the data base connection using application context
	 * 
	 * @param context
	 * @throws CryptoUtilsException
	 */
	public DBTrustedCertificateTestRunner(Context context)
			throws CryptoUtilsException {
		this.trustedCertificateController = new TrustedCertificateController(
				context);
		this.subjectController = new SubjectController(context);
		this.certificateController = new CertificateController(context);
	}

	public void testTrustedCertificateDB(Integer testNumber, Boolean details)
			throws DBException {
		log.info(" ********* TrustedCertificate DB-Controller Test Begin *********");
		List<SubjectDAO> allSubjectList = subjectController.getAll();
		List<CertificateDAO> allCertificatesList = certificateController
				.getAll();
		for (CertificateDAO certificate : allCertificatesList) {
			certificateController.getCertificateDetails(certificate);
		}

		Random rand = new Random(System.currentTimeMillis());
		Integer id;

		List<SubjectDAO> dummySubjectList = new LinkedList<SubjectDAO>();
		// Select 10 subject randomly
		for (int i = 0; i < 10; i++) {
			Integer subID = rand.nextInt(allSubjectList.size());
			dummySubjectList.add(allSubjectList.get(subID));
		}

		List<TrustedCertificateDAO> dummyTrustedCertificateList = createDummyTrustedCertificateList(
				dummySubjectList, allCertificatesList, 10);
		log.info(" ********* INSERT *********");
		for (TrustedCertificateDAO trustedCertificate : dummyTrustedCertificateList) {
			do {
				id = rand.nextInt(dummySubjectList.size());
			} while (id == 0);
			performTrustedCertificateInsert(trustedCertificate, id, details);
		}

		log.info(" ********* GET ALL *********");
		List<TrustedCertificateDAO> dbList = performTrustedCertificateGetAll(details);

		log.info(" ********* GET BY ID *********");
		for (int i = 0; i <= testNumber; i++) {
			do {
				id = rand.nextInt(dbList.size());
			} while (id == 0);
			performTrustedCertificateGetByID(id, details);
		}

		log.info(" ********* GET BY SUBJECT ID *********");
		for (int i = 0; i <= testNumber; i++) {
			do {
				id = rand.nextInt(dummySubjectList.size());
			} while (id == 0);
			performTrustedCertificateGetBySubjectID(id, details);
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
			value[1] = DataBaseDictionary.FILTER_TYPE_TRUSTED_CERTIFICATE_ID;
			filterMap.put(DataBaseDictionary.FILTER_TRUSTED_CERTIFICATE_ID,
					value);

			value = new String[3];
			/*
			 * Establish filter properties
			 */
			// Filter value
			value[0] = dbList.get(id).getTrustLevel() + "";
			// Filter type
			value[1] = DataBaseDictionary.FILTER_TYPE_TRUSTED_CERTIFICATE_LEVEL;
			filterMap.put(DataBaseDictionary.FILTER_TRUSTED_CERTIFICATE_LEVEL,
					value);

			performTrustedCertificateGetByAdvanced(filterMap, details);
		}

		log.info(" ********* UPDATE *********");
		for (int i = 0; i <= testNumber; i++) {
			do {
				id = rand.nextInt(dbList.size());
			} while (id == 0);
			TrustedCertificateDAO trustedCertificate = dbList.get(id);
			trustedCertificate
					.setTrustLevel(0);
			performTrustedCertificateUpdate(trustedCertificate, details);
		}

		log.info(" ********* DELETE *********");
		for (int i = 0; i <= testNumber; i++) {
			do {
				id = rand.nextInt(dbList.size());
			} while (id == 0);
			performTrustedCertificateDelete(dbList.get(id), details);
		}
	}

	/**
	 * Create a list of dummy trustedCertificates for testing proposes
	 * 
	 * @param dummySubjectList
	 *            List of subject, which represents the owners of the
	 *            trustedCertificates List
	 * @param certificatesAvailable
	 *            List of available certificates in the data base
	 * @param count
	 *            How many trusted certificates should be created
	 * @throws DBException
	 */
	private List<TrustedCertificateDAO> createDummyTrustedCertificateList(
			List<SubjectDAO> dummySubjectList,
			List<CertificateDAO> certificatesAvailable, Integer count)
			throws DBException {

		// Resulting trustedCertificate DAO dummy list
		List<TrustedCertificateDAO> dummyTrustedCertificateList = new LinkedList<TrustedCertificateDAO>();
		Random rand = new Random(System.currentTimeMillis());
		Integer trustLevel = 0;
		Integer id = 0;
		for (int i = 0; i < count; i++) {
			TrustedCertificateDAO trustedCertificateDAO = new TrustedCertificateDAO();
			do {
				id = rand.nextInt(certificatesAvailable.size());
			} while (id == 0);
			trustedCertificateDAO.setTrustedCertificate(certificatesAvailable
					.get(id));
			trustLevel = rand.nextInt(4);
			trustedCertificateDAO.setTrustLevel(trustLevel);
			dummyTrustedCertificateList.add(trustedCertificateDAO);
		}

		return dummyTrustedCertificateList;

	}

	/**
	 * Perform the insertion test to the data base, the test will be OK if the
	 * inserted values are the same that the ones in the object
	 * 
	 * @param trustedCertificate
	 * @param subjectID
	 * @param details
	 */
	private void performTrustedCertificateInsert(
			TrustedCertificateDAO trustedCertificate, Integer subjectID,
			Boolean details) {
		try {
			Integer trcID = trustedCertificateController.insert(
					trustedCertificate, subjectID);
			TrustedCertificateDAO resTrustedCertificate = trustedCertificateController
					.getById(trcID);

			trustedCertificate.setId(trcID);
			String res = resTrustedCertificate.equals(trustedCertificate) ? "OK"
					: "FAIL";
			log.info("[TRUSTED_CERTIFICATE] INSERT= " + res);

			if (details) {
				log.info("[TRUSTED_CERTIFICATE] TRUSTED_CERTIFICATE ORG= "
						+ trustedCertificate);
				log.info("[TRUSTED_CERTIFICATE] TRUSTED_CERTIFICATE DB = "
						+ resTrustedCertificate);
			}

		} catch (DBException e) {
			log.error("[TRUSTED_CERTIFICATE] INSERT Error: " + e);
		}
	}

	/**
	 * Perform the update test to the data base, the test will be OK if the
	 * inserted values are the same that the ones in the object
	 * 
	 * @param trustedCertificate
	 *            TrustedCertificate to be updated
	 * @param details
	 */
	private void performTrustedCertificateUpdate(
			TrustedCertificateDAO trustedCertificate, Boolean details) {
		try {
			trustedCertificateController.update(trustedCertificate);
			TrustedCertificateDAO resTrustedCertificate = trustedCertificateController
					.getById(trustedCertificate.getId());

			String res = resTrustedCertificate.equals(trustedCertificate) ? "OK"
					: "FAIL";
			log.info("[TRUSTED_CERTIFICATE] UPDATE ["
					+ trustedCertificate.getId() + "]= " + res);

			if (details) {
				log.info("[TRUSTED_CERTIFICATE] TRUSTED_CERTIFICATE= "
						+ trustedCertificate);
			}

		} catch (DBException e) {
			log.error("[TRUSTED_CERTIFICATE] UPDATE Error: " + e);
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
	private void performTrustedCertificateDelete(
			TrustedCertificateDAO trustedCertificateDAO, Boolean details) {
		try {
			Integer countBefore = trustedCertificateController.getCount();
			trustedCertificateController.delete(trustedCertificateDAO);
			Integer countAfter = trustedCertificateController.getCount();

			String res = countBefore.equals(countAfter + 1) ? "OK" : "FAIL";
			log.info("[TRUSTED_CERTIFICATE] DELETE ["
					+ trustedCertificateDAO.getId() + "]= " + res);

			if (details) {
				log.info("[TRUSTED_CERTIFICATE] TRUSTED_CERTIFICATE= "
						+ trustedCertificateDAO);
			}

		} catch (DBException e) {
			log.error("[TRUSTED_CERTIFICATE] DELETE Error: " + e);
		}

	}

	/**
	 * Perform the trustedCertificate getAll search test, if the result list is
	 * not empty, the test is OK otherwise the test FAIL
	 * 
	 * @param details
	 */
	private List<TrustedCertificateDAO> performTrustedCertificateGetAll(
			Boolean details) {
		try {
			List<TrustedCertificateDAO> resList = trustedCertificateController
					.getAll();
			if (details) {
				log.info("COUNT= " + resList.size());
				for (TrustedCertificateDAO sub : resList) {
					log.info("[TRUSTED_CERTIFICATE] = " + sub);
				}
			}
			String res = resList.size() != 0 ? "OK" : "FAIL";
			log.info("[TRUSTED_CERTIFICATE] GET ALL = " + res);
			return resList;
		} catch (DBException e) {
			log.error("[TRUSTED_CERTIFICATE] GET_ALLError: " + e);
		}
		return new LinkedList<TrustedCertificateDAO>();
	}

	/**
	 * Perform the trustedCertificate search by subjectID test, if the result
	 * list is not empty, the test is OK otherwise the test FAIL
	 * 
	 * @param subjectID
	 *            subject id to be searched
	 * @param details
	 */
	private void performTrustedCertificateGetBySubjectID(Integer subjectID,
			Boolean details) {
		try {
			List<TrustedCertificateDAO> resList = trustedCertificateController
					.getBySubjectId(subjectID);
			if (details) {
				log.info("COUNT= " + resList.size());
				for (TrustedCertificateDAO sub : resList) {
					log.info("[TRUSTED_CERTIFICATE] = " + sub);
				}
			}
			String res = resList.size() != 0 ? "OK" : "FAIL";
			log.info("[TRUSTED_CERTIFICATE] GET BY SUBJECT ID [" + subjectID
					+ "]= " + res);
		} catch (DBException e) {
			log.error("[TRUSTED_CERTIFICATE] GET BY SUBJECT ID Error: " + e);
		}
	}

	/**
	 * Perform the trustedCertificate search by ID test, if the result
	 * trustedCertificate has its id!=0, the test is OK otherwise the test FAIL
	 * 
	 * @param trustedCertificateID
	 *            Id to be searched
	 * @param details
	 */
	private void performTrustedCertificateGetByID(Integer trustedCertificateID,
			Boolean details) {
		try {
			TrustedCertificateDAO resTrustedCertificate = trustedCertificateController
					.getById(trustedCertificateID);
			if (details) {
				log.info("TrustedCertificate= " + resTrustedCertificate);
			}

			String res = resTrustedCertificate.getId() != 0 ? "OK" : "FAIL";
			log.info("[TRUSTED_CERTIFICATE] GET BY ID [" + trustedCertificateID
					+ "]= " + res);
		} catch (DBException e) {
			log.error("[TRUSTED_CERTIFICATE] GET BY ID Error: " + e);
		}
	}

	/**
	 * Test the search of trustedCertificate using a filter map as parameter, if
	 * the result list is not empty, the test is OK otherwise the test FAIL
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
	private void performTrustedCertificateGetByAdvanced(
			Map<String, String[]> filterMap, Boolean details) {
		try {

			List<TrustedCertificateDAO> resList = trustedCertificateController
					.getByAdvancedFilter(filterMap);
			if (details) {
				log.info("COUNT= " + resList.size());
				for (TrustedCertificateDAO sub : resList) {
					log.info("[TRUSTED_CERTIFICATE] GET BY ADVANCED FILTER = "
							+ sub);
				}
			}
			String res = resList.size() != 0 ? "OK" : "FAIL";
			log.info("[TRUSTED_CERTIFICATE] GET BY ADVANCED FILTER = " + res);
		} catch (DBException e) {
			log.error("[TRUSTED_CERTIFICATE] GET BY ADVANCED FILTER Error: "
					+ e);
		}
	}
}
