/**
 *  Created on  : 09/08/2012
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
import cinvestav.android.pki.db.controller.SubjectController;
import cinvestav.android.pki.db.dao.SubjectDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.android.pki.utils.DataBaseDictionary;
import cinvestav.android.pki.utils.LogUtil;

/**
 * This class contains all the test corresponding to Subject DB
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 09/08/2012
 * @version 1.0
 */
public class DBSubjectTestRunner {

	protected static LogUtil log = new LogUtil("ANDROID_PKI_UTILS");
	private SubjectController subjectController;

	/**
	 * 
	 * @param context
	 * @param name
	 * @param factory
	 * @param version
	 */
	public DBSubjectTestRunner(Context context, String name,
			CursorFactory factory, int version) {
		this.subjectController = new SubjectController(context, name, factory,
				version);
	}

	/**
	 * Constructor that inits the data base connection using application context
	 * 
	 * @param context
	 */
	public DBSubjectTestRunner(Context context) {
		this.subjectController = new SubjectController(context);
	}

	public void testSubjectDB(Integer testNumber, Boolean details) {
		log.info(" ********* Subject DB-Controller Test Begin *********");
		List<SubjectDAO> testList = createDummySubjectList();
		log.info(" ********* INSERT *********");
		for (SubjectDAO subject : testList) {
			performSubjectInsert(subject, details);
		}

		Random rand = new Random(System.currentTimeMillis());

		log.info(" ********* GET CURRENT ID *********");
		for (int i = 0; i <= testNumber; i++) {
			performSubjectGetCurrentId(details);
		}
		
		log.info(" ********* GET ALL *********");
		List<SubjectDAO> dbList = performSubjetGetAll(details);

		log.info(" ********* GET BY ID *********");
		for (int i = 0; i <= testNumber; i++) {
			Integer id = rand.nextInt(dbList.size());
			performSubjetGetByID(dbList.get(id).getId(), details);
		}

		log.info(" ********* GET BY NAME *********");
		for (int i = 0; i <= testNumber; i++) {
			Integer id = rand.nextInt(dbList.size());
			performSubjetGetByName(dbList.get(id).getName(), details);
		}

		log.info(" ********* GET BY ADV FILTER *********");
		for (int i = 0; i <= testNumber; i++) {
			Integer id = rand.nextInt(dbList.size());
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
			value[0] = dbList.get(id).getName() + "";
			// Filter type
			value[1] = DataBaseDictionary.FILTER_TYPE_SUBJECT_NAME;
			filterMap.put(DataBaseDictionary.FILTER_SUBJECT_NAME, value);

			value = new String[3];
			/*
			 * Establish filter properties
			 */
			// Filter value
			value[0] = dbList.get(id).getId() + "";
			// Filter type
			value[1] = DataBaseDictionary.FILTER_TYPE_SUBJECT_ID;
			filterMap.put(DataBaseDictionary.FILTER_SUBJECT_ID, value);

			performSubjetGetByAdvanced(filterMap, details);
		}

		log.info(" ********* UPDATE *********");
		for (int i = 0; i <= testNumber; i++) {
			Integer id = rand.nextInt(dbList.size());
			SubjectDAO sub = dbList.get(id);
			sub.setName(sub.getName() + "X");
			performSubjectUpdate(sub, details);
		}

		log.info(" ********* DELETE *********");
		for (int i = 0; i <= testNumber; i++) {
			Integer delID = rand.nextInt(dbList.size());
			SubjectDAO del = new SubjectDAO();
			del.setId(delID);
			performSubjectDelete(del, details);
		}

	}

	private List<SubjectDAO> createDummySubjectList() {
		List<SubjectDAO> dummySubjectList = new LinkedList<SubjectDAO>();

		SubjectDAO subjectTest = new SubjectDAO();
		subjectTest.setName("Javier Silva");
		subjectTest.setDeviceID(SCCipherTestActivity.ANDROID_ID);
		dummySubjectList.add(subjectTest);

		subjectTest = new SubjectDAO();
		subjectTest.setName("Juan Pérez");
		subjectTest.setDeviceID(SCCipherTestActivity.ANDROID_ID);
		dummySubjectList.add(subjectTest);

		subjectTest = new SubjectDAO();
		subjectTest.setName("Cynthia Palma");
		subjectTest.setDeviceID(SCCipherTestActivity.ANDROID_ID);
		dummySubjectList.add(subjectTest);

		subjectTest = new SubjectDAO();
		subjectTest.setName("Edgar Olvera");
		subjectTest.setDeviceID(SCCipherTestActivity.ANDROID_ID);
		dummySubjectList.add(subjectTest);

		subjectTest = new SubjectDAO();
		subjectTest.setName("Francisco Silva");
		subjectTest.setDeviceID(SCCipherTestActivity.ANDROID_ID);
		dummySubjectList.add(subjectTest);

		subjectTest = new SubjectDAO();
		subjectTest.setName("Victor Gastelum");
		subjectTest.setDeviceID(SCCipherTestActivity.ANDROID_ID);
		dummySubjectList.add(subjectTest);

		subjectTest = new SubjectDAO();
		subjectTest.setName("Victor Zaragoza");
		subjectTest.setDeviceID(SCCipherTestActivity.ANDROID_ID);
		dummySubjectList.add(subjectTest);

		subjectTest = new SubjectDAO();
		subjectTest.setName("Selene Escutia");
		subjectTest.setDeviceID(SCCipherTestActivity.ANDROID_ID);
		dummySubjectList.add(subjectTest);

		subjectTest = new SubjectDAO();
		subjectTest.setName("Daniela Perez");
		subjectTest.setDeviceID(SCCipherTestActivity.ANDROID_ID);
		dummySubjectList.add(subjectTest);

		subjectTest = new SubjectDAO();
		subjectTest.setName("Juan Martinez");
		subjectTest.setDeviceID(SCCipherTestActivity.ANDROID_ID);
		dummySubjectList.add(subjectTest);

		subjectTest = new SubjectDAO();
		subjectTest.setName("Gabriela Ortiz");
		subjectTest.setDeviceID(SCCipherTestActivity.ANDROID_ID);
		dummySubjectList.add(subjectTest);
		
		subjectTest = new SubjectDAO();
		subjectTest.setName("Edgar Zaragoza");
		subjectTest.setDeviceID(SCCipherTestActivity.ANDROID_ID);
		dummySubjectList.add(subjectTest);
		
		subjectTest = new SubjectDAO();
		subjectTest.setName("Daniel Martin Nava");
		subjectTest.setDeviceID(SCCipherTestActivity.ANDROID_ID);
		dummySubjectList.add(subjectTest);
		
		subjectTest = new SubjectDAO();
		subjectTest.setName("Citlalli Hernandez");
		subjectTest.setDeviceID(SCCipherTestActivity.ANDROID_ID);
		dummySubjectList.add(subjectTest);
		
		subjectTest = new SubjectDAO();
		subjectTest.setName("Javis JR");
		subjectTest.setDeviceID(SCCipherTestActivity.ANDROID_ID);
		dummySubjectList.add(subjectTest);
		
		subjectTest = new SubjectDAO();
		subjectTest.setName("Cyn");
		subjectTest.setDeviceID(SCCipherTestActivity.ANDROID_ID);
		dummySubjectList.add(subjectTest);
		
		subjectTest = new SubjectDAO();
		subjectTest.setName("Abril Dominguez");
		subjectTest.setDeviceID(SCCipherTestActivity.ANDROID_ID);
		dummySubjectList.add(subjectTest);
		
		subjectTest = new SubjectDAO();
		subjectTest.setName("Juanito Balderas");
		subjectTest.setDeviceID(SCCipherTestActivity.ANDROID_ID);
		dummySubjectList.add(subjectTest);
		
		subjectTest = new SubjectDAO();
		subjectTest.setName("Ernesto Guardiola");
		subjectTest.setDeviceID(SCCipherTestActivity.ANDROID_ID);
		dummySubjectList.add(subjectTest);
		
		subjectTest = new SubjectDAO();
		subjectTest.setName("Sergio Martinez");
		subjectTest.setDeviceID(SCCipherTestActivity.ANDROID_ID);
		dummySubjectList.add(subjectTest);
		
		subjectTest = new SubjectDAO();
		subjectTest.setName("Oswaldin");
		subjectTest.setDeviceID(SCCipherTestActivity.ANDROID_ID);
		dummySubjectList.add(subjectTest);
		
		subjectTest = new SubjectDAO();
		subjectTest.setName("Juanito BS");
		subjectTest.setDeviceID(SCCipherTestActivity.ANDROID_ID);
		dummySubjectList.add(subjectTest);

		return dummySubjectList;
	}

	private void performSubjectInsert(SubjectDAO subject, Boolean details) {
		try {
			Integer subID = subjectController.insert(subject);
			SubjectDAO resSubject = subjectController.getById(subID);

			subject.setId(subID);
			String res = resSubject.equals(subject) ? "OK" : "FAIL";
			log.info("[SUBJECT] INSERT= " + res);

			if (details) {
				log.info("[SUBJECT] SUBJECT ORG= " + subject);
				log.info("[SUBJECT] SUBJECT DB = " + resSubject);
			}

		} catch (DBException e) {
			log.error("[SUBJECT] INSERT Error: " + e);
		}
	}

	private void performSubjectUpdate(SubjectDAO subject, Boolean details) {
		try {
			subjectController.update(subject);
			SubjectDAO resSubject = subjectController.getById(subject.getId());

			String res = resSubject.equals(subject) ? "OK" : "FAIL";
			log.info("[SUBJECT] UPDATE [" + subject.getId() + "]= " + res);

			if (details) {
				log.info("[SUBJECT] SUBJECT= " + subject);
			}

		} catch (DBException e) {
			log.error("[SUBJECT] UPDATE Error: " + e);
		}

	}

	private void performSubjectDelete(SubjectDAO subjectDAO, Boolean details) {
		try {
			subjectController.delete(subjectDAO);
			SubjectDAO resSubject = subjectController.getById(subjectDAO
					.getId());

			String res = resSubject.getActive() == Boolean.FALSE ? "OK"
					: "FAIL";
			log.info("[SUBJECT] DELETE [" + subjectDAO.getId() + "]= " + res);

			if (details) {
				log.info("[SUBJECT] SUBJECT= " + subjectDAO);
			}

		} catch (DBException e) {
			log.error("[SUBJECT] DELETE Error: " + e);
		}
	}

	/**
	 * Perform the subject getAll search test, if the result list is not empty,
	 * the test is OK otherwise the test FAIL
	 * 
	 * @param details
	 */
	private List<SubjectDAO> performSubjetGetAll(Boolean details) {
		try {
			List<SubjectDAO> resList = subjectController.getAll();
			if (details) {
				log.info("COUNT= " + resList.size());
				for (SubjectDAO sub : resList) {
					log.info("[SUBJECT] = " + sub);
				}
			}
			String res = resList.size() != 0 ? "OK" : "FAIL";
			log.info("[SUBJECT] GET ALL = " + res);
			return resList;
		} catch (DBException e) {
			log.error("[SUBJECT] GET_ALLError: " + e);
		}
		return new LinkedList<SubjectDAO>();
	}

	/**
	 * Perform the subject search by name test, if the result list is not empty,
	 * the test is OK otherwise the test FAIL
	 * 
	 * @param name
	 *            Name to be searched
	 * @param details
	 */
	private void performSubjetGetByName(String name, Boolean details) {
		try {
			List<SubjectDAO> resList = subjectController.getByName(name);
			if (details) {
				log.info("COUNT= " + resList.size());
				for (SubjectDAO sub : resList) {
					log.info("[SUBJECT] GET BY NAME [" + name + "]= " + sub);
				}
			}
			String res = resList.size() != 0 ? "OK" : "FAIL";
			log.info("[SUBJECT] GET BY NAME = " + res);
		} catch (DBException e) {
			log.error("[SUBJECT] GET BY NAME Error: " + e);
		}
	}

	/**
	 * Perform the subject search by ID test, if the result subject has its
	 * id!=0, the test is OK otherwise the test FAIL
	 * 
	 * @param subjectID
	 *            Id to be searched
	 * @param details
	 */
	private void performSubjetGetByID(Integer subjectID, Boolean details) {
		try {
			SubjectDAO resSubject = subjectController.getById(subjectID);
			if (details) {
				log.info("Subject= " + resSubject);
			}

			String res = resSubject.getId() != 0 ? "OK" : "FAIL";
			log.info("[SUBJECT] GET BY ID [" + subjectID + "]= " + res);
		} catch (DBException e) {
			log.error("[SUBJECT] GET BY ID Error: " + e);
		}
	}

	/**
	 * Test the search of subject using a filter map as parameter, if the result
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
	private void performSubjetGetByAdvanced(Map<String, String[]> filterMap,
			Boolean details) {
		try {

			List<SubjectDAO> resList = subjectController
					.getByAdvancedFilter(filterMap);
			if (details) {
				log.info("COUNT= " + resList.size());
				for (SubjectDAO sub : resList) {
					log.info("[SUBJECT] GET BY ADVANCED FILTER = " + sub);
				}
			}
			String res = resList.size() != 0 ? "OK" : "FAIL";
			log.info("[SUBJECT] GET BY ADVANCED FILTER = " + res);
		} catch (DBException e) {
			log.error("[SUBJECT] GET BY ADVANCED FILTER Error: " + e);
		}
	}

	/**
	 * Perform the test for get the current id, if the result is not 0, the test
	 * is OK otherwise the test FAIL
	 * 
	 * @param details
	 */
	private void performSubjectGetCurrentId(Boolean details) {
		Integer currentID = subjectController.getCurrentId();
		if (details) {
			log.info("[SUBJECT] CURRENT ID= " + currentID);
		}

		String res = !currentID.equals(0) ? "OK" : "FAIL";
		log.info("[SUBJECT] CURRENT ID = " + res);
	}
}
