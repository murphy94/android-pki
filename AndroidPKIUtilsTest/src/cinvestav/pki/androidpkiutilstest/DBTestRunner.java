/**
 *  Created on  : 08/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	
 */
package cinvestav.pki.androidpkiutilstest;

import java.io.IOException;

import android.content.Context;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase.CursorFactory;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.db.db.DataBaseHelper;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.android.pki.utils.LogUtil;

/**
 * Run all the test for DB functions available in the PKI library
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 08/08/2012
 * @version 1.0
 */
public class DBTestRunner {

	protected static LogUtil log = new LogUtil("ANDROID_PKI_UTILS");

	DBSubjectTestRunner dbSubjectTestRunner;
	DBPersonalKeyTestRunner dbPersonalKeyTestRunner;
	DBCertificateTestRunner dbCertificateTestRunner;
	DBTrustedCertificateTestRunner dbTrustedCertificateTestRunner;
	DBCRLTestRunner dbcrlTestRunner;

	/**
	 * 
	 * @param context
	 * @param name
	 * @param factory
	 * @param version
	 * @throws CryptoUtilsException
	 */
	public DBTestRunner(Context context, String name, CursorFactory factory,
			int version) throws CryptoUtilsException {
		dbSubjectTestRunner = new DBSubjectTestRunner(context, name, factory,
				version);
		dbPersonalKeyTestRunner = new DBPersonalKeyTestRunner(context, name,
				factory, version);
		dbCertificateTestRunner = new DBCertificateTestRunner(context, name,
				factory, version);
		dbTrustedCertificateTestRunner = new DBTrustedCertificateTestRunner(
				context, name, factory, version);
		dbcrlTestRunner = new DBCRLTestRunner(context, name, factory, version);

	}

	/**
	 * Constructor that inits the data base connection using application context
	 * 
	 * @param context
	 * @throws CryptoUtilsException
	 */
	public DBTestRunner(Context context) throws CryptoUtilsException {
		dbSubjectTestRunner = new DBSubjectTestRunner(context);
		dbPersonalKeyTestRunner = new DBPersonalKeyTestRunner(context);
		dbCertificateTestRunner = new DBCertificateTestRunner(context);
		dbTrustedCertificateTestRunner = new DBTrustedCertificateTestRunner(
				context);
		dbcrlTestRunner = new DBCRLTestRunner(context);
	}

	public void runTest(Context context, Boolean detailResult) {
		log.info(" ********* DB Test Begin *********");
		Integer testNumber = 5;
		try {
			initDBLoader(context);

			// dbSubjectTestRunner.testSubjectDB(testNumber, detailResult);
			// dbPersonalKeyTestRunner.testPersonalKeyDB(testNumber,
			// detailResult);
			dbCertificateTestRunner.testCertificateDB(testNumber, detailResult);
			//dbTrustedCertificateTestRunner.testTrustedCertificateDB(testNumber,
			//detailResult);
			//dbcrlTestRunner.testCRLDB(testNumber, detailResult);
		} catch (DBException e) {
			e.printStackTrace();
			log.error(e, e);
		}
	}

	private void initDBLoader(Context context) {

		log.info(" ********* Initial DB Loader Test Begin *********");
		DataBaseHelper myDbHelper;
		myDbHelper = new DataBaseHelper(context);

		try {
			/*
			 * Creates a empty database on the system and rewrites it with your
			 * own database. if the database is already created, do nothing
			 */
			myDbHelper.createDataBase(context.getPackageName());
			log.info("CREATE DATA BASE = OK");
		} catch (IOException ioe) {
			ioe.printStackTrace();
			log.info("CREATE DATA BASE = FAIL");
		}

		try {
			myDbHelper.openDataBase(context.getPackageName());
			log.info("OPEN DATA BASE = OK");
		} catch (SQLException sqle) {
			sqle.printStackTrace();
			log.info("OPEN DATA BASE = FAIL");

		}
	}
}
