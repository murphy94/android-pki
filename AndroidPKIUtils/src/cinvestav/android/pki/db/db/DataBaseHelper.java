/**
 *  Created on  : 06/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Class that will be used for read the default SQLite database, for the pki utility, the data base
 *  file is in assets folder and will be written to the default system folder, so the application can read its
 *  content
 */
package cinvestav.android.pki.db.db;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;

import android.content.Context;
import android.database.Cursor;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteDatabase.CursorFactory;
import android.database.sqlite.SQLiteException;
import android.database.sqlite.SQLiteOpenHelper;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.android.pki.utils.DataBaseDictionary;
import cinvestav.android.pki.utils.LogUtil;

/**
 * Class that will be used for read the default SQLite database, for the pki
 * utility, the data base file is in assets folder and will be written to the
 * default system folder, so the application can read its content
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 06/08/2012
 * @version 1.0
 */
public class DataBaseHelper extends SQLiteOpenHelper {

	// The Android's default system path of your application database.
	// protected static String DB_PATH = "/data/data/"
	// + DataBaseDictionary.PACKAGE_NAME + "/databases/";

	protected static String DB_NAME = DataBaseDictionary.DATABASE_NAME
			+ ".sqlite";

	protected SQLiteDatabase myDataBase;

	protected final Context myContext;

	protected static LogUtil log = new LogUtil("ANDROID_PKI_UTILS");

	/**
	 * @param context
	 * @param name
	 * @param factory
	 * @param version
	 */
	public DataBaseHelper(Context context, String name, CursorFactory factory,
			int version) {
		super(context, name, factory, version);
		this.myContext = context;
	}

	/**
	 * Constructor Takes and keeps a reference of the passed context in order to
	 * access to the application assets and resources.
	 * 
	 * @param context
	 */
	public DataBaseHelper(Context context) {
		super(context, DB_NAME, null, 1);
		this.myContext = context;
	}

	/**
	 * Creates a empty database on the system and rewrites it with your own
	 * database. if the database is already created, do nothing
	 * 
	 * @param packageName
	 *            Application package name
	 * 
	 * @throws IOException
	 *             If the database file could not be read from assets directory
	 */
	public void createDataBase(String packageName) throws IOException {

		boolean dbExist = checkDataBase(packageName);

		if (dbExist) {
			// do nothing - database already exist
		} else {

			// By calling this method and empty database will be created into
			// the default system path
			// of your application so we are gonna be able to overwrite that
			// database with our database.
			this.getReadableDatabase();

			try {

				copyDataBase(packageName);

			} catch (IOException e) {

				throw new Error("Error copying database: " + e);

			}
			this.close();
		}

	}

	/**
	 * Check if the database already exist to avoid re-copying the file each
	 * time you open the application.
	 * 
	 * @return true if it exists, false if it doesn't
	 */
	protected boolean checkDataBase(String packageName) {

		SQLiteDatabase checkDB = null;

		try {
			String myPath = "/data/data/" + packageName + "/databases/"
					+ DB_NAME;
			checkDB = SQLiteDatabase.openDatabase(myPath, null,
					SQLiteDatabase.OPEN_READONLY);

		} catch (SQLiteException e) {

			// database does't exist yet.

		}

		if (checkDB != null) {

			checkDB.close();

		}

		return checkDB != null ? true : false;
	}

	/**
	 * Copies your database from your local assets-folder to the just created
	 * empty database in the system folder, from where it can be accessed and
	 * handled. This is done by transfering bytestream.
	 * 
	 * @param packageName
	 *            Application package name
	 * 
	 * @throws IOException
	 *             If the database file could no be read in the assets directory
	 *             of the application
	 */
	protected void copyDataBase(String packageName) throws IOException {

		// Open your local db as the input stream
		// AssetManager manager = myContext.getAssets();

		InputStream myInput = myContext.getAssets().open(DB_NAME);

		// Path to the just created empty db
		String outFileName = "/data/data/" + packageName + "/databases/"
				+ DB_NAME;

		// Open the empty db as the output stream
		OutputStream myOutput = new FileOutputStream(outFileName);

		// transfer bytes from the inputfile to the outputfile
		byte[] buffer = new byte[1024];
		int length;
		while ((length = myInput.read(buffer)) > 0) {
			myOutput.write(buffer, 0, length);
		}

		// Close the streams
		myOutput.flush();
		myOutput.close();
		myInput.close();

	}

	/**
	 * Opens the default data base
	 * 
	 * @param packageName
	 *            Application package name
	 * 
	 * @throws SQLException
	 *             If the data base could not be opened from the system
	 *             directory
	 */
	public void openDataBase(String packageName) throws SQLException {

		// Open the database
		String myPath = "/data/data/" + packageName + "/databases/" + DB_NAME;
		myDataBase = SQLiteDatabase.openDatabase(myPath, null,
				SQLiteDatabase.OPEN_READWRITE);
		myDataBase.close();
	}

	@Override
	public synchronized void close() {

		if (myDataBase != null)
			myDataBase.close();

		super.close();

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * android.database.sqlite.SQLiteOpenHelper#onCreate(android.database.sqlite
	 * .SQLiteDatabase)
	 */
	@Override
	public void onCreate(SQLiteDatabase arg0) {
		// TODO Auto-generated method stub

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * android.database.sqlite.SQLiteOpenHelper#onUpgrade(android.database.sqlite
	 * .SQLiteDatabase, int, int)
	 */
	@Override
	public void onUpgrade(SQLiteDatabase arg0, int arg1, int arg2) {
		// TODO Auto-generated method stub

	}

	/**
	 * Generates a PreparedStatement from a filters map, a connection and a base
	 * statement
	 * 
	 * @param filters
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
	 * @param c
	 *            Connection for the PreparedStatement
	 * @param statement
	 *            Base SQL statement for the PreparedStatement
	 * @return If every thing goes ok a PreparedStatemt ready to be executed
	 * @throws DBException
	 *             If something goes wrong during the Prepared Statement
	 *             construction
	 */
	protected Cursor executeAdvancedQuery(Map<String, String[]> filters,
			String tableName, SQLiteDatabase db) throws SQLException {

		// Flag for the first filter
		Boolean ini = Boolean.TRUE;
		String statement = "";
		// The filters map is iterated in order to creates a dynamic SQL WHERE
		// CLAUSE
		// statement
		for (Map.Entry<String, String[]> entry : filters.entrySet()) {
			// entry - Has every entry of the map, one at the time
			// If isn't the first element in the where clause AND is added
			if (ini) {
				// The filter in the map is added, using the defined alias
				statement += " " + entry.getKey();
				ini = Boolean.FALSE;
			} else {
				statement += " AND " + entry.getKey();
			}
		}

		statement += " ";

		// log.info(statement);

		String[] filterArray = new String[filters.entrySet().size()];

		// Create the filter values array, filled with the values saved in the
		// filter map
		// The index for the filter array
		int cont = 0;
		// Again the filter map is iterated
		for (Map.Entry<String, String[]> entry : filters.entrySet()) {
			String[] val = entry.getValue();
			// Depending on the data type, the values is aggregated to the ps
			if (val[1].compareTo(DataBaseDictionary.STRING_SIMPLE) == 0) {
				// If the type is 'String_SIMPLE', the search is made with '='
				filterArray[cont] = val[0];
			} else if (val[1].compareTo(DataBaseDictionary.STRING_JOKER) == 0) {
				// In this case the search will be made using LIKE and the joker
				// '%'
				// is added at the end of the search value
				filterArray[cont] = val[0] + "%";
			} else if (val[1].compareTo(DataBaseDictionary.STRING_DOBLE_JOKER) == 0) {
				// In this case the search will be made using LIKE and the joker
				// '%'
				// is added at the end and the beginning of the search value
				filterArray[cont] = "%" + val[0] + "%";
			} else if (val[1].compareTo(DataBaseDictionary.NUMBER_TYPE) == 0) {
				// If is Number
				filterArray[cont] = val[0];
			}/*
			 * else if (val[1].compareTo(DataBaseDictionary.DOUBLE_TYPE) == 0) {
			 * // For Double filterArray[cont] = val[0]; } else if
			 * (val[1].compareTo(DataBaseDictionary.DATE_TYPE) == 0){ // For
			 * Date values filterArray[cont] = val[0]; } else
			 * if(val[1].compareTo(DataBaseDictionary.TIME_TYPE)==0){ //For Time
			 * values filterArray[cont] = val[0]; }else
			 * if(val[1].compareTo(DataBaseDictionary.BOOLEAN_TYPE)==0){ //For
			 * Boolean values filterArray[cont] = val[0]; }
			 */
			cont++;
		}

		return db.query(tableName, null, statement, filterArray, null, null,
				null, null);
	}
}
