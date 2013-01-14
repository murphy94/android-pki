/**
 *  Created on  : 22/07/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Class that implements the methods for retrieving and modifying information
 * about keys in the DB
 */
package cinvestav.android.pki.db.db;

import java.text.ParseException;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteDatabase.CursorFactory;
import cinvestav.android.pki.db.dao.PersonalKeyDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.android.pki.utils.DataBaseDictionary;

/**
 * Class that implements the methods for retrieving and modifying information
 * about keys in the DB
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 22/07/2012
 * @version 1.0
 */
public class PersonalKeyDB extends DataBaseHelper {

	/**
	 * 
	 * @param context
	 * @param name
	 * @param factory
	 * @param version
	 */
	public PersonalKeyDB(Context context, String name, CursorFactory factory,
			int version) {
		super(context, name, factory, version);
	}

	/**
	 * Constructor that inits the data base connection using application context
	 * 
	 * @param context
	 */
	public PersonalKeyDB(Context context) {
		super(context);
	}

	/**
	 * Inserts a new Key in the data base
	 * 
	 * @param key
	 *            Key to insert
	 * @param ownerID
	 *            If of the owner of this key
	 * @return the Id of the row inserted in the data base
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public Integer insert(PersonalKeyDAO key, Integer ownerID)
			throws DBException {
		SQLiteDatabase db = this.getWritableDatabase();

		/*
		 * Sets the values to the contentValue object
		 */
		ContentValues values = new ContentValues();
		// Key Data
		values.put(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_DATA,
				key.getKeyStr());
		// Key Unique id
		values.put(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_KEYID,
				key.getKeyID());
		// Key Type
		values.put(DataBaseDictionary.COLUMN_NAME_SUBJECT_ID, ownerID);
		// Owner ID
		values.put(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_TYPE,
				key.getKeyType());

		// Creation date
		values.put(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_CREATION_DATE,
				DataBaseDictionary.FORMATTER_DB.format(new Date()));
		// Comment
		values.put(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_COMMENT,
				key.getComment());

		try {
			// Inserting Row
			long newID = db.insertOrThrow(
					DataBaseDictionary.TABLE_PERSONAL_KEY, null, values);
			// Closing database connection
			db.close();
			return (int) newID;
		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException(
					"Error while inserting into PersonalKey table: " + ex, ex);
		}

	}

	/**
	 * Updates the key in the data base
	 * 
	 * @param key
	 *            PersonalKeyDAO with the updated fields, the only field that
	 *            won't be modified is the ID
	 * @param ownerID
	 *            If of the owner of this key
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public void update(PersonalKeyDAO key, Integer ownerID) throws DBException {
		try {

			SQLiteDatabase db = this.getWritableDatabase();

			/*
			 * Sets the values to the contentValue object
			 */
			ContentValues values = new ContentValues();
			// Key Data
			values.put(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_DATA,
					key.getKeyStr());
			// Key Unique id
			values.put(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_KEYID,
					key.getKeyID());
			// Key Type
			values.put(DataBaseDictionary.COLUMN_NAME_SUBJECT_ID, ownerID);
			// Owner ID
			values.put(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_TYPE,
					key.getKeyType());
			// Comment
			values.put(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_COMMENT,
					key.getComment());

			// Creation date
			values.put(
					DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_CREATION_DATE,
					DataBaseDictionary.FORMATTER_DB.format(key
							.getCreationDate()));

			// updating row
			db.update(DataBaseDictionary.TABLE_PERSONAL_KEY, values,
					DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_ID + " = ?",
					new String[] { String.valueOf(key.getId()) });
			db.close();

		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException("Error while updating PersonalKey: " + ex, ex);
		}
	}

	/**
	 * Deletes a key from the data base
	 * 
	 * @param key
	 *            PersonalKeyDAO that will be deleted, the register to be
	 *            deleted will be searched by id
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public void delete(PersonalKeyDAO key) throws DBException {
		try {

			SQLiteDatabase db = this.getWritableDatabase();
			db.delete(DataBaseDictionary.TABLE_PERSONAL_KEY,
					DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_ID + " = ?",
					new String[] { String.valueOf(key.getId()) });
			db.close();

		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException("Error while deleting PersonalKey [id = "
					+ key.getId() + "]:" + ex, ex);
		}
	}

	/**
	 * Get the total count of rows in PersonalKey table
	 * 
	 * @return
	 */
	public Integer getCount() {
		String countQuery = "SELECT  * FROM "
				+ DataBaseDictionary.TABLE_PERSONAL_KEY;
		SQLiteDatabase db = this.getReadableDatabase();
		Cursor cursor = db.rawQuery(countQuery, null);
		Integer count = cursor.getCount();
		cursor.close();
		db.close();
		// return count
		return count;
	}

	/**
	 * Gets the list of all the keys saved in the data base
	 * 
	 * @return A list of keys
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<PersonalKeyDAO> getAllPersonalKeys() throws DBException {
		try {

			// Select All Query
			String selectQuery = DataBaseDictionary.GET_ALL_PERSONALKEY;

			SQLiteDatabase db = this.getReadableDatabase();
			Cursor cursor = db.rawQuery(selectQuery, null);
			// Result processing
			List<PersonalKeyDAO> keys = new LinkedList<PersonalKeyDAO>();
			// looping through all rows and adding to list
			if (cursor.moveToFirst()) {
				// For each element in the result set, a new object is generated
				// and added to the list
				do {
					PersonalKeyDAO key = new PersonalKeyDAO();
					key.setId(cursor.getInt(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_ID)));
					key.setKeyID(cursor.getString(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_KEYID)));
					key.setKeyStr(cursor.getString(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_DATA)));
					key.setKeyType(cursor.getInt(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_TYPE)));
					key.setComment(cursor.getString(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_COMMENT)));
					key.setSubjectId(cursor.getInt(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_SUBJECT_ID)));

					Date date;
					try {
						date = DataBaseDictionary.FORMATTER_DB
								.parse(cursor.getString(cursor
										.getColumnIndex(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_CREATION_DATE)));

					} catch (ParseException e) {
						date = new Date(0);
					} catch (NullPointerException e) {
						date = new Date(0);
					}
					key.setCreationDate(date);

					keys.add(key);
				} while (cursor.moveToNext());
			}
			cursor.close();
			db.close();
			return keys;
		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException("Error getting all PersonalKeys : " + ex, ex);
		}
	}

	/**
	 * Gets a list of keys that were founded using the specified filter
	 * 
	 * @param filter
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
	 * @return A list of keys that agrees with the filter
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */

	public List<PersonalKeyDAO> getByAdvancedFilter(Map<String, String[]> filter)
			throws DBException {

		try {

			SQLiteDatabase db = this.getReadableDatabase();
			Cursor cursor = executeAdvancedQuery(filter,
					DataBaseDictionary.TABLE_PERSONAL_KEY, db);

			// Result processing
			List<PersonalKeyDAO> keys = new LinkedList<PersonalKeyDAO>();
			// looping through all rows and adding to list
			if (cursor.moveToFirst()) {
				// For each element in the result set, a new object is generated
				// and added to the list
				do {
					PersonalKeyDAO key = new PersonalKeyDAO();
					key.setId(cursor.getInt(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_ID)));
					key.setKeyID(cursor.getString(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_KEYID)));
					key.setKeyStr(cursor.getString(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_DATA)));
					key.setKeyType(cursor.getInt(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_TYPE)));
					key.setComment(cursor.getString(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_COMMENT)));
					key.setSubjectId(cursor.getInt(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_SUBJECT_ID)));
					Date date;
					try {
						date = DataBaseDictionary.FORMATTER_DB
								.parse(cursor.getString(cursor
										.getColumnIndex(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_CREATION_DATE)));

					} catch (ParseException e) {
						date = new Date(0);
					} catch (NullPointerException e) {
						date = new Date(0);
					}
					key.setCreationDate(date);
					keys.add(key);
				} while (cursor.moveToNext());
			}
			cursor.close();
			db.close();
			return keys;
		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException("Error getting PersonalKeys : " + ex, ex);
		}
	}

	/**
	 * Searches all the private keys that belongs to the selected subject, a
	 * private key could be a RSA, EC private key or PKCS ones
	 * 
	 * @param holderId
	 *            Id of the subject of which the keys must be searched
	 * @return a list of PersonalKeyDAO elements
	 * @throws DBException
	 */
	public List<PersonalKeyDAO> getAllPrivateKeys(Integer subjectId)
			throws DBException {
		try {
			SQLiteDatabase db = this.getReadableDatabase();
			String statement = " ("
					+ DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_TYPE + "="
					+ PersonalKeyDAO.PKCS12_EC + " OR "
					+ DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_TYPE + "="
					+ PersonalKeyDAO.PKCS12_RSA + " OR "
					+ DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_TYPE + "="
					+ PersonalKeyDAO.PRIVATE_RSA + " OR "
					+ DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_TYPE + "="
					+ PersonalKeyDAO.PRIVATE_EC + ") AND "
					+ DataBaseDictionary.COLUMN_NAME_SUBJECT_ID + "=?";
			String[] filterArray = { subjectId + "" };

			Cursor cursor = db.query(DataBaseDictionary.TABLE_PERSONAL_KEY,
					null, statement, filterArray, null, null, null, null);

			// Result processing
			List<PersonalKeyDAO> keys = new LinkedList<PersonalKeyDAO>();
			// looping through all rows and adding to list
			if (cursor.moveToFirst()) {
				// For each element in the result set, a new object is generated
				// and added to the list
				do {
					PersonalKeyDAO key = new PersonalKeyDAO();
					key.setId(cursor.getInt(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_ID)));
					key.setKeyID(cursor.getString(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_KEYID)));
					key.setKeyStr(cursor.getString(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_DATA)));
					key.setKeyType(cursor.getInt(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_TYPE)));
					key.setComment(cursor.getString(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_COMMENT)));
					key.setSubjectId(cursor.getInt(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_SUBJECT_ID)));
					Date date;
					try {
						date = DataBaseDictionary.FORMATTER_DB
								.parse(cursor.getString(cursor
										.getColumnIndex(DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_CREATION_DATE)));

					} catch (ParseException e) {
						date = new Date(0);
					} catch (NullPointerException e) {
						date = new Date(0);
					}
					key.setCreationDate(date);
					keys.add(key);
				} while (cursor.moveToNext());
			}
			cursor.close();
			db.close();
			return keys;
		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException("Error getting PersonalKeys : " + ex, ex);
		}
	}

	/**
	 * Get the current Id in PersonalKey table
	 * 
	 * @return An integer that represents the current id
	 */
	public Integer getCurrentId() {
		String countQuery = " SELECT MAX("
				+ DataBaseDictionary.COLUMN_NAME_PERSONAL_KEY_ID
				+ ") as id FROM " + DataBaseDictionary.TABLE_PERSONAL_KEY + ";";
		SQLiteDatabase db = this.getReadableDatabase();
		Cursor cursor = db.rawQuery(countQuery, null);
		Integer id = 0;
		if (cursor.moveToFirst()) {
			id = cursor.getInt(0);
		}
		cursor.close();
		db.close();
		// return count
		return id;
	}
}
