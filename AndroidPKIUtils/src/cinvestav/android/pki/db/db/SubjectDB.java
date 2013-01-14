/**
 *  Created on  : 23/07/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Class that implements the methods for retrieving and modifying information
 * about subjects in the DB
 */
package cinvestav.android.pki.db.db;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteDatabase.CursorFactory;
import cinvestav.android.pki.db.dao.SubjectDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.android.pki.utils.DataBaseDictionary;

/**
 * Class that implements the methods for retrieving and modifying information
 * about subjects in the DB
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 23/07/2012
 * @version 1.0
 */
public class SubjectDB extends DataBaseHelper {

	/**
	 * 
	 * @param context
	 * @param name
	 * @param factory
	 * @param version
	 */
	public SubjectDB(Context context, String name, CursorFactory factory,
			int version) {
		super(context, name, factory, version);
	}

	/**
	 * Constructor that inits the data base connection using application context
	 * 
	 * @param context
	 */
	public SubjectDB(Context context) {
		super(context);
	}

	/**
	 * Inserts a new Subject in the data base
	 * 
	 * @param subject
	 *            Subject to insert
	 * @return the Id of the row inserted in the data base
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public Integer insert(SubjectDAO subject) throws DBException {
		SQLiteDatabase db = this.getWritableDatabase();

		/*
		 * Sets the values to the contentValue object
		 */
		ContentValues values = new ContentValues();
		// Subject Name
		values.put(DataBaseDictionary.COLUMN_NAME_SUBJECT_NAME,
				subject.getName());
		// Subject Active = True = 1
		values.put(DataBaseDictionary.COLUMN_NAME_SUBJECT_ACTIVE, Boolean.TRUE
				+ "");

		values.put(DataBaseDictionary.COLUMN_NAME_SUBJECT_DEVICE,
				subject.getDeviceID());

		try {
			// Inserting Row
			long newID = db.insertOrThrow(DataBaseDictionary.TABLE_SUBJECT,
					null, values);
			// Closing database connection
			db.close();
			return (int) newID;
		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException("Error while inserting into Subject table: "
					+ ex, ex);
		} catch (IllegalStateException ex) {
			log.error(ex, ex);
			throw new DBException("Error while inserting into Subject table : "
					+ ex, ex);
		}
	}

	/**
	 * Updates the subject in the data base
	 * 
	 * @param subject
	 *            SubjectDAO with the updated fields, the only field that won't
	 *            be modified is the ID
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public void update(SubjectDAO subject) throws DBException {

		SQLiteDatabase db = this.getWritableDatabase();

		/*
		 * Sets the values to the contentValue object
		 */
		ContentValues values = new ContentValues();
		// Subject Name
		values.put(DataBaseDictionary.COLUMN_NAME_SUBJECT_NAME,
				subject.getName());

		// Device ID
		values.put(DataBaseDictionary.COLUMN_NAME_SUBJECT_DEVICE,
				subject.getDeviceID());

		try {
			// updating row
			db.update(DataBaseDictionary.TABLE_SUBJECT, values,
					DataBaseDictionary.COLUMN_NAME_SUBJECT_ID + " = ?",
					new String[] { String.valueOf(subject.getId()) });
			db.close();

		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException("Error while updating Subject [id = "
					+ subject.getId() + "]: " + ex, ex);
		} catch (IllegalStateException ex) {
			log.error(ex, ex);
			throw new DBException("Error while updating Subject [id = "
					+ subject.getId() + "]: " + ex, ex);
		}
	}

	/**
	 * Deletes a subject from the data base, in fact the subject registry will
	 * persist in the data base, but a flag of inactive subject will be raised
	 * 
	 * @param subject
	 *            SubjectDAO that will be deleted, the register to be deleted
	 *            will be searched by id
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public void delete(SubjectDAO subject) throws DBException {
		SQLiteDatabase db = this.getWritableDatabase();

		/*
		 * Sets the values to the contentValue object
		 */
		ContentValues values = new ContentValues();
		// Subject Name
		values.put(DataBaseDictionary.COLUMN_NAME_SUBJECT_ACTIVE, Boolean.FALSE
				+ "");

		try {
			// updating row
			db.update(DataBaseDictionary.TABLE_SUBJECT, values,
					DataBaseDictionary.COLUMN_NAME_SUBJECT_ID + " = ?",
					new String[] { String.valueOf(subject.getId()) });
			db.close();

		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException("Error while deleting Subject [id = "
					+ subject.getId() + "]: " + ex, ex);
		} catch (IllegalStateException ex) {
			log.error(ex, ex);
			throw new DBException("Error while deleting Subject [id = "
					+ subject.getId() + "]: " + ex, ex);
		}
	}

	/**
	 * Gets the list of all the subjects saved in the data base
	 * 
	 * @return A list of subjects
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<SubjectDAO> getAllSubjects() throws DBException {
		try {

			// Select All Query
			String selectQuery = DataBaseDictionary.GET_ALL_SUBJECT;

			SQLiteDatabase db = this.getReadableDatabase();
			Cursor cursor = db.rawQuery(selectQuery, null);
			// Result processing
			List<SubjectDAO> subjects = new LinkedList<SubjectDAO>();
			// looping through all rows and adding to list
			if (cursor.moveToFirst()) {
				// For each element in the result set, a new object is generated
				// and added to the list
				do {
					SubjectDAO subject = new SubjectDAO();
					subject.setId(cursor.getInt(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_SUBJECT_ID)));
					subject.setName(cursor.getString(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_SUBJECT_NAME)));
					subject.setActive(Boolean.parseBoolean(cursor.getString(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_SUBJECT_ACTIVE))));
					subject.setDeviceID(cursor.getString(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_SUBJECT_DEVICE)));

					subjects.add(subject);
				} while (cursor.moveToNext());
			}
			cursor.close();
			db.close();
			return subjects;
		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException("Error getting all Subjects : " + ex, ex);
		} catch (IllegalStateException ex) {
			log.error(ex, ex);
			throw new DBException("Error getting all Subjects : " + ex, ex);
		}
	}

	/**
	 * Gets a list of subjects that were founded using the specified filter
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
	 * @return A list of subjects that agrees with the filter
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<SubjectDAO> getByAdvancedFilter(Map<String, String[]> filter)
			throws DBException {
		try {
			SQLiteDatabase db = this.getReadableDatabase();
			Cursor cursor = executeAdvancedQuery(filter,
					DataBaseDictionary.TABLE_SUBJECT, db);

			// Result processing
			List<SubjectDAO> subjects = new LinkedList<SubjectDAO>();
			// looping through all rows and adding to list
			if (cursor.moveToFirst()) {
				// For each element in the result set, a new object is generated
				// and added to the list
				do {
					// The resultSet values are extracted using the column names
					SubjectDAO subject = new SubjectDAO();
					subject.setId(cursor.getInt(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_SUBJECT_ID)));
					subject.setName(cursor.getString(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_SUBJECT_NAME)));
					subject.setActive(Boolean.parseBoolean(cursor.getString(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_SUBJECT_ACTIVE))));
					subject.setDeviceID(cursor.getString(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_SUBJECT_DEVICE)));

					subjects.add(subject);

				} while (cursor.moveToNext());
			}
			cursor.close();
			db.close();
			return subjects;
		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException("Error getting Subjects : " + ex, ex);
		} catch (IllegalStateException ex) {
			log.error(ex, ex);
			throw new DBException("Error getting Subjects : " + ex, ex);
		}
	}

	/**
	 * Get the total count of rows in Subject table
	 * 
	 * @return
	 */
	public Integer getCount() {
		String countQuery = "SELECT  * FROM "
				+ DataBaseDictionary.TABLE_SUBJECT;
		SQLiteDatabase db = this.getReadableDatabase();
		Cursor cursor = db.rawQuery(countQuery, null);
		Integer count = cursor.getCount();
		cursor.close();
		db.close();
		// return count
		return count;
	}

	/**
	 * Get the current Id in Subject table
	 * 
	 * @return An integer that represents the current id
	 */
	public Integer getCurrentId() {
		String countQuery = " SELECT MAX("
				+ DataBaseDictionary.COLUMN_NAME_SUBJECT_ID + ") as id FROM "
				+ DataBaseDictionary.TABLE_SUBJECT + ";";
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
