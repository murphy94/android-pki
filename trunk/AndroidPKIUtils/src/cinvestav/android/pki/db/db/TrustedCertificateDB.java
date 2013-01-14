/**
 *  Created on  : 24/07/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Class that implements the methods for retrieving and modifying information
 * about trusted Certificates linked to a trustedCertificate in the DB
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
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.android.pki.db.dao.SubjectDAO;
import cinvestav.android.pki.db.dao.TrustedCertificateDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.android.pki.utils.DataBaseDictionary;

/**
 * Class that implements the methods for retrieving and modifying information
 * about trusted Certificates linked to a trustedCertificate in the DB
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 24/07/2012
 * @version 1.0
 */
public class TrustedCertificateDB extends DataBaseHelper {

	/**
	 * 
	 * @param context
	 * @param name
	 * @param factory
	 * @param version
	 */
	public TrustedCertificateDB(Context context, String name,
			CursorFactory factory, int version) {
		super(context, name, factory, version);
	}

	/**
	 * Constructor that inits the data base connection using application context
	 * 
	 * @param context
	 */
	public TrustedCertificateDB(Context context) {
		super(context);
	}

	/**
	 * Inserts a new TrustedCertificate in the data base
	 * 
	 * @param trustedCertificate
	 *            TrustedCertificate to insert
	 * @param subjectID
	 *            Subject to which the trusted certificate will be linked to
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public Integer insert(TrustedCertificateDAO trustedCertificate,
			Integer subjectID) throws DBException {

		SQLiteDatabase db = this.getWritableDatabase();

		/*
		 * Sets the values to the contentValue object
		 */
		ContentValues values = new ContentValues();
		// Trust Level
		values.put(DataBaseDictionary.COLUMN_NAME_TRUSTED_CERTIFICATE_LEVEL,
				trustedCertificate.getTrustLevel());
		// Subject ID
		values.put(DataBaseDictionary.COLUMN_NAME_SUBJECT_ID, subjectID + "");
		// Trusted Certificate ID
		values.put(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_ID,
				trustedCertificate.getTrustedCertificate().getId());

		try {
			// Inserting Row
			long newID = db.insertOrThrow(
					DataBaseDictionary.TABLE_TRUSTED_CERTIFICATE, null, values);
			// Closing database connection
			db.close();
			return (int) newID;
		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException(
					"Error while inserting into TrustedCertificate table: "
							+ ex, ex);
		}
	}

	/**
	 * Updates the trustedCertificate in the data base
	 * 
	 * @param trustedCertificate
	 *            TrustedCertificateDAO with the updated fields, the only field
	 *            that won't be modified is the ID
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public void update(TrustedCertificateDAO trustedCertificate)
			throws DBException {

		SQLiteDatabase db = this.getWritableDatabase();

		/*
		 * Sets the values to the contentValue object
		 */
		ContentValues values = new ContentValues();
		// Trust Level
		values.put(DataBaseDictionary.COLUMN_NAME_TRUSTED_CERTIFICATE_LEVEL,
				trustedCertificate.getTrustLevel());

		try {
			// updating row
			db.update(DataBaseDictionary.TABLE_TRUSTED_CERTIFICATE, values,
					DataBaseDictionary.COLUMN_NAME_TRUSTED_CERTIFICATE_ID
							+ " = ?",
					new String[] { String.valueOf(trustedCertificate.getId()) });
			db.close();

		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException("Error while updating Subject [id = "
					+ trustedCertificate.getId() + "]: " + ex, ex);
		}

	}

	/**
	 * Deletes a trustedCertificate from the data base
	 * 
	 * @param trustedCertificate
	 *            TrustedCertificateDAO that will be deleted, the register to be
	 *            deleted will be searched by id
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public void delete(TrustedCertificateDAO trustedCertificate)
			throws DBException {

		try {

			SQLiteDatabase db = this.getWritableDatabase();
			db.delete(DataBaseDictionary.TABLE_TRUSTED_CERTIFICATE,
					DataBaseDictionary.COLUMN_NAME_TRUSTED_CERTIFICATE_ID
							+ " = ?",
					new String[] { String.valueOf(trustedCertificate.getId()) });
			db.close();

		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException(
					"Error while deleting TrustedCertificate [id = "
							+ trustedCertificate.getId() + "]:" + ex, ex);
		}

	}

	/**
	 * Gets the list of all the trustedCertificates saved in the data base
	 * 
	 * @return A list of trustedCertificates
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<TrustedCertificateDAO> getAllTrustedCertificates()
			throws DBException {
		try {

			// Select All Query
			String selectQuery = DataBaseDictionary.GET_ALL_TRUSTED_CERTIFICATE;

			SQLiteDatabase db = this.getReadableDatabase();
			Cursor cursor = db.rawQuery(selectQuery, null);
			// Result processing
			List<TrustedCertificateDAO> trustedCertificates = new LinkedList<TrustedCertificateDAO>();
			// looping through all rows and adding to list
			if (cursor.moveToFirst()) {
				// For each element in the result set, a new object is generated
				// and added to the list
				do {
					TrustedCertificateDAO trustedCertificate = new TrustedCertificateDAO();
					trustedCertificate
							.setId(cursor.getInt(cursor
									.getColumnIndex(DataBaseDictionary.COLUMN_NAME_TRUSTED_CERTIFICATE_ID)));
					trustedCertificate
							.setTrustLevel(cursor.getInt(cursor
									.getColumnIndex(DataBaseDictionary.COLUMN_NAME_TRUSTED_CERTIFICATE_LEVEL)));

					// Query the trusted certificate information
					Cursor cursorAux = db
							.query(DataBaseDictionary.TABLE_CERTIFICATE,
									null,
									DataBaseDictionary.COLUMN_NAME_CERTIFICATE_ID
											+ "=?",
									new String[] { cursor.getString(cursor
											.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_ID)) },
									null, null, null, null);

					if (cursorAux != null) {
						Boolean res = cursorAux.moveToFirst();
						if (res) {

							CertificateDAO certificate = new CertificateDAO();

							certificate
									.setId(cursorAux.getInt(cursorAux
											.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_ID)));
							certificate
									.setCertificateStr(cursorAux.getString(cursorAux
											.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_DATA)));
							certificate
									.setSerialNumber(cursorAux.getInt(cursorAux
											.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_SERIAL_NUMBER)));
							certificate
									.setStatus(cursorAux.getInt(cursorAux
											.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_STATUS)));
							certificate
									.setSignDeviceId(cursorAux.getString(cursorAux
											.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_SIGN_DEVICE)));

							certificate
									.setSubjectKeyId(cursorAux.getString(cursorAux
											.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_SUBJET_KEY_ID)));

							Date date;
							try {
								date = DataBaseDictionary.FORMATTER_DB
										.parse(cursorAux.getString(cursorAux
												.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_LAST_UPDATE)));

							} catch (ParseException e) {
								date = new Date(0);
							} catch (NullPointerException e) {
								date = new Date(0);
							}
							certificate.setLastStatusUpdateDate(date);
							certificate.setCaCertificate(new CertificateDAO());
							certificate.setOwner(new SubjectDAO());
							trustedCertificate
									.setTrustedCertificate(certificate);
						}
					}
					trustedCertificates.add(trustedCertificate);

				} while (cursor.moveToNext());
			}
			cursor.close();
			db.close();
			return trustedCertificates;
		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException("Error getting all TrustedCertificates : "
					+ ex, ex);
		}
	}

	/**
	 * Gets a list of trustedCertificates that were founded using the specified
	 * filter
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
	 * @return A list of trustedCertificates that agrees with the filter
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<TrustedCertificateDAO> getByAdvancedFilter(
			Map<String, String[]> filter) throws DBException {
		try {
			SQLiteDatabase db = this.getReadableDatabase();
			Cursor cursor = executeAdvancedQuery(filter,
					DataBaseDictionary.TABLE_TRUSTED_CERTIFICATE, db);

			// Result processing
			List<TrustedCertificateDAO> trustedCertificates = new LinkedList<TrustedCertificateDAO>();
			// looping through all rows and adding to list
			if (cursor.moveToFirst()) {
				// For each element in the result set, a new object is generated
				// and added to the list
				do {
					TrustedCertificateDAO trustedCertificate = new TrustedCertificateDAO();
					trustedCertificate
							.setId(cursor.getInt(cursor
									.getColumnIndex(DataBaseDictionary.COLUMN_NAME_TRUSTED_CERTIFICATE_ID)));
					trustedCertificate
							.setTrustLevel(cursor.getInt(cursor
									.getColumnIndex(DataBaseDictionary.COLUMN_NAME_TRUSTED_CERTIFICATE_LEVEL)));

					// Query the trusted certificate information
					Cursor cursorAux = db
							.query(DataBaseDictionary.TABLE_CERTIFICATE,
									null,
									DataBaseDictionary.COLUMN_NAME_CERTIFICATE_ID
											+ "=?",
									new String[] { cursor.getString(cursor
											.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_ID)) },
									null, null, null, null);

					if (cursorAux != null) {
						Boolean res = cursorAux.moveToFirst();
						if (res) {

							CertificateDAO certificate = new CertificateDAO();

							certificate
									.setId(cursorAux.getInt(cursorAux
											.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_ID)));
							certificate
									.setCertificateStr(cursorAux.getString(cursorAux
											.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_DATA)));
							certificate
									.setSerialNumber(cursorAux.getInt(cursorAux
											.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_SERIAL_NUMBER)));
							certificate
									.setStatus(cursorAux.getInt(cursorAux
											.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_STATUS)));

							certificate
									.setSignDeviceId(cursorAux.getString(cursorAux
											.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_SIGN_DEVICE)));

							certificate
									.setSubjectKeyId(cursorAux.getString(cursorAux
											.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_SUBJET_KEY_ID)));

							Date date;
							try {
								date = DataBaseDictionary.FORMATTER_DB
										.parse(cursorAux.getString(cursorAux
												.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_LAST_UPDATE)));

							} catch (ParseException e) {
								date = new Date(0);
							} catch (NullPointerException e) {
								date = new Date(0);
							}
							certificate.setLastStatusUpdateDate(date);
							certificate.setCaCertificate(new CertificateDAO());
							certificate.setOwner(new SubjectDAO());
							trustedCertificate
									.setTrustedCertificate(certificate);
						}
					}
					trustedCertificates.add(trustedCertificate);
				} while (cursor.moveToNext());
			}
			cursor.close();
			db.close();
			return trustedCertificates;
		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException("Error getting TrustedCertificates : " + ex,
					ex);
		}
	}

	/**
	 * Get the total count of rows in Trusted Certificate table
	 * 
	 * @return
	 */
	public Integer getCount() {
		String countQuery = "SELECT  * FROM "
				+ DataBaseDictionary.TABLE_TRUSTED_CERTIFICATE;
		SQLiteDatabase db = this.getReadableDatabase();
		Cursor cursor = db.rawQuery(countQuery, null);
		Integer count = cursor.getCount();
		cursor.close();
		db.close();
		// return count
		return count;
	}

	/**
	 * Get the current Id in TrustedCertificate table
	 * 
	 * @return An integer that represents the current id
	 */
	public Integer getCurrentId() {
		String countQuery = " SELECT MAX("
				+ DataBaseDictionary.COLUMN_NAME_TRUSTED_CERTIFICATE_ID
				+ ") as id FROM "
				+ DataBaseDictionary.TABLE_TRUSTED_CERTIFICATE + ";";
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
