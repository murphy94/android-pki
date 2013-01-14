/**
 *  Created on  : 24/07/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Class that implements the methods for retrieving and modifying information
 * about CRL in the DB
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
import cinvestav.android.pki.db.dao.CRLDAO;
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.android.pki.db.dao.SubjectDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.android.pki.utils.DataBaseDictionary;

/**
 * Class that implements the methods for retrieving and modifying information
 * about CRL in the DB
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 24/07/2012
 * @version 1.0
 */
public class CRLDB extends DataBaseHelper {

	/**
	 * 
	 * @param context
	 * @param name
	 * @param factory
	 * @param version
	 */
	public CRLDB(Context context, String name, CursorFactory factory,
			int version) {
		super(context, name, factory, version);
	}

	/**
	 * Constructor that inits the data base connection using application context
	 * 
	 * @param context
	 */
	public CRLDB(Context context) {
		super(context);
	}

	/**
	 * Inserts a new CRL in the data base
	 * 
	 * @param crl
	 *            CRL to insert
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public Integer insert(CRLDAO crl) throws DBException {

		SQLiteDatabase db = this.getWritableDatabase();

		/*
		 * Sets the values to the contentValue object
		 */
		ContentValues values = new ContentValues();
		// Serial Number
		values.put(DataBaseDictionary.COLUMN_NAME_CRL_SERIAL_NUMBER,
				crl.getSerialNumber());
		// PublishDate
		values.put(DataBaseDictionary.COLUMN_NAME_CRL_PUBLISH_DATE,
				DataBaseDictionary.FORMATTER_DB.format(crl.getPublishDate()));
		// Description
		values.put(DataBaseDictionary.COLUMN_NAME_CRL_DESCRIPTION,
				crl.getDescription());

		// Issuer Certificate ID
		values.put(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_ID, crl
				.getIssuerCertificate().getId());

		values.put(DataBaseDictionary.COLUMN_NAME_CRL_DATA, crl.getCrlDataStr());

		try {
			// Inserting Row
			long newID = db.insertOrThrow(DataBaseDictionary.TABLE_CRL, null,
					values);
			// Closing database connection
			db.close();
			return (int) newID;
		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException(
					"Error while inserting into CRL table: " + ex, ex);
		}
	}

	/**
	 * Deletes a CRL from the data base
	 * 
	 * @param crl
	 *            CRLDAO that will be deleted, the register to be deleted will
	 *            be searched by id
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public void delete(CRLDAO crl) throws DBException {

		try {

			SQLiteDatabase db = this.getWritableDatabase();
			db.delete(DataBaseDictionary.TABLE_CRL,
					DataBaseDictionary.COLUMN_NAME_CRL_ID + " = ?",
					new String[] { String.valueOf(crl.getId()) });
			db.close();

		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException("Error while deleting CRL [id = "
					+ crl.getId() + "]:" + ex, ex);
		}

	}

	/**
	 * Gets the list of all the entries saved in the data base
	 * 
	 * @return A list of entries
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<CRLDAO> getAllCRLs() throws DBException {
		try {
			// Select All Query
			String selectQuery = DataBaseDictionary.GET_ALL_CRL;

			SQLiteDatabase db = this.getReadableDatabase();
			Cursor cursor = db.rawQuery(selectQuery, null);
			// Result processing
			List<CRLDAO> crls = new LinkedList<CRLDAO>();
			// looping through all rows and adding to list
			if (cursor.moveToFirst()) {
				// For each element in the result set, a new object is generated
				// and added to the list
				do {
					// The resultSet values are extracted using the column names
					CRLDAO crl = new CRLDAO();
					crl.setId(cursor.getInt(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CRL_ID)));
					crl.setCrlDataStr(cursor.getString(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CRL_DATA)));
					crl.setDescription(cursor.getString(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CRL_DESCRIPTION)));

					Date date;
					try {
						date = DataBaseDictionary.FORMATTER_DB
								.parse(cursor.getString(cursor
										.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CRL_PUBLISH_DATE)));
					} catch (ParseException e) {
						date = new Date(0);
					} catch (NullPointerException e) {
						date = new Date(0);
					}
					crl.setPublishDate(date);

					crl.setSerialNumber(cursor.getInt(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CRL_SERIAL_NUMBER)));

					// Query the issuer certificate information
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
							crl.setIssuerCertificate(certificate);
						}
					}
					crls.add(crl);
				} while (cursor.moveToNext());
			}
			cursor.close();
			db.close();
			return crls;
		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException("Error getting all CRLs : " + ex, ex);
		}
	}

	/**
	 * Gets a list of entries that were founded using the specified filter
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
	 * @return A list of entries that agrees with the filter
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<CRLDAO> getByAdvancedFilter(Map<String, String[]> filter)
			throws DBException {
		try {

			SQLiteDatabase db = this.getReadableDatabase();
			Cursor cursor = executeAdvancedQuery(filter,
					DataBaseDictionary.TABLE_CRL, db);

			// Result processing
			List<CRLDAO> crls = new LinkedList<CRLDAO>();
			// looping through all rows and adding to list
			if (cursor.moveToFirst()) {
				// For each element in the result set, a new object is generated
				// and added to the list
				do {
					// The resultSet values are extracted using the column names
					CRLDAO crl = new CRLDAO();
					crl.setId(cursor.getInt(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CRL_ID)));
					crl.setCrlDataStr(cursor.getString(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CRL_DATA)));
					crl.setDescription(cursor.getString(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CRL_DESCRIPTION)));

					Date date;
					try {
						date = DataBaseDictionary.FORMATTER_DB
								.parse(cursor.getString(cursor
										.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CRL_PUBLISH_DATE)));
					} catch (ParseException e) {
						date = new Date(0);
					} catch (NullPointerException e) {
						date = new Date(0);
					}
					crl.setPublishDate(date);

					crl.setSerialNumber(cursor.getInt(cursor
							.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CRL_SERIAL_NUMBER)));

					// Query the issuer certificate information
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
							crl.setIssuerCertificate(certificate);
						}
					}
					crls.add(crl);
				} while (cursor.moveToNext());
			}
			cursor.close();
			db.close();
			return crls;
		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException("Error getting CRLs : " + ex, ex);
		}
	}

	/**
	 * Get the total count of rows in CRL table
	 * 
	 * @return
	 */
	public Integer getCount() {
		String countQuery = "SELECT  * FROM " + DataBaseDictionary.TABLE_CRL;
		SQLiteDatabase db = this.getReadableDatabase();
		Cursor cursor = db.rawQuery(countQuery, null);
		Integer count = cursor.getCount();
		cursor.close();
		db.close();
		// return count
		return count;
	}

	/**
	 * Get the current Id in CRL table
	 * 
	 * @return An integer that represents the current id
	 */
	public Integer getCurrentId() {
		String countQuery = " SELECT MAX("
				+ DataBaseDictionary.COLUMN_NAME_CRL_ID + ") as id FROM "
				+ DataBaseDictionary.TABLE_CRL + ";";
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
