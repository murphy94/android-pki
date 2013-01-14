/**
 *  Created on  : 23/07/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Class that implements the methods for retrieving and modifying information
 * about certificates in the DB
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
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.android.pki.utils.DataBaseDictionary;

/**
 * Class that implements the methods for retrieving and modifying information
 * about certificates in the DB
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 23/07/2012
 * @version 1.0
 */
public class CertificateDB extends DataBaseHelper {

	/**
	 * 
	 * @param context
	 * @param name
	 * @param factory
	 * @param version
	 */
	public CertificateDB(Context context, String name, CursorFactory factory,
			int version) {
		super(context, name, factory, version);
	}

	/**
	 * Constructor that inits the data base connection using application context
	 * 
	 * @param context
	 */
	public CertificateDB(Context context) {
		super(context);
	}

	/**
	 * Inserts a new Certificate in the data base
	 * 
	 * @param certificate
	 *            Certificate to insert
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public Integer insert(CertificateDAO certificate) throws DBException {

		SQLiteDatabase db = this.getWritableDatabase();

		/*
		 * Sets the values to the contentValue object
		 */
		ContentValues values = new ContentValues();
		// Certificate Data
		values.put(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_DATA,
				certificate.getCertificateStr());
		// Serial Number
		values.put(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_SERIAL_NUMBER,
				certificate.getSerialNumber());
		// Owner ID
		values.put(DataBaseDictionary.COLUMN_NAME_SUBJECT_ID, certificate
				.getOwner().getId());
		// CA Certificate ID
		values.put(
				DataBaseDictionary.COLUMN_NAME_CERTIFICATE_CA_CERITIFICATE_ID,
				certificate.getCaCertificate().getId());

		// Status
		values.put(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_STATUS,
				certificate.getStatus());

		// Sign Device Id
		values.put(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_SIGN_DEVICE,
				certificate.getSignDeviceId());

		// Subject Key Id
		values.put(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_SUBJET_KEY_ID,
				certificate.getSubjectKeyId());

		// Last status update date
		values.put(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_LAST_UPDATE,
				DataBaseDictionary.FORMATTER_DB.format(new Date()));

		try {
			// Inserting Row
			long newID = db.insertOrThrow(DataBaseDictionary.TABLE_CERTIFICATE,
					null, values);
			// Closing database connection
			db.close();
			return (int) newID;
		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException(
					"Error while inserting into Cerificate table: " + ex, ex);
		}
	}

	/**
	 * Updates the certificate in the data base
	 * 
	 * @param certificate
	 *            CertificateDAO with the updated fields, the only field that
	 *            won't be modified is the ID
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public void update(CertificateDAO certificate) throws DBException {
		try {

			SQLiteDatabase db = this.getWritableDatabase();

			/*
			 * Sets the values to the contentValue object
			 */
			ContentValues values = new ContentValues();
			// Certificate Data
			values.put(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_DATA,
					certificate.getCertificateStr());
			// Serial Number
			values.put(
					DataBaseDictionary.COLUMN_NAME_CERTIFICATE_SERIAL_NUMBER,
					certificate.getSerialNumber());
			// Owner ID
			values.put(DataBaseDictionary.COLUMN_NAME_SUBJECT_ID, certificate
					.getOwner().getId());
			// CA Certificate ID
			values.put(
					DataBaseDictionary.COLUMN_NAME_CERTIFICATE_CA_CERITIFICATE_ID,
					certificate.getCaCertificate().getId());

			// Status
			values.put(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_STATUS,
					certificate.getStatus());

			// Last status update date
			values.put(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_LAST_UPDATE,
					DataBaseDictionary.FORMATTER_DB.format(new Date()));

			// Sign Device Id
			values.put(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_SIGN_DEVICE,
					certificate.getSignDeviceId());

			// Subject Key Id
			values.put(
					DataBaseDictionary.COLUMN_NAME_CERTIFICATE_SUBJET_KEY_ID,
					certificate.getSubjectKeyId());

			// updating row
			db.update(DataBaseDictionary.TABLE_CERTIFICATE, values,
					DataBaseDictionary.COLUMN_NAME_CERTIFICATE_ID + " = ?",
					new String[] { String.valueOf(certificate.getId()) });
			db.close();

		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException("Error while updating Certificate: " + ex, ex);
		}
	}

	/**
	 * Updates the certificate status in the data base
	 * 
	 * @param certificate
	 *            CertificateDAO with the updated Status, just this field will
	 *            be updated
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public void updateStatus(CertificateDAO certificate) throws DBException {
		try {

			SQLiteDatabase db = this.getWritableDatabase();

			/*
			 * Sets the values to the contentValue object
			 */
			ContentValues values = new ContentValues();

			// Status
			values.put(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_STATUS,
					certificate.getStatus());

			// Last status update date
			values.put(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_LAST_UPDATE,
					DataBaseDictionary.FORMATTER_DB.format(new Date()));

			// updating row
			db.update(DataBaseDictionary.TABLE_CERTIFICATE, values,
					DataBaseDictionary.COLUMN_NAME_CERTIFICATE_ID + " = ?",
					new String[] { String.valueOf(certificate.getId()) });
			db.close();

		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException("Error while updating Certificate status: "
					+ ex, ex);
		}
	}

	/**
	 * Gets the list of all the certificates saved in the data base
	 * 
	 * @return A list of certificates
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<CertificateDAO> getAllCertificates() throws DBException {

		try {
			// Select All Query
			String selectQuery = DataBaseDictionary.GET_ALL_CERTIFICATE;

			SQLiteDatabase db = this.getReadableDatabase();
			Cursor cursor = db.rawQuery(selectQuery, null);
			// Result processing
			List<CertificateDAO> certificates = new LinkedList<CertificateDAO>();
			// looping through all rows and adding to list
			if (cursor.moveToFirst()) {
				// For each element in the result set, a new object is generated
				// and added to the list
				do {
					// The resultSet values are extracted using the column names
					CertificateDAO certificate = new CertificateDAO();
					certificate
							.setId(cursor.getInt(cursor
									.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_ID)));
					certificate
							.setCertificateStr(cursor.getString(cursor
									.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_DATA)));
					certificate
							.setSerialNumber(cursor.getInt(cursor
									.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_SERIAL_NUMBER)));
					certificate
							.setStatus(cursor.getInt(cursor
									.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_STATUS)));

					certificate
							.setSignDeviceId(cursor.getString(cursor
									.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_SIGN_DEVICE)));

					certificate
							.setSubjectKeyId(cursor.getString(cursor
									.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_SUBJET_KEY_ID)));

					Date date;
					try {
						date = DataBaseDictionary.FORMATTER_DB
								.parse(cursor.getString(cursor
										.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_LAST_UPDATE)));

					} catch (ParseException e) {
						date = new Date(0);
					} catch (NullPointerException e) {
						date = new Date(0);
					}
					certificate.setLastStatusUpdateDate(date);
					certificate.setCaCertificate(new CertificateDAO());
					certificate.setOwner(new SubjectDAO());
					certificates.add(certificate);

				} while (cursor.moveToNext());
			}
			cursor.close();
			db.close();
			return certificates;
		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException("Error getting all Certificates : " + ex, ex);
		}
	}

	/**
	 * Adds to the certificate the information about its owner and CA
	 * certificate
	 * 
	 * @param certificate
	 *            Certificate to which will be added the information, also the
	 *            ID of this certificate will be used as SQL filter
	 */
	public void getCertificateDetails(CertificateDAO certificate) {
		Boolean res = Boolean.FALSE;

		SQLiteDatabase db = this.getReadableDatabase();
		Cursor cursor = db
				.query(DataBaseDictionary.TABLE_CERTIFICATE,
						new String[] {
								DataBaseDictionary.COLUMN_NAME_SUBJECT_ID,
								DataBaseDictionary.COLUMN_NAME_CERTIFICATE_CA_CERITIFICATE_ID },
						DataBaseDictionary.COLUMN_NAME_CERTIFICATE_ID + "=?",
						new String[] { certificate.getId() + "" }, null, null,
						null, null);

		if (cursor != null) {
			res = cursor.moveToFirst();
			if (res) {
				// Query the owner of the certificate
				Cursor cursorAux = db
						.query(DataBaseDictionary.TABLE_SUBJECT,
								null,
								DataBaseDictionary.COLUMN_NAME_SUBJECT_ID
										+ "=?",
								new String[] { cursor.getString(cursor
										.getColumnIndex(DataBaseDictionary.COLUMN_NAME_SUBJECT_ID)) },
								null, null, null, null);

				// If the cursor containing the subject is not null or the
				// query result is empty
				if (cursorAux != null) {
					res = cursorAux.moveToFirst();
					if (res) {
						// Get Owner information
						SubjectDAO owner = new SubjectDAO();
						owner.setId(cursorAux.getInt(cursorAux
								.getColumnIndex(DataBaseDictionary.COLUMN_NAME_SUBJECT_ID)));
						owner.setName(cursorAux.getString(cursorAux
								.getColumnIndex(DataBaseDictionary.COLUMN_NAME_SUBJECT_NAME)));
						owner.setActive(Boolean.parseBoolean(cursorAux.getString(cursorAux
								.getColumnIndex(DataBaseDictionary.COLUMN_NAME_SUBJECT_ACTIVE))));
						certificate.setOwner(owner);

					}
					cursorAux.close();
				}

				res = Boolean.FALSE;
				// Query the ca certificate information
				cursorAux = db
						.query(DataBaseDictionary.TABLE_CERTIFICATE,
								null,
								DataBaseDictionary.COLUMN_NAME_CERTIFICATE_ID
										+ "=?",
								new String[] { cursor.getString(cursor
										.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_CA_CERITIFICATE_ID)) },
								null, null, null, null);

				if (cursorAux != null) {
					res = cursorAux.moveToFirst();
					if (res) {

						CertificateDAO caCertificate = new CertificateDAO();

						caCertificate
								.setId(cursorAux.getInt(cursorAux
										.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_ID)));
						caCertificate
								.setCertificateStr(cursorAux.getString(cursorAux
										.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_DATA)));
						caCertificate
								.setSerialNumber(cursorAux.getInt(cursorAux
										.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_SERIAL_NUMBER)));
						caCertificate
								.setStatus(cursorAux.getInt(cursorAux
										.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_STATUS)));
						caCertificate
								.setSignDeviceId(cursorAux.getString(cursorAux
										.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_SIGN_DEVICE)));

						caCertificate
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
						caCertificate.setLastStatusUpdateDate(date);

						// Query the ca certificate owner
						Cursor cursorAuxCa = db
								.query(DataBaseDictionary.TABLE_SUBJECT,
										null,
										DataBaseDictionary.COLUMN_NAME_SUBJECT_ID
												+ "=?",
										new String[] { cursorAux.getString(cursorAux
												.getColumnIndex(DataBaseDictionary.COLUMN_NAME_SUBJECT_ID)) },
										null, null, null, null);

						// If the cursor containing the subject is not null or
						// the
						// query result is empty
						if (cursorAuxCa != null) {
							res = cursorAuxCa.moveToFirst();
							if (res) {
								// Get Owner information
								SubjectDAO ca = new SubjectDAO();
								ca.setId(cursorAuxCa.getInt(cursorAuxCa
										.getColumnIndex(DataBaseDictionary.COLUMN_NAME_SUBJECT_ID)));
								ca.setName(cursorAuxCa.getString(cursorAuxCa
										.getColumnIndex(DataBaseDictionary.COLUMN_NAME_SUBJECT_NAME)));
								ca.setActive(Boolean.parseBoolean(cursorAuxCa.getString(cursorAuxCa
										.getColumnIndex(DataBaseDictionary.COLUMN_NAME_SUBJECT_ACTIVE))));
								caCertificate.setOwner(ca);

							}
							cursorAuxCa.close();
						}

						certificate.setCaCertificate(caCertificate);
						cursorAux.close();
					}
				}
				cursor.close();
			}
		}

		db.close();
		// return certificate;
	}

	/**
	 * Gets a list of certificates that were founded using the specified filter
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
	 * @return A list of certificates that agrees with the filter
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<CertificateDAO> getByAdvancedFilter(Map<String, String[]> filter)
			throws DBException {
		try {

			SQLiteDatabase db = this.getReadableDatabase();
			Cursor cursor = executeAdvancedQuery(filter,
					DataBaseDictionary.TABLE_CERTIFICATE, db);

			// Result processing
			List<CertificateDAO> certificates = new LinkedList<CertificateDAO>();
			// looping through all rows and adding to list
			if (cursor.moveToFirst()) {
				// For each element in the result set, a new object is generated
				// and added to the list
				do {
					// The resultSet values are extracted using the column names
					CertificateDAO certificate = new CertificateDAO();
					certificate
							.setId(cursor.getInt(cursor
									.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_ID)));
					certificate
							.setCertificateStr(cursor.getString(cursor
									.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_DATA)));
					certificate
							.setSerialNumber(cursor.getInt(cursor
									.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_SERIAL_NUMBER)));
					certificate
							.setStatus(cursor.getInt(cursor
									.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_STATUS)));
					certificate
							.setSignDeviceId(cursor.getString(cursor
									.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_SIGN_DEVICE)));

					certificate
							.setSubjectKeyId(cursor.getString(cursor
									.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_SUBJET_KEY_ID)));

					Date date;
					try {
						date = DataBaseDictionary.FORMATTER_DB
								.parse(cursor.getString(cursor
										.getColumnIndex(DataBaseDictionary.COLUMN_NAME_CERTIFICATE_LAST_UPDATE)));

					} catch (ParseException e) {
						date = new Date(0);
					} catch (NullPointerException e) {
						date = new Date(0);
					}
					certificate.setLastStatusUpdateDate(date);
					certificate.setCaCertificate(new CertificateDAO());
					certificate.setOwner(new SubjectDAO());
					certificates.add(certificate);

				} while (cursor.moveToNext());
			}
			cursor.close();
			db.close();
			return certificates;
		} catch (SQLException ex) {
			log.error(ex, ex);
			throw new DBException("Error getting Certificates : " + ex, ex);
		}
	}

	/**
	 * Get the total count of rows in Certificate table
	 * 
	 * @return
	 */
	public Integer getCount() {
		String countQuery = "SELECT * FROM "
				+ DataBaseDictionary.TABLE_CERTIFICATE;
		SQLiteDatabase db = this.getReadableDatabase();
		Cursor cursor = db.rawQuery(countQuery, null);
		Integer count = cursor.getCount();
		cursor.close();
		db.close();
		// return count
		return count;
	}

	/**
	 * Get the current Id in Certificate table
	 * 
	 * @return An integer that represents the current id
	 */
	public Integer getCurrentId() {
		String countQuery = " SELECT MAX("
				+ DataBaseDictionary.COLUMN_NAME_CERTIFICATE_ID
				+ ") as id FROM " + DataBaseDictionary.TABLE_CERTIFICATE + ";";
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

	/**
	 * Get the current serial number for the CA
	 * 
	 * @param caSubjectId
	 *            CA subject Id of which the serial number is required
	 * @return the current serial number corresponding to the selected CA
	 */
	public Integer getCurrentSerialNumberForCA(Integer caSubjectId) {
		// Select MAX(num_cer) as sn FROM Certificate WHERE ca_cer IN (SELECT
		// ide_cer FROM Certificate WHERE ide_sub=PARAMETER);
		String countQuery = " SELECT MAX("
				+ DataBaseDictionary.COLUMN_NAME_CERTIFICATE_SERIAL_NUMBER
				+ ") as sn FROM " + DataBaseDictionary.TABLE_CERTIFICATE
				+ " WHERE "
				+ DataBaseDictionary.COLUMN_NAME_CERTIFICATE_CA_CERITIFICATE_ID
				+ " IN (SELECT "
				+ DataBaseDictionary.COLUMN_NAME_CERTIFICATE_ID + " FROM "
				+ DataBaseDictionary.TABLE_CERTIFICATE + " WHERE "
				+ DataBaseDictionary.COLUMN_NAME_SUBJECT_ID + "=" + caSubjectId
				+ ");";
		SQLiteDatabase db = this.getReadableDatabase();
		Cursor cursor = db.rawQuery(countQuery, null);
		Integer sn = 0;
		if (cursor.moveToFirst()) {
			sn = cursor.getInt(0);
		}
		cursor.close();
		db.close();
		// return count
		return sn;
	}
}
