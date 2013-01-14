/**
 *  Created on  : 30/07/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	This class implements all the methods for accessing the Data Base layer
 * classes, it should be the connection between the view layer an the database
 * layer for retrieve and modify trusted certificates information
 */
package cinvestav.android.pki.db.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase.CursorFactory;
import cinvestav.android.pki.db.dao.TrustedCertificateDAO;
import cinvestav.android.pki.db.db.TrustedCertificateDB;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.android.pki.utils.DataBaseDictionary;

/**
 * This class implements all the methods for accessing the Data Base layer
 * classes, it should be the connection between the view layer an the database
 * layer for retrieve and modify trusted certificates information
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 30/07/2012
 * @version 1.0
 */
public class TrustedCertificateController {

	TrustedCertificateDB trustedCertificateDB;

	/**
	 * 
	 * @param context
	 * @param name
	 * @param factory
	 * @param version
	 */
	public TrustedCertificateController(Context context, String name,
			CursorFactory factory, int version) {
		trustedCertificateDB = new TrustedCertificateDB(context, name, factory,
				version);
	}

	/**
	 * Constructor that inits the data base connection using application context
	 * 
	 * @param context
	 */
	public TrustedCertificateController(Context context) {
		trustedCertificateDB = new TrustedCertificateDB(context);
	}

	/**
	 * Inserts a new TrustedCertificate in the data base
	 * 
	 * @param trustedCertificate
	 *            TrustedCertificate to insert
	 * @param subjectId
	 *            Subject to which the trusted certificate will be linked to
	 * @return the Id of the row inserted in the data base
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public Integer insert(TrustedCertificateDAO trustedCertificate,
			Integer subjectId) throws DBException {
		return trustedCertificateDB.insert(trustedCertificate, subjectId);
	}

	/**
	 * Updates the trustedCertificate in the data base
	 * 
	 * @param trustedCertificate
	 *            TrustedCertificateDAO with the updated fields, the only field
	 *            that won't be modified is the Id
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public void update(TrustedCertificateDAO trustedCertificate)
			throws DBException {
		trustedCertificateDB.update(trustedCertificate);
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
		trustedCertificateDB.delete(trustedCertificate);
	}

	/**
	 * Gets the list of all the trustedCertificates saved in the data base
	 * 
	 * @return A list of trustedCertificates
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<TrustedCertificateDAO> getAll() throws DBException {
		return trustedCertificateDB.getAllTrustedCertificates();
	}

	/**
	 * Get a trusted certificate DAO from the DB using its Id as SQL filter
	 * 
	 * @param id
	 *            Trusted Certificate data base Id
	 * @return a {@link TrustedCertificate} object filled with the data base
	 *         information if the trusted certificate id was found, or an empty
	 *         {@link TrustedCertificateDAO} object (id = 0) if no results were
	 *         found in the data base
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public TrustedCertificateDAO getById(Integer id) throws DBException {
		/*
		 * Filter map where: Key = Tag of the filter to be used, should be
		 * define in "DataBaseDictionary" Class, this tags must be written as a
		 * SQL WHERE clause using a PreparedStament form for example: 'DBfield =
		 * ?' or 'DBfield LIKE ?' Value = Must be a string array of 3 positions
		 * where: [0] = Value to be searched in the data base [1] = Data type,
		 * according to this, the PreparedStatemen will be constructed, the
		 * valid DataTypes are defined in the "DataBaseDictionary"
		 */
		Map<String, String[]> filterMap = new HashMap<String, String[]>();
		String[] value = new String[3];

		/*
		 * Establish filter properties
		 */
		// Filter value
		value[0] = id + "";
		// Filter type
		value[1] = DataBaseDictionary.FILTER_TYPE_TRUSTED_CERTIFICATE_ID;

		filterMap.put(DataBaseDictionary.FILTER_TRUSTED_CERTIFICATE_ID, value);
		List<TrustedCertificateDAO> resList = trustedCertificateDB
				.getByAdvancedFilter(filterMap);
		if (!resList.isEmpty()) {
			return resList.get(0);
		}
		return new TrustedCertificateDAO();
	}

	/**
	 * List of trusted certificates linked to the subject, using subject id as
	 * SQL filter
	 * 
	 * @param subjectId
	 *            Id of the subject to which the trusted certificates will like
	 *            to get
	 * @return a List of {@link TrustedCertificateDAO} filled with the trusted
	 *         certificates linked to the subject in the data base, if no
	 *         coincidences are found, an empty list will be returned
	 * @throws DBException
	 */
	public List<TrustedCertificateDAO> getBySubjectId(Integer subjectId)
			throws DBException {
		/*
		 * Filter map where: Key = Tag of the filter to be used, should be
		 * define in "DataBaseDictionary" Class, this tags must be written as a
		 * SQL WHERE clause using a PreparedStament form for example: 'DBfield =
		 * ?' or 'DBfield LIKE ?' Value = Must be a string array of 3 positions
		 * where: [0] = Value to be searched in the data base [1] = Data type,
		 * according to this, the PreparedStatemen will be constructed, the
		 * valid DataTypes are defined in the "DataBaseDictionary"
		 */
		Map<String, String[]> filterMap = new HashMap<String, String[]>();
		String[] value = new String[3];

		/*
		 * Establish filter properties
		 */
		// Filter value
		value[0] = subjectId + "";
		// Filter type
		value[1] = DataBaseDictionary.FILTER_TYPE_SUBJECT_ID;
		filterMap.put(DataBaseDictionary.FILTER_SUBJECT_ID, value);
		return trustedCertificateDB.getByAdvancedFilter(filterMap);
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
		return trustedCertificateDB.getByAdvancedFilter(filter);
	}

	/**
	 * Get the total count of rows in TrustedCertificate table
	 * 
	 * @return
	 */
	public Integer getCount() {
		return trustedCertificateDB.getCount();
	}

	/**
	 * Get the current Id in TrustedCertificate table
	 * 
	 * @return An integer that represents the current id
	 */
	public Integer getCurrentId() {
		return trustedCertificateDB.getCurrentId();
	}
}
