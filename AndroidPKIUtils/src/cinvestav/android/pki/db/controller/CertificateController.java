/**
 *  Created on  : 30/07/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	This class implements all the methods for accessing the Data Base layer
 * classes, it should be the connection between the view layer an the database
 * layer for retrieve and modify certificate information
 */
package cinvestav.android.pki.db.controller;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase.CursorFactory;
import cinvestav.android.pki.cryptography.utils.X509UtilsDictionary;
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.android.pki.db.db.CertificateDB;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.android.pki.utils.DataBaseDictionary;

/**
 * This class implements all the methods for accessing the Data Base layer
 * classes, it should be the connection between the view layer an the database
 * layer for retrieve and modify certificate information
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 30/07/2012
 * @version 1.0
 */
public class CertificateController {

	CertificateDB certificateDB;

	/**
	 * 
	 * @param context
	 * @param name
	 * @param factory
	 * @param version
	 */
	public CertificateController(Context context, String name,
			CursorFactory factory, int version) {
		certificateDB = new CertificateDB(context, name, factory, version);
	}

	/**
	 * Constructor that inits the data base connection using application context
	 * 
	 * @param context
	 */
	public CertificateController(Context context) {
		certificateDB = new CertificateDB(context);
	}

	/**
	 * Inserts a new Certificate in the data base
	 * 
	 * @param certificate
	 *            Certificate to insert
	 * @return the Id of the row inserted in the data base
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public Integer insert(CertificateDAO certificate) throws DBException {
		return certificateDB.insert(certificate);
	}

	/**
	 * Updates the certificate in the data base
	 * 
	 * @param certificate
	 *            {@link CertificateDAO} with the updated fields, the only field
	 *            that won't be modified is the Id
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public void update(CertificateDAO certificate) throws DBException {
		certificateDB.update(certificate);
	}

	/**
	 * Updates the certificate status in the data base
	 * 
	 * @param certificate
	 *            {@link CertificateDAO} with the updated Status, just this
	 *            field will be updated
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public void updateStatus(CertificateDAO certificate) throws DBException {
		certificateDB.updateStatus(certificate);
	}

	/**
	 * Gets the certificate DAO from the data base using the certificate serial
	 * number as filter
	 * 
	 * @param serialNumber
	 *            Serial Number which will be searched
	 * @return a {@link CertificateDAO} object filled with the certificate
	 *         information, corresponding to the asked serial number, if no
	 *         coincidence is found in the data base an empty
	 *         {@link CertificateDAO} object (id = 0) will be returned
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public CertificateDAO getBySerialNumber(Integer serialNumber)
			throws DBException {
		// Create an special filter
		/*
		 * Filter map where: Key = Tag of the filter to be used, should be
		 * define in "DataBaseDictionary" Class, this tags must be written as a
		 * SQL WHERE clause using a PreparedStament form for example: 'DBfield =
		 * ?' or 'DBfield LIKE ?' Value = Must be a string array of 3 positions
		 * where: [0] = Value to be searched in the data base [1] = Data type,
		 * according to this, the PreparedStatemen will be constructed, the
		 * valid DataTypes are defined in the "DataBaseDictionary" Class
		 */
		Map<String, String[]> filterMap = new HashMap<String, String[]>();
		String[] value = new String[3];

		/*
		 * Establish filter properties
		 */
		// Filter value
		value[0] = serialNumber + "";
		// Filter type
		value[1] = DataBaseDictionary.FILTER_TYPE_CERTIFICATE_SERIAL_NUMBER;
		filterMap.put(DataBaseDictionary.FILTER_CERTIFICATE_SERIAL_NUMBER,
				value);
		List<CertificateDAO> resList = certificateDB
				.getByAdvancedFilter(filterMap);
		if (!resList.isEmpty()) {
			return resList.get(0);
		}
		return new CertificateDAO();
	}

	/**
	 * Gets the certificate DAO from the data base using the certificate
	 * database Id as filter
	 * 
	 * @param id
	 *            DataBase certificate Id which will be searched
	 * @return a {@link CertificateDAO} object filled with the certificate
	 *         information, corresponding to the asked id, if no coincidence is
	 *         found in the data base an empty {@link CertificateDAO} object (id
	 *         = 0) will be returned
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public CertificateDAO getById(Integer id) throws DBException {
		// Create an special filter
		/*
		 * Filter map where: Key = Tag of the filter to be used, should be
		 * define in "DataBaseDictionary" Class, this tags must be written as a
		 * SQL WHERE clause using a PreparedStament form for example: 'DBfield =
		 * ?' or 'DBfield LIKE ?' Value = Must be a string array of 3 positions
		 * where: [0] = Value to be searched in the data base [1] = Data type,
		 * according to this, the PreparedStatemen will be constructed, the
		 * valid DataTypes are defined in the "DataBaseDictionary" Class
		 */
		Map<String, String[]> filterMap = new HashMap<String, String[]>();
		String[] value = new String[3];

		/*
		 * Establish filter properties
		 */
		// Filter value
		value[0] = id + "";
		// Filter type
		value[1] = DataBaseDictionary.FILTER_TYPE_CERTIFICATE_ID;
		filterMap.put(DataBaseDictionary.FILTER_CERTIFICATE_ID, value);
		List<CertificateDAO> resList = certificateDB
				.getByAdvancedFilter(filterMap);
		if (!resList.isEmpty()) {
			return resList.get(0);
		}
		return new CertificateDAO();
	}

	/**
	 * Gets a list of the certificates that belongs to the desired subjectId
	 * 
	 * @param ownerId
	 *            Subject Id that must be search for
	 * @return A List of {@link CertificateDAO} filled with the certificates
	 *         that belong to the asked subject Id in the data base, if no
	 *         coincidences are found, an empty list will be returned
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<CertificateDAO> getByOwnerId(Integer ownerId)
			throws DBException {
		// Create an special filter
		/*
		 * Filter map where: Key = Tag of the filter to be used, should be
		 * define in "DataBaseDictionary" Class, this tags must be written as a
		 * SQL WHERE clause using a PreparedStament form for example: 'DBfield =
		 * ?' or 'DBfield LIKE ?' Value = Must be a string array of 3 positions
		 * where: [0] = Value to be searched in the data base [1] = Data type,
		 * according to this, the PreparedStatemen will be constructed, the
		 * valid DataTypes are defined in the "DataBaseDictionary" Class
		 */
		Map<String, String[]> filterMap = new HashMap<String, String[]>();
		String[] value = new String[3];

		/*
		 * Establish filter properties
		 */
		// Filter value
		value[0] = ownerId + "";
		// Filter type
		value[1] = DataBaseDictionary.FILTER_TYPE_SUBJECT_ID;
		filterMap.put(DataBaseDictionary.FILTER_SUBJECT_ID, value);
		return certificateDB.getByAdvancedFilter(filterMap);
	}

	/**
	 * Gets a list of the certificates issued by the desired CA, using the CA's
	 * subject Id as filter
	 * 
	 * @param caSubjectId
	 *            Subject Id of the CA of which the issued certificates list are
	 *            desired
	 * @return A List of {@link CertificateDAO} filled with the certificates
	 *         that belong to the asked CA's subject Id in the data base, if no
	 *         coincidences are found, an empty list will be returned
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<CertificateDAO> getByCASubjectId(Integer caSubjectId)
			throws DBException {
		// Create an special filter
		/*
		 * Filter map where: Key = Tag of the filter to be used, should be
		 * define in "DataBaseDictionary" Class, this tags must be written as a
		 * SQL WHERE clause using a PreparedStament form for example: 'DBfield =
		 * ?' or 'DBfield LIKE ?' Value = Must be a string array of 3 positions
		 * where: [0] = Value to be searched in the data base [1] = Data type,
		 * according to this, the PreparedStatemen will be constructed, the
		 * valid DataTypes are defined in the "DataBaseDictionary" Class
		 */
		Map<String, String[]> filterMap = new HashMap<String, String[]>();
		String[] value = new String[3];

		/*
		 * Establish filter properties
		 */
		// Filter value
		value[0] = caSubjectId + "";
		// Filter type
		value[1] = DataBaseDictionary.FILTER_TYPE_SUBJECT_ID;
		filterMap.put(DataBaseDictionary.FILTER_SUBJECT_ID, value);
		List<CertificateDAO> ownedCerts = certificateDB
				.getByAdvancedFilter(filterMap);
		List<CertificateDAO> res = new LinkedList<CertificateDAO>();
		for (CertificateDAO caCert : ownedCerts) {
			res.addAll(getByCACertificateId(caCert.getId()));
		}
		return res;
	}

	/**
	 * Gets a list of the certificates issued by the desired CA, using the CA's
	 * certificate Id as filter
	 * 
	 * @param caCertificateId
	 *            Certificate Id of the CA of which the issued certificates list
	 *            are desired
	 * @return A List of {@link CertificateDAO} filled with the certificates
	 *         that belong to the asked CA's certificate Id in the data base, if
	 *         no coincidences are found, an empty list will be returned
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<CertificateDAO> getByCACertificateId(Integer caCertificateId)
			throws DBException {
		// Create an special filter
		/*
		 * Filter map where: Key = Tag of the filter to be used, should be
		 * define in "DataBaseDictionary" Class, this tags must be written as a
		 * SQL WHERE clause using a PreparedStament form for example: 'DBfield =
		 * ?' or 'DBfield LIKE ?' Value = Must be a string array of 3 positions
		 * where: [0] = Value to be searched in the data base [1] = Data type,
		 * according to this, the PreparedStatemen will be constructed, the
		 * valid DataTypes are defined in the "DataBaseDictionary" Class
		 */
		Map<String, String[]> filterMap = new HashMap<String, String[]>();
		String[] value = new String[3];

		/*
		 * Establish filter properties
		 */
		// Filter value
		value[0] = caCertificateId + "";
		// Filter type
		value[1] = DataBaseDictionary.FILTER_TYPE_CERTIFICATE_CA_ID;
		filterMap.put(DataBaseDictionary.FILTER_CERTIFICATE_CA_ID, value);
		return certificateDB.getByAdvancedFilter(filterMap);
	}

	/**
	 * Gets a list of the certificates issued by the desired CA, using the CA's
	 * certificate serial number as filter
	 * 
	 * @param caCertificateSerialNumber
	 *            Certificate serial number of the CA of which the issued
	 *            certificates list are desired
	 * @return A List of {@link CertificateDAO} filled with the certificates
	 *         that belong to the asked CA's certificate serial number in the
	 *         data base, if no coincidences are found, an empty list will be
	 *         returned
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<CertificateDAO> getByCACertificateSerialNumber(
			Integer caCertificateSerialNumber) throws DBException {
		// Create an special filter
		/*
		 * Filter map where: Key = Tag of the filter to be used, should be
		 * define in "DataBaseDictionary" Class, this tags must be written as a
		 * SQL WHERE clause using a PreparedStament form for example: 'DBfield =
		 * ?' or 'DBfield LIKE ?' Value = Must be a string array of 3 positions
		 * where: [0] = Value to be searched in the data base [1] = Data type,
		 * according to this, the PreparedStatemen will be constructed, the
		 * valid DataTypes are defined in the "DataBaseDictionary" Class
		 */
		Map<String, String[]> filterMap = new HashMap<String, String[]>();
		String[] value = new String[3];

		/*
		 * Establish filter properties
		 */
		// Filter value
		value[0] = caCertificateSerialNumber + "";
		// Filter type
		value[1] = DataBaseDictionary.FILTER_TYPE_CERTIFICATE_SERIAL_NUMBER;
		filterMap.put(DataBaseDictionary.FILTER_CERTIFICATE_SERIAL_NUMBER,
				value);
		return certificateDB.getByAdvancedFilter(filterMap);
	}

	/**
	 * Gets a list of the certificates with the desired db status
	 * 
	 * @param status
	 *            DataBase certificate Status which will be searched, Status of
	 *            the certificate in the DB, the possible values are at
	 *            {@link X509UtilsDictionary} ej.
	 *            X509UtilsDictionary.X509_CERTIFICATE_STATUS_VALID
	 * @return A List of {@link CertificateDAO} filled with the certificates
	 *         that belong to the asked CA's certificate serial number in the
	 *         data base, if no coincidences are found, an empty list will be
	 *         returned
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<CertificateDAO> getByStatus(Integer status) throws DBException {
		// Create an special filter
		/*
		 * Filter map where: Key = Tag of the filter to be used, should be
		 * define in "DataBaseDictionary" Class, this tags must be written as a
		 * SQL WHERE clause using a PreparedStament form for example: 'DBfield =
		 * ?' or 'DBfield LIKE ?' Value = Must be a string array of 3 positions
		 * where: [0] = Value to be searched in the data base [1] = Data type,
		 * according to this, the PreparedStatemen will be constructed, the
		 * valid DataTypes are defined in the "DataBaseDictionary" Class
		 */
		Map<String, String[]> filterMap = new HashMap<String, String[]>();
		String[] value = new String[3];

		/*
		 * Establish filter properties
		 */
		// Filter value
		value[0] = status + "";
		// Filter type
		value[1] = DataBaseDictionary.FILTER_TYPE_CERTIFICATE_STATUS;
		filterMap.put(DataBaseDictionary.FILTER_CERTIFICATE_STATUS, value);
		return certificateDB.getByAdvancedFilter(filterMap);

	}

	/**
	 * Gets the list of all the certificates saved in the data base
	 * 
	 * @return A list of certificates
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<CertificateDAO> getAll() throws DBException {
		return certificateDB.getAllCertificates();
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
		return certificateDB.getByAdvancedFilter(filter);
	}

	/**
	 * Adds to the certificate the information about its owner and CA
	 * certificate
	 * 
	 * @param certificate
	 *            Certificate to which will be added the information, also the
	 *            Id of this certificate will be used as SQL filter
	 */
	public void getCertificateDetails(CertificateDAO certificate) {
		certificateDB.getCertificateDetails(certificate);
	}

	/**
	 * Get the total count of rows in Certificate table
	 * 
	 * @return
	 */
	public Integer getCount() {
		return certificateDB.getCount();
	}

	/**
	 * Get the current Id in Certificate table
	 * 
	 * @return An integer that represents the current id
	 */
	public Integer getCurrentId() {
		return certificateDB.getCurrentId();
	}

	/**
	 * Get the current serial number for the CA
	 * 
	 * @param caSubjectId
	 *            CA subject Id of which the serial number is required
	 * @return the current serial number corresponding to the selected CA
	 */
	public Integer getCurrentSerialNumberForCA(Integer caSubjectId) {
		return certificateDB.getCurrentSerialNumberForCA(caSubjectId);
	}

}
