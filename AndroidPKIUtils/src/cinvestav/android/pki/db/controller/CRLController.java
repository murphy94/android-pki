/**
 *  Created on  : 31/07/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	This class implements all the methods for accessing the Data Base layer
 * classes, it should be the connection between the view layer an the database
 * layer for retrieve and modify CRLs information
 */
package cinvestav.android.pki.db.controller;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase.CursorFactory;
import cinvestav.android.pki.db.dao.CRLDAO;
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.android.pki.db.db.CRLDB;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.android.pki.utils.DataBaseDictionary;

/**
 * This class implements all the methods for accessing the Data Base layer
 * classes, it should be the connection between the view layer an the database
 * layer for retrieve and modify CRLs information
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 31/07/2012
 * @version 1.0
 */
public class CRLController {

	CRLDB crlDB;
	CertificateController certificateController;

	/**
	 * 
	 * @param context
	 * @param name
	 * @param factory
	 * @param version
	 */
	public CRLController(Context context, String name, CursorFactory factory,
			int version) {
		crlDB = new CRLDB(context, name, factory, version);
		certificateController = new CertificateController(context, name,
				factory, version);
	}

	/**
	 * Constructor that inits the data base connection using application context
	 * 
	 * @param context
	 */
	public CRLController(Context context) {
		crlDB = new CRLDB(context);
		certificateController = new CertificateController(context);
	}

	/**
	 * Inserts a new CRL in the data base
	 * 
	 * @param crl
	 *            CRL to insert
	 * @return the Id of the row inserted in the data base
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public Integer insert(CRLDAO crl) throws DBException {
		return crlDB.insert(crl);
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
		crlDB.delete(crl);
	}

	/**
	 * Gets the list of all the CRLs saved in the data base
	 * 
	 * @return A list of CRLs
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<CRLDAO> getAll() throws DBException {
		return crlDB.getAllCRLs();
	}

	/**
	 * Get a {@link CRLDAO} from the DB using its Id as SQL filter
	 * 
	 * @param id
	 *            CRL data base Id
	 * @return a {@link CRLDAO} object filled with the data base information if
	 *         the CRL id was found, or an empty {@link CRLDAO} object (id = 0)
	 *         if no results were found in the data base
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public CRLDAO getById(Integer id) throws DBException {
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
		value[1] = DataBaseDictionary.FILTER_TYPE_CRL_ID;

		filterMap.put(DataBaseDictionary.FILTER_CRL_ID, value);
		List<CRLDAO> resList = crlDB.getByAdvancedFilter(filterMap);
		if (!resList.isEmpty()) {
			return resList.get(0);
		}
		return new CRLDAO();
	}

	/**
	 * Get a CRL list using the serial number as SQL filter
	 * 
	 * @param serialNumber
	 *            Serial Number of the CRL that will like to search
	 * @return a {@link CRLDAO} object filled with the CRL saved with the
	 *         desired serial number , if no coincidences are found, an empty
	 *         {@link CRLDAO} object (id = 0) will be returned
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public CRLDAO getBySerialNumber(Integer serialNumber) throws DBException {
		/*
		 * Filter map where: Key = Tag of the filter to be used, should be
		 * define in "DataBaseDictionary" Class, this tags must be written as a
		 * SQL WHERE clause using a PreparedStament form for example: 'DBfield =
		 * ?' or 'DBfield LIKE ?' Value = Must be a string array of 3 positions
		 * where: [0] = Value to be searched in the data base [1] = Data type,
		 * according to this, the PreparedStatemen will be constructed, the
		 * valid DataTypes are defined in the "DataBaseDictionary" Class [2] =
		 * Alias of the field used in the SQL Statement
		 */
		Map<String, String[]> filterMap = new HashMap<String, String[]>();
		String[] value = new String[3];

		/*
		 * Establish filter properties
		 */
		// Filter value
		value[0] = serialNumber + "";
		// Filter type
		value[1] = DataBaseDictionary.FILTER_TYPE_CRL_SERIAL_NUMBER;
		// Database filter table alias

		filterMap.put(DataBaseDictionary.FILTER_CRL_SERIAL_NUMBER, value);
		List<CRLDAO> resList = crlDB.getByAdvancedFilter(filterMap);
		if (!resList.isEmpty()) {
			return resList.get(0);
		}
		return new CRLDAO();
	}

	/**
	 * Get the list of all the CRLs issued by a CA using its certificate Id as
	 * SQL filter
	 * 
	 * @param issuerCertificateId
	 *            Id of the certificate to be used as filter
	 * @return A list of {@link CRLDAO} filled with all the CRLs issued using
	 *         the desired certificate, or an empty list if no CRL were found
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<CRLDAO> getByIssuerCertificateId(Integer issuerCertificateId)
			throws DBException {
		/*
		 * Filter map where: Key = Tag of the filter to be used, should be
		 * define in "DataBaseDictionay" Class, this tags must be written as a
		 * SQL WHERE clause using a PreparedStament form for example: 'DBfield =
		 * ?' or 'DBfield LIKE ?' Value = Must be a string array of 3 positions
		 * where: [0] = Value to be searched in the data base [1] = Data type,
		 * according to this, the PreparedStatemen will be constructed, the
		 * valid DataTypes are defined in the "DataBaseDictionary" Class [2] =
		 * Alias of the field used in the SQL Statement
		 */
		Map<String, String[]> filterMap = new HashMap<String, String[]>();
		String[] value = new String[3];

		value = new String[3];
		value[0] = issuerCertificateId + "";
		value[1] = DataBaseDictionary.FILTER_TYPE_CERTIFICATE_ID;

		filterMap.put(DataBaseDictionary.FILTER_CERTIFICATE_ID, value);

		return crlDB.getByAdvancedFilter(filterMap);
	}

	/**
	 * Get the list of all the CRLs issued by a CA using its certificate Serial
	 * Number as SQL filter
	 * 
	 * @param issuerCertificateSerialNumber
	 *            Serial Number of the certificate to be used as filter
	 * @return A list of {@link CRLDAO} filled with all the CRLs issued using
	 *         the desired certificate, or an empty list if no CRL were found
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<CRLDAO> getByIssuerCertificateSerialNumber(
			Integer issuerCertificateSerialNumber) throws DBException {

		// Get the certificate using the serial number
		CertificateDAO certificate = certificateController
				.getBySerialNumber(issuerCertificateSerialNumber);
		// If the certificate Id ==0, the serial number was not found, so an
		// empty list is returned
		if (certificate.getId() == 0)
			return new LinkedList<CRLDAO>();
		return getByIssuerCertificateId(certificate.getId());

	}

	/**
	 * Get the list of all the CRLs issued by a CA using its subject Id as SQL
	 * filter, so this function will return all CRL issued by a CA no mater what
	 * certificate was used for sign it
	 * 
	 * @param issuerSubjectId
	 *            Id of the CA subject in the data base to be used as filter
	 * @return A list of {@link CRLDAO} filled with all the CRLs issued by an
	 *         specific subject, or an empty list if no CRL were found
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<CRLDAO> getByIssuerSubjectId(Integer issuerSubjectId)
			throws DBException {
		List<CRLDAO> crlList = new LinkedList<CRLDAO>();
		// Get the certificate list using the subjectId
		List<CertificateDAO> certificateList = certificateController
				.getByOwnerId(issuerSubjectId);
		for (CertificateDAO certificate : certificateList) {
			crlList.addAll(getByIssuerCertificateId(certificate.getId()));
		}

		return crlList;
	}

	/**
	 * Gets a list of CRLs that were founded using the specified filter
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
	 * @return A list of CRLs that agrees with the filter
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<CRLDAO> getByAdvancedFilter(Map<String, String[]> filter)
			throws DBException {
		return crlDB.getByAdvancedFilter(filter);
	}

	/**
	 * Get the total count of rows in CRL table
	 * 
	 * @return
	 */
	public Integer getCount() {
		return crlDB.getCount();
	}

	/**
	 * Get the current Id in CRL table
	 * 
	 * @return An integer that represents the current id
	 */
	public Integer getCurrentId() {
		return crlDB.getCurrentId();
	}
}
