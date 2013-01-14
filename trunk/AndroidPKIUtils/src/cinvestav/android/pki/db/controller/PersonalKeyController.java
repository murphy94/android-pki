/**
 * 
 *  Created on  : 27/07/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	This class implements all the methods for accessing the Data Base layer
 * classes, it should be the connection between the view layer an the database
 * layer for retrieve and modify personal keys information
 */
package cinvestav.android.pki.db.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase.CursorFactory;
import cinvestav.android.pki.db.dao.PersonalKeyDAO;
import cinvestav.android.pki.db.db.PersonalKeyDB;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.android.pki.utils.DataBaseDictionary;

/**
 * This class implements all the methods for accessing the Data Base layer
 * classes, it should be the connection between the view layer an the database
 * layer for retrieve and modify personal keys information
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 27/07/2012
 * @version 1.0
 */
public class PersonalKeyController {

	PersonalKeyDB personalKeyDB;

	/**
	 * 
	 * @param context
	 * @param name
	 * @param factory
	 * @param version
	 */
	public PersonalKeyController(Context context, String name,
			CursorFactory factory, int version) {
		personalKeyDB = new PersonalKeyDB(context, name, factory, version);
	}

	/**
	 * Constructor that inits the data base connection using application context
	 * 
	 * @param context
	 */
	public PersonalKeyController(Context context) {
		personalKeyDB = new PersonalKeyDB(context);
	}

	/**
	 * Inserts a new Key in the data base
	 * 
	 * @param personalKey
	 *            Key to insert
	 * @param ownerId
	 *            If of the owner of this key
	 * @return the Id of the row inserted in the data base
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public Integer insert(PersonalKeyDAO personalKey, Integer ownerId)
			throws DBException {
		return personalKeyDB.insert(personalKey, ownerId);
	}

	/**
	 * Updates the key in the data base
	 * 
	 * @param personalKey
	 *            PersonalKeyDAO with the updated fields, the only field that
	 *            won't be modified is the Id
	 * @param ownerId
	 *            If of the owner of this key
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public void update(PersonalKeyDAO personalKey, Integer ownerId)
			throws DBException {
		personalKeyDB.update(personalKey, ownerId);
	}

	/**
	 * Deletes a personalKey from the data base
	 * 
	 * @param personalKey
	 *            PersonalKeyDAO that will be deleted, the register to be
	 *            deleted will be searched by id
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public void delete(PersonalKeyDAO personalKey) throws DBException {
		personalKeyDB.delete(personalKey);
	}

	/**
	 * Gets the list of all the personalKeys saved in the data base
	 * 
	 * @return A list of personalKeys
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<PersonalKeyDAO> getAll() throws DBException {
		return personalKeyDB.getAllPersonalKeys();
	}

	/**
	 * Gets a {@link PersonalKeyDAO} object filled with the Data base
	 * information using personal Key id as SQL filter
	 * 
	 * @param personalKeyId
	 *            Key id to be used as filter in the SQL sentence
	 * @return a {@link PersonalKeyDAO} object filled with the data base
	 *         information if the personal key id was found, or an empty
	 *         {@link PersonalKeyDAO} object (personalKey id = 0) if no results
	 *         were found in the data base
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public PersonalKeyDAO getById(Integer personalKeyId) throws DBException {
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
		value[0] = personalKeyId + ""; // Filter value
		value[1] = DataBaseDictionary.FILTER_TYPE_PERSONALKEY_ID; // Filter type
		filterMap.put(DataBaseDictionary.FILTER_PERSONALKEY_ID, value);
		List<PersonalKeyDAO> resList = personalKeyDB
				.getByAdvancedFilter(filterMap);
		if (!resList.isEmpty()) {
			return resList.get(0);
		}
		return new PersonalKeyDAO();
	}

	/**
	 * Gets a {@link PersonalKeyDAO} object filled with the Data base
	 * information using personal Key unique key Id as SQL filter
	 * 
	 * @param uniqueKey
	 *            Unique Key to be used as filter in the SQL sentence
	 * @return a {@link PersonalKeyDAO} object filled with the data base
	 *         information if the unique key was found, or an empty
	 *         {@link PersonalKeyDAO} object (personalKey id = 0) if no results
	 *         were found in the data base
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public PersonalKeyDAO getByUniqueKey(String uniqueKey) throws DBException {
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
		value[0] = uniqueKey + "";
		// Filter type
		value[1] = DataBaseDictionary.FILTER_TYPE_PERSONALKEY_UNIQUE_KEY;

		filterMap.put(DataBaseDictionary.FILTER_PERSONALKEY_UNIQUE_KEY, value);
		List<PersonalKeyDAO> resList = personalKeyDB
				.getByAdvancedFilter(filterMap);
		if (!resList.isEmpty()) {
			return resList.get(0);
		}
		return new PersonalKeyDAO();
	}

	/**
	 * Gets a list of the personal keys linked to the desired subject id
	 * 
	 * @param subjectId
	 *            Subject Id that must be search for
	 * @return A List of {@link PersonalKeyDAO} filled with the personal keys
	 *         linked to the asked subject Id in the data base, if no
	 *         coincidences are found, an empty list will be returned
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<PersonalKeyDAO> getBySubjectId(Integer subjectId)
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
		return personalKeyDB.getByAdvancedFilter(filterMap);
	}

	/**
	 * Gets a list of the personal keys of the desired key type
	 * 
	 * @param type
	 *            Key type that must be search for
	 * @return A List of {@link PersonalKeyDAO} filled with the personal keys of
	 *         the key type in the data base, if no coincidences are found, an
	 *         empty list will be returned
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<PersonalKeyDAO> getByType(Integer type) throws DBException {
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
		value[0] = type + "";
		// Filter type
		value[1] = DataBaseDictionary.FILTER_TYPE_PERSONALKEY_TYPE;

		filterMap.put(DataBaseDictionary.FILTER_PERSONALKEY_TYPE, value);
		return personalKeyDB.getByAdvancedFilter(filterMap);
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
		List<PersonalKeyDAO> res;
		/*
		 * Filter map where: Key = Tag of the filter to be used, should be
		 * define in "DataBaseDictionary" Class, this tags must be written as a
		 * SQL WHERE clause using a PreparedStament form for example: 'DBfield =
		 * ?' or 'DBfield LIKE ?' Value = Must be a string array of 3 positions
		 * where: [0] = Value to be searched in the data base [1] = Data type,
		 * according to this, the PreparedStatemen will be constructed, the
		 * valid DataTypes are defined in the "DataBaseDictionary"
		 */
//		Map<String, String[]> filterMap = new HashMap<String, String[]>();
//		String[] value = new String[3];

		/*
		 * Establish Subject ID filter properties
		 */
		// Filter value
//		value[0] = subjectId + "";
		// Filter type
//		value[1] = DataBaseDictionary.FILTER_TYPE_SUBJECT_ID;
//		filterMap.put(DataBaseDictionary.FILTER_SUBJECT_ID, value);

//		value = new String[3];
		/*
		 * Establish Private RSA key type filter properties
		 */
		// Filter value
//		value[0] = PersonalKeyDAO.PRIVATE_RSA + "";
		// Filter type
//		value[1] = DataBaseDictionary.FILTER_TYPE_PERSONALKEY_TYPE;

//		filterMap.put(DataBaseDictionary.FILTER_PERSONALKEY_TYPE, value);

		// Get all the Private RSA keys that belongs to the selected owner
//		res = getByAdvancedFilter(filterMap);

		// Now get the EC private keys for that user
//		filterMap = new HashMap<String, String[]>();
//		value = new String[3];

		/*
		 * Establish Subject ID filter properties
		 */
		// Filter value
//		value[0] = subjectId + "";
		// Filter type
//		value[1] = DataBaseDictionary.FILTER_TYPE_SUBJECT_ID;
//		filterMap.put(DataBaseDictionary.FILTER_SUBJECT_ID, value);

//		value = new String[3];
		/*
		 * Establish Private RSA key type filter properties
		 */
		// Filter value
//		value[0] = PersonalKeyDAO.PRIVATE_EC + "";
		// Filter type
//		value[1] = DataBaseDictionary.FILTER_TYPE_PERSONALKEY_TYPE;

//		filterMap.put(DataBaseDictionary.FILTER_PERSONALKEY_TYPE, value);

		// Get all the Private EC keys that belongs to the selected owner and
		// add the result to the previews one
//		res.addAll(getByAdvancedFilter(filterMap));

		// Again make an other search but now for PKCS_EC keys
		// Now get the EC private keys for that user
//		filterMap = new HashMap<String, String[]>();
//		value = new String[3];

		/*
		 * Establish Subject ID filter properties
		 */
		// Filter value
//		value[0] = subjectId + "";
		// Filter type
//		value[1] = DataBaseDictionary.FILTER_TYPE_SUBJECT_ID;
//		filterMap.put(DataBaseDictionary.FILTER_SUBJECT_ID, value);

//		value = new String[3];
		/*
		 * Establish Private RSA key type filter properties
		 */
		// Filter value
//		value[0] = PersonalKeyDAO.PKCS12_EC + "";
		// Filter type
//		value[1] = DataBaseDictionary.FILTER_TYPE_PERSONALKEY_TYPE;

//		filterMap.put(DataBaseDictionary.FILTER_PERSONALKEY_TYPE, value);

		// Get all the PKCS EC keys that belongs to the selected owner and
		// add the result to the previews one
//		res.addAll(getByAdvancedFilter(filterMap));

		// Finally make an other search but now for PKCS_RSA keys
		// Now get the EC private keys for that user
//		filterMap = new HashMap<String, String[]>();
//		value = new String[3];

		/*
		 * Establish Subject ID filter properties
		 */
		// Filter value
//		value[0] = subjectId + "";
		// Filter type
//		value[1] = DataBaseDictionary.FILTER_TYPE_SUBJECT_ID;
//		filterMap.put(DataBaseDictionary.FILTER_SUBJECT_ID, value);

//		value = new String[3];
		/*
		 * Establish Private RSA key type filter properties
		 */
		// Filter value
//		value[0] = PersonalKeyDAO.PKCS12_RSA + "";
		// Filter type
//		value[1] = DataBaseDictionary.FILTER_TYPE_PERSONALKEY_TYPE;

//		filterMap.put(DataBaseDictionary.FILTER_PERSONALKEY_TYPE, value);

		// Get all the PKCS RSA keys that belongs to the selected owner and
		// add the result to the previews one
//		res.addAll(getByAdvancedFilter(filterMap));

		res = personalKeyDB.getAllPrivateKeys(subjectId);
		return res;
	}

	/**
	 * Gets a list of personalKeys that were founded using the specified filter
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
	 * @return A list of personalKeys that agrees with the filter
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<PersonalKeyDAO> getByAdvancedFilter(Map<String, String[]> filter)
			throws DBException {
		return personalKeyDB.getByAdvancedFilter(filter);
	}

	/**
	 * Get the total count of rows in PersonalKey table
	 * 
	 * @return
	 */
	public Integer getCount() {
		return personalKeyDB.getCount();
	}

	/**
	 * Get the current Id in PersonalKey table
	 * 
	 * @return An integer that represents the current id
	 */
	public Integer getCurrentId() {
		return personalKeyDB.getCurrentId();
	}
}
