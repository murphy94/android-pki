/**
 *  Created on  : 30/07/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	This class implements all the methods for accessing the Data Base layer
 * classes, it should be the connection between the view layer an the database
 * layer for retrieve and modify subject information
 */
package cinvestav.android.pki.db.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase.CursorFactory;
import cinvestav.android.pki.db.dao.SubjectDAO;
import cinvestav.android.pki.db.db.SubjectDB;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.android.pki.utils.DataBaseDictionary;

/**
 * This class implements all the methods for accessing the Data Base layer
 * classes, it should be the connection between the view layer an the database
 * layer for retrieve and modify subject information
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 30/07/2012
 * @version 1.0
 */
public class SubjectController {

	SubjectDB subjectDB;

	/**
	 * 
	 * @param context
	 * @param name
	 * @param factory
	 * @param version
	 */
	public SubjectController(Context context, String name,
			CursorFactory factory, int version) {
		subjectDB = new SubjectDB(context, name, factory, version);
	}

	/**
	 * Constructor that inits the data base connection using application context
	 * 
	 * @param context
	 */
	public SubjectController(Context context) {
		subjectDB = new SubjectDB(context);
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
		return subjectDB.insert(subject);
	}

	/**
	 * Updates the subject in the data base
	 * 
	 * @param subject
	 *            SubjectDAO with the updated fields, the only field that won't
	 *            be modified is the Id
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public void update(SubjectDAO subject) throws DBException {
		subjectDB.update(subject);
	}

	/**
	 * Deletes a subject from the data base
	 * 
	 * @param subject
	 *            SubjectDAO that will be deleted, the register to be deleted
	 *            will be searched by id
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public void delete(SubjectDAO subject) throws DBException {
		subjectDB.delete(subject);
	}

	/**
	 * Gets the list of all the subjects saved in the data base
	 * 
	 * @return A list of subjects
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<SubjectDAO> getAll() throws DBException {
		return subjectDB.getAllSubjects();
	}

	/**
	 * Gets a {@link SubjectDAO} object filled with the Data base information
	 * using subject id as SQL filter
	 * 
	 * @param subjectId
	 *            Subject id to be used as filter in the SQL sentence
	 * @return a {@link SubjectDAO} object filled with the data base information
	 *         if the subject id was found, or an empty {@link SubjectDAO}
	 *         object (subject id = 0) if no results were found in the data base
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public SubjectDAO getById(Integer subjectId) throws DBException {
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
		List<SubjectDAO> resList = subjectDB.getByAdvancedFilter(filterMap);
		if (!resList.isEmpty()) {
			return resList.get(0);
		}
		return new SubjectDAO();
	}

	/**
	 * Gets a list of the subjects that contains the required name in their data
	 * base name field
	 * 
	 * @param name
	 *            Subject name that must be search for
	 * @return A List of {@link SubjectDAO} filled with the subject that
	 *         contains the name in the data base, if no coincidences are found,
	 *         an empty list will be returned
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<SubjectDAO> getByName(String name) throws DBException {
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
		value[0] = name + "";
		// Filter type
		value[1] = DataBaseDictionary.FILTER_TYPE_SUBJECT_NAME;

		filterMap.put(DataBaseDictionary.FILTER_SUBJECT_NAME, value);
		return subjectDB.getByAdvancedFilter(filterMap);
	}

	/**
	 * Gets a list of the subjects that contains the required deviceId in their
	 * data base device field
	 * 
	 * @param deviceId
	 *            Device ID that must be search for
	 * @return A List of {@link SubjectDAO} filled with the subject that
	 *         contains the name in the data base, if no coincidences are found,
	 *         an empty list will be returned
	 * @throws DBException
	 *             If something goes wrong during the SQL statement Execution
	 */
	public List<SubjectDAO> getByDeviceId(String deviceId) throws DBException {
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
		value[0] = deviceId + "";
		// Filter type
		value[1] = DataBaseDictionary.FILTER_TYPE_SUBJECT_DEVICE;

		filterMap.put(DataBaseDictionary.FILTER_SUBJECT_DEVICE, value);
		return subjectDB.getByAdvancedFilter(filterMap);
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
		return subjectDB.getByAdvancedFilter(filter);
	}

	/**
	 * Get the total count of rows in Subject table
	 * 
	 * @return
	 */
	public Integer getCount() {
		return subjectDB.getCount();
	}

	/**
	 * Get the current Id in Subject table
	 * 
	 * @return An integer that represents the current id
	 */
	public Integer getCurrentId() {
		return subjectDB.getCurrentId();
	}

}
