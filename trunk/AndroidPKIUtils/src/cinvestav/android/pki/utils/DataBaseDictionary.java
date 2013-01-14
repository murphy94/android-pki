/**
 *  Created on  : January 24, 2012
 *  Author      : Ing. Javier Silva Pérez
 *  Description :
 *  	Static class in which are saved all the intructions for the DB like
 *  	SELECTs, INSTERTs, UPDATEs, etc, this instructions are saved as
 *  	PreparedStatements
 *  
 */
package cinvestav.android.pki.utils;

import java.io.File;
import java.text.DateFormat;
import java.text.SimpleDateFormat;

/**
 * 
 * @author Ing. Javier Silva Pérez
 */
public class DataBaseDictionary {

	public static final String FILE_SEPARATOR = File.separator;

	public static final DateFormat FORMATTER_VIEW = new SimpleDateFormat(
			"dd-MM-yyyy");
	public static final DateFormat FORMATTER_DB = new SimpleDateFormat(
			"yyyy-MM-dd");
	/**
	 * Possible Data Types
	 */
	/**
	 * Simple String, in this case the search will not use any joker
	 */
	public static final String STRING_SIMPLE = "String";
	/**
	 * Joker String, in this case the search will be made using the joker '%' at
	 * the end of the string
	 */
	public static final String STRING_JOKER = "StringL";
	/**
	 * Double Joker, in this case the search will be made using the joker '%' at
	 * the end and beginning of the string
	 */
	public static final String STRING_DOBLE_JOKER = "LStringL";
	/**
	 * For integer value, a parser to Integer will be used
	 */
	public static final String NUMBER_TYPE = "int";

	public static final String DATABASE_NAME = "pki_movil_db";

	public static final String TABLE_SUBJECT = "Subject";
	public static final String TABLE_PERSONAL_KEY = "PersonalKey";
	public static final String TABLE_CERTIFICATE = "Certificate";
	public static final String TABLE_CRL = "CRL";
	public static final String TABLE_TRUSTED_CERTIFICATE = "TrustedCertificate";

	/**
	 * Table columns name
	 */
	/* Subject */
	public static final String COLUMN_NAME_SUBJECT_ID = "ide_sub";
	public static final String COLUMN_NAME_SUBJECT_NAME = "nam_sub";
	public static final String COLUMN_NAME_SUBJECT_ACTIVE = "act_sub";
	public static final String COLUMN_NAME_SUBJECT_DEVICE = "dev_sub";

	/* Personal Key */
	public static final String COLUMN_NAME_PERSONAL_KEY_ID = "ide_key";
	public static final String COLUMN_NAME_PERSONAL_KEY_DATA = "dat_key";
	public static final String COLUMN_NAME_PERSONAL_KEY_KEYID = "kid_key";
	public static final String COLUMN_NAME_PERSONAL_KEY_TYPE = "typ_key";
	public static final String COLUMN_NAME_PERSONAL_KEY_COMMENT = "com_key";
	public static final String COLUMN_NAME_PERSONAL_KEY_CREATION_DATE = "dte_key";
	// public static final String COLUMN_NAME_PERSONAL_KEY_SUBJECT_ID =
	// "ide_sub";

	/* Certificate */
	public static final String COLUMN_NAME_CERTIFICATE_ID = "ide_cer";
	public static final String COLUMN_NAME_CERTIFICATE_DATA = "dat_cer";
	public static final String COLUMN_NAME_CERTIFICATE_SERIAL_NUMBER = "num_cer";
	public static final String COLUMN_NAME_CERTIFICATE_CA_CERITIFICATE_ID = "ca_cer";
	// public static final String COLUMN_NAME_CERTIFICATE_SUBJECT_ID =
	// "ide_sub";
	public static final String COLUMN_NAME_CERTIFICATE_STATUS = "sta_cer";
	public static final String COLUMN_NAME_CERTIFICATE_LAST_UPDATE = "upd_cer";
	public static final String COLUMN_NAME_CERTIFICATE_SIGN_DEVICE = "dev_cer";
	public static final String COLUMN_NAME_CERTIFICATE_SUBJET_KEY_ID = "key_cer";

	/* Trusted Certificate */
	public static final String COLUMN_NAME_TRUSTED_CERTIFICATE_ID = "ide_trc";
	public static final String COLUMN_NAME_TRUSTED_CERTIFICATE_LEVEL = "lvl_trc";
	// public static final String COLUMN_NAME_TRUSTED_CERTIFICATE_SUBJECT_ID =
	// "ide_sub";
	// public static final String COLUMN_NAME_TRUSTED_CERTIFICATE_CERTIFICATE_ID
	// = "ide_cer";

	/* CRL */
	public static final String COLUMN_NAME_CRL_ID = "ide_crl";
	public static final String COLUMN_NAME_CRL_SERIAL_NUMBER = "num_crl";
	public static final String COLUMN_NAME_CRL_PUBLISH_DATE = "dat_crl";
	public static final String COLUMN_NAME_CRL_DESCRIPTION = "des_crl";
	public static final String COLUMN_NAME_CRL_DATA = "crl_crl";
	// public static final String COLUMN_NAME_CRL_ISSUER_CERTIFICATE_ID =
	// "ide_cer";
	public static final String COLUMN_NAME_CRL_IS_PUBLISHED = "pub_crl";

	/** Beginning of SELECTs **/

	public static final String GET_ALL_PERSONALKEY = "SELECT * FROM PersonalKey";

	public static final String GET_ALL_SUBJECT = "SELECT * FROM Subject WHERE act_sub=\"true\"";

	public static final String GET_ALL_CERTIFICATE = "SELECT * FROM Certificate ";
	/*
	 * + ALIAS_CERTIFICATE + " INNER JOIN Certificate " + ALIAS_CACERTIFICATE +
	 * "ON " + ALIAS_CERTIFICATE + ".ca_cer=" + ALIAS_CERTIFICATE +
	 * ".ide_cer INNER JOIN Subject " + ALIAS_SUBJECT + "ON " +
	 * ALIAS_CERTIFICATE + ".ide_sub=" + ALIAS_SUBJECT +
	 * ".ide_sub INNER JOIN Subject " + ALIAS_CASUBJECT + "ON " +
	 * ALIAS_CACERTIFICATE + ".ide_sub = " + ALIAS_CASUBJECT + ".ide_sub ";
	 */

	public static final String GET_ALL_TRUSTED_CERTIFICATE = "SELECT * FROM TrustedCertificate ";

	public static final String GET_ALL_CRL = "SELECT * FROM CRL";
	/** END SELECTs **/

	/** BEGIN SEARCH FILTERS DEFINITION **/

	/** BEGIN Permission FILTERS **/
	public static String FILTER_PERMISSION_ID = "ide_per = ?";
	public static String FILTER_TYPE_PERMISSION_ID = DataBaseDictionary.NUMBER_TYPE;

	public static String FILTER_PERMISSION_NAME = "nam_per LIKE ?";
	public static String FILTER_TYPE_PERMISSION_NAME = DataBaseDictionary.STRING_DOBLE_JOKER;
	/** END Permission FILTERS **/

	/** BEGIN Device FILTERS **/
	public static String FILTER_DEVICE_ID = "ide_dev = ?";
	public static String FILTER_TYPE_DEVICE_ID = DataBaseDictionary.NUMBER_TYPE;

	public static String FILTER_DEVICE_UNIQUE_KEY = "uni_dev LIKE ?";
	public static String FILTER_TYPE_DEVICE_UNIQUE_KEY = DataBaseDictionary.STRING_DOBLE_JOKER;
	/** END Device FILTERS **/

	/** BEGIN PersonalKey FILTERS **/
	public static String FILTER_PERSONALKEY_ID = "ide_key = ?";
	public static String FILTER_TYPE_PERSONALKEY_ID = DataBaseDictionary.NUMBER_TYPE;

	public static String FILTER_PERSONALKEY_UNIQUE_KEY = "kid_key LIKE ?";
	public static String FILTER_TYPE_PERSONALKEY_UNIQUE_KEY = DataBaseDictionary.STRING_DOBLE_JOKER;

	public static String FILTER_PERSONALKEY_TYPE = "typ_key = ?";
	public static String FILTER_TYPE_PERSONALKEY_TYPE = DataBaseDictionary.NUMBER_TYPE;
	/** END PersonalKey FILTERS **/

	/** BEGIN Subject FILTERS **/
	public static String FILTER_SUBJECT_ID = "ide_sub = ?";
	public static String FILTER_TYPE_SUBJECT_ID = DataBaseDictionary.NUMBER_TYPE;

	public static String FILTER_SUBJECT_NAME = "nam_sub LIKE ?";
	public static String FILTER_TYPE_SUBJECT_NAME = DataBaseDictionary.STRING_DOBLE_JOKER;

	public static String FILTER_SUBJECT_NAME_EXACT = "nam_sub LIKE ?";
	public static String FILTER_TYPE_SUBJECT_NAME_EXACT = DataBaseDictionary.STRING_SIMPLE;

	public static String FILTER_SUBJECT_DEVICE = "dev_sub LIKE ?";
	public static String FILTER_TYPE_SUBJECT_DEVICE = DataBaseDictionary.STRING_SIMPLE;

	public static String FILTER_SUBJECT_ACTIVE = "act_sub = ?";
	public static String FILTER_TYPE_SUBJECT_ACTIVE = DataBaseDictionary.NUMBER_TYPE;
	/** END PermisSubjectsion FILTERS **/

	/** BEGIN Certificate FILTERS **/
	public static String FILTER_CERTIFICATE_ID = "ide_cer = ?";
	public static String FILTER_TYPE_CERTIFICATE_ID = DataBaseDictionary.NUMBER_TYPE;

	public static String FILTER_CERTIFICATE_SERIAL_NUMBER = "num_cer = ?";
	public static String FILTER_TYPE_CERTIFICATE_SERIAL_NUMBER = DataBaseDictionary.NUMBER_TYPE;

	public static String FILTER_CERTIFICATE_OWNER = "ide_sub = ?";
	public static String FILTER_TYPE_CERTIFICATE_OWNER = DataBaseDictionary.NUMBER_TYPE;

	public static String FILTER_CERTIFICATE_CA_ID = "ca_cer = ?";
	public static String FILTER_TYPE_CERTIFICATE_CA_ID = DataBaseDictionary.NUMBER_TYPE;

	public static String FILTER_CERTIFICATE_STATUS = "sta_cer = ?";
	public static String FILTER_TYPE_CERTIFICATE_STATUS = DataBaseDictionary.NUMBER_TYPE;

	public static String FILTER_CERTIFICATE_SIGN_DEVICE = "dev_cer = ?";
	public static String FILTER_TYPE_CERTIFICATE_SIGN_DEVICE = DataBaseDictionary.STRING_SIMPLE;

	public static String FILTER_CERTIFICATE_SUBJECT_KEY_ID = "key_cer = ?";
	public static String FILTER_TYPE_CERTIFICATE_SUBJECT_KEY_ID = DataBaseDictionary.STRING_SIMPLE;
	/** END Certificate FILTERS **/

	/** BEGIN TrustedCertificate FILTERS **/
	public static String FILTER_TRUSTED_CERTIFICATE_ID = "ide_trc = ?";
	public static String FILTER_TYPE_TRUSTED_CERTIFICATE_ID = DataBaseDictionary.NUMBER_TYPE;

	public static String FILTER_TRUSTED_CERTIFICATE_LEVEL = "lvl_trc = ?";
	public static String FILTER_TYPE_TRUSTED_CERTIFICATE_LEVEL = DataBaseDictionary.NUMBER_TYPE;
	/** END TrustedCertificate FILTERS **/

	/** BEGIN Entry FILTERS **/
	public static String FILTER_ENTRY_ID = "ide_ent = ?";
	public static String FILTER_TYPE_ENTRY_ID = DataBaseDictionary.NUMBER_TYPE;

	public static String FILTER_ENTRY_REASON = "rea_ent = ?";
	public static String FILTER_TYPE_ENTRY_REASON = DataBaseDictionary.NUMBER_TYPE;

	/*
	 * public static String FILTER_ENTRY_INITIAL_REVOCATION_DATE =
	 * "rev_ent >= ?"; public static String
	 * FILTER_TYPE_ENTRY_INITIAL_REVOCATION_DATE = DataBaseDictionary.DATE_TYPE;
	 * public static String FILTER_ENTRY_FINAL_REVOCATION_DATE = "rev_ent <= ?";
	 * public static String FILTER_TYPE_ENTRY_FINAL_REVOCATION_DATE =
	 * DataBaseDictionary.DATE_TYPE;
	 * 
	 * public static String FILTER_ENTRY_INITIAL_INVALIDITY_DATE =
	 * "dat_ent >= ?"; public static String
	 * FILTER_TYPE_ENTRY_INITIAL_INVALIDITY_DATE = DataBaseDictionary.DATE_TYPE;
	 * public static String FILTER_ENTRY_FINAL_INVALIDITY_DATE = "dat_ent <= ?";
	 * public static String FILTER_TYPE_ENTRY_FINAL_INVALIDITY_DATE =
	 * DataBaseDictionary.DATE_TYPE;
	 */
	/** END Entry FILTERS **/

	/** BEGIN CRL FILTERS **/
	public static String FILTER_CRL_ID = "ide_crl = ?";
	public static String FILTER_TYPE_CRL_ID = DataBaseDictionary.NUMBER_TYPE;

	public static String FILTER_CRL_SERIAL_NUMBER = "num_crl = ?";
	public static String FILTER_TYPE_CRL_SERIAL_NUMBER = DataBaseDictionary.NUMBER_TYPE;

	/*
	 * public static String FILTER_CRL_INITIAL_PUBLISH_DATE = "dat_crl >= ?";
	 * public static String FILTER_TYPE_CRL_INITIAL_PUBLISH_DATE =
	 * DataBaseDictionary.DATE_TYPE; public static String
	 * FILTER_CRL_FINAL_PUBLISH_DATE = "dat_crl <= ?"; public static String
	 * FILTER_TYPE_CRL_FINAL_PUBLISH_DATE = DataBaseDictionary.DATE_TYPE;
	 * 
	 * public static String FILTER_CRL_IS_PUBLISHED = "pub_crl = ?"; public
	 * static String FILTER_TYPE_CRL_IS_PUBLISHED =
	 * DataBaseDictionary.BOOLEAN_TYPE;
	 */
	/** END CRL FILTERS **/

	/** END SEARCH FILTERS DEFINITION **/

}
