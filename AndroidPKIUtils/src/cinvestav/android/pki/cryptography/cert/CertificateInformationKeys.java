/**
 *  Created on  : 22/05/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	
 */
package cinvestav.android.pki.cryptography.cert;

import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;

import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.x500.style.BCStyle;

/**
 * Contains all supported field keys, that will be used to fill out the
 * certificate in the PKI
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 22/05/2012
 * @version 1.0
 */
public class CertificateInformationKeys {
	/**
	 * country code - StringType(SIZE(2))
	 */
	public static final String COUNTRY = "c";

	/**
	 * street - StringType(SIZE(1..64))
	 */
	public static final String STREET = "street";

	/**
	 * locality name - StringType(SIZE(1..64))
	 */
	public static final String LOCALITY = "l";

	/**
	 * state, or province name - StringType(SIZE(1..64))
	 */
	public static final String STATE = "st";

	/**
	 * postalCode - DirectoryString(SIZE(1..40)
	 */
	public static final String POSTAL_CODE = "postalcode";

	/**
	 * Domain Name Qualifier - DirectoryString(SIZE(1..64)
	 */
	public static final String DN_QUALIFIER = "dn";

	/**
	 * organization - StringType(SIZE(1..64))
	 */
	public static final String ORGANIZATION = "o";

	/**
	 * organizational unit name - StringType(SIZE(1..64))
	 */
	public static final String ORGANIZATION_UNITY = "ou";

	/**
	 * Title
	 */
	public static final String TITLE = "t";
	/**
	 * common name - StringType(SIZE(1..64))
	 */
	public static final String FULL_COMMON_NAME = "cn";

	/**
	 * device serial number name - StringType(SIZE(1..64))
	 */
	public static final String DEVICE_SERIAL_NUMBER_NAME = "sn";

	/**
	 * Naming attributes of type X520name
	 */
	public static final String SURNAME = "surname";
	public static final String GIVENNAME = "givenname";
	public static final String INITIALS = "initials";
	public static final String GENERATION = "generation";
	public static final String UNIQUE_IDENTIFIER = "uniqueidentifier";

	/**
	 * businessCategory - DirectoryString(SIZE(1..128)
	 */
	public static final String BUSINESS_CATEGORY = "businesscategory";

	/**
	 * RFC 3039 Pseudonym - DirectoryString(SIZE(1..64)
	 */
	public static final String PSEUDONYM = "pseudonym";

	/**
	 * RFC 3039 DateOfBirth - GeneralizedTime - YYYYMMDD000000Z
	 */
	public static final String DATE_OF_BIRTH = "dateofbirth";

	/**
	 * RFC 3039 PlaceOfBirth - DirectoryString(SIZE(1..128)
	 */
	public static final String PLACE_OF_BIRTH = "placeofbirth";

	/**
	 * RFC 3039 Gender - PrintableString (SIZE(1)) -- "M", "F", "m" or "f"
	 */
	public static final String GENDER = "gender";

	/**
	 * RFC 3039 CountryOfCitizenship - PrintableString (SIZE (2)) -- ISO 3166
	 * codes only
	 */
	public static final String COUNTRY_OF_CITIZENSHIP = "countryofcitizenship";

	/**
	 * RFC 3039 CountryOfResidence - PrintableString (SIZE (2)) -- ISO 3166
	 * codes only
	 */
	public static final String COUNTRY_OF_RESIDENCE = "countryofresidence";

	/**
	 * ISIS-MTT NameAtBirth - DirectoryString(SIZE(1..64)
	 */
	public static final String NAME_AT_BIRTH = "nameofbirth";

	/**
	 * RFC 3039 PostalAddress - SEQUENCE SIZE (1..6) OF
	 * DirectoryString(SIZE(1..30))
	 */
	public static final String POSTAL_ADDRESS = "postaladdress";

	/**
	 * id-at-telephoneNumber
	 */
	public static final String TELEPHONE_NUMBER = "telephonenumber";

	/**
	 * id-at-name
	 */
	public static final String NAME = "name";

	/**
	 * Email address
	 */
	public static final String EmailAddress = "emailaddress";

	/**
	 * more from PKCS#9
	 */
	public static final String UnstructuredName = "unstructuredname";
	public static final String UnstructuredAddress = "unstructuredaddress";

	/*
	 * others...
	 */
	public static final String DC = "dc";

	/**
	 * LDAP User id.
	 */
	public static final String UID = "uid";

	/**
	 * Friendly name for the certificate
	 */
	public static final String FRIENDLY_NAME = "FRIENDLY_NAME";

	/**
	 * ID of the device in which the certificate has been created
	 */
	public static final String DEVICE_ID = "DEVICE_ID";

	/**
	 * ID of the device in which the certificate has been signed
	 */
	public static final String SIGN_DEVICE_ID = "SIGN_DEVICE_ID";

	/**
	 * GPS Latitude coordinate position in which the certificate has been
	 * created
	 */
	public static final String CREATION_POSITION_LATITUDE = "CREATION_POSITION_LATITUDE";

	/**
	 * GPS longitude coordinate position in which the certificate has been
	 * created
	 */
	public static final String CREATION_POSITION_LONGITUDE = "CREATION_POSITION_LONGITUDE";

	/**
	 * Document used for identify the user during identity confirmation process
	 */
	public static final String IDENTIFICATION_DOCUMENT = "IDENTIFICATION_DOCUMENT";

	/**
	 * Permission Id corresponding to this certificate in the organization
	 */
	public static final String USER_PERMISSION_ID = "USER_PERMISSION_ID";

	/**
	 * ID of the user, this id should be the one saved in the company registry
	 */
	public static final String USER_ID = "USER_ID";

	/**
	 * Serial number of the CA certificate that signs the certificate
	 */
	public static final String CA_CERTIFICATE_SERIAL_NUMBER = "CA_CERTIFICATE_SERIAL_NUMBER";

	/**
	 * Sign Device Id of the CA certificate
	 */
	public static final String CA_CERTIFICATE_SIGN_DEVICE_ID = "CA_CERTIFICATE_SIGN_DEVICE_ID";

	/**
	 * Authority key Id of the CA that signs the certificate, means the Key Id
	 * of the next level CA
	 */
	public static final String CA_CERTIFICATE_SIGN_AUTHORITY_KEY_ID = "CA_CERTIFICATE_SIGN_AUTHORITY_KEY_ID";

	/**
	 * Public OID in range to the OID registered in IANA for Key SD - PKI
	 * project for Device ID certificate field
	 */
	public static final ASN1ObjectIdentifier DEVICE_ID_OID = new ASN1ObjectIdentifier(
			"1.3.6.1.4.1.40611.1");

	/**
	 * Public OID in range to the OID registered in IANA for Key SD - PKI
	 * project for Sign Device ID certificate field
	 */
	public static final ASN1ObjectIdentifier SIGN_DEVICE_ID_OID = new ASN1ObjectIdentifier(
			"1.3.6.1.4.1.40611.6");

	/**
	 * Public OID in range to the OID registered in IANA for Key SD - PKI
	 * project for Creation position x certificate field
	 */
	public static final ASN1ObjectIdentifier CREATION_POSITION_LATITUDE_OID = new ASN1ObjectIdentifier(
			"1.3.6.1.4.1.40611.2.1");

	/**
	 * Public OID in range to the OID registered in IANA for Key SD - PKI
	 * project for Creation position x certificate field
	 */
	public static final ASN1ObjectIdentifier CREATION_POSITION_LONGITUDE_OID = new ASN1ObjectIdentifier(
			"1.3.6.1.4.1.40611.2.2");

	/**
	 * Public OID in range to the OID registered in IANA for Key SD - PKI
	 * project for User id certificate field
	 */
	public static final ASN1ObjectIdentifier USER_ID_OID = new ASN1ObjectIdentifier(
			"1.3.6.1.4.1.40611.3");

	/**
	 * Public OID in range to the OID registered in IANA for Key SD - PKI
	 * project for Identification document certificate field
	 */
	public static final ASN1ObjectIdentifier IDENTIFICATION_DOCUMENT_OID = new ASN1ObjectIdentifier(
			"1.3.6.1.4.1.40611.4");

	/**
	 * Public OID in range to the OID registered in IANA for Key SD - PKI
	 * project for User Permission certificate field
	 */
	public static final ASN1ObjectIdentifier USER_PERMISSION_OID = new ASN1ObjectIdentifier(
			"1.3.6.1.4.1.40611.5");

	/**
	 * Public OID in range to the OID registered in IANA for Key SD - PKI
	 * project for the serial number of the CA certificate used for sign the
	 * certificate
	 */
	public static final ASN1ObjectIdentifier CA_CERTIFICATE_SERIAL_NUMBER_OID = new ASN1ObjectIdentifier(
			"1.3.6.1.4.1.40611.7.1");

	/**
	 * Public OID in range to the OID registered in IANA for Key SD - PKI
	 * project for the sign device id of the CA certificate used for sign the
	 * certificate
	 */
	public static final ASN1ObjectIdentifier CA_CERTIFICATE_SIGN_DEVICE_ID_OID = new ASN1ObjectIdentifier(
			"1.3.6.1.4.1.40611.7.2");

	/**
	 * Public OID in range to the OID registered in IANA for Key SD - PKI
	 * project for the authority key id of the CA certificate used for sign the
	 * certificate
	 */
	public static final ASN1ObjectIdentifier CA_CERTIFICATE_SIGN_AUTHORITY_KEY_ID_OID = new ASN1ObjectIdentifier(
			"1.3.6.1.4.1.40611.7.3");

	/**
	 * default look up table translating OID values into their common symbols
	 * following the convention in RFC 2253 with a few extras
	 */
	public static final Hashtable<ASN1ObjectIdentifier, String> DEFAULT_NAME_LOOK_UP = new Hashtable<ASN1ObjectIdentifier, String>();

	/**
	 * look up table translating common symbols into their OIDS.
	 */
	public static final Hashtable<String, ASN1ObjectIdentifier> ASN1_OID_LOOK_UP = new Hashtable<String, ASN1ObjectIdentifier>();

	/**
	 * Return a multilanguage String equivalence of the certificate map key, if
	 * the desired language is not available the key name will be returned in
	 * English
	 * 
	 * @param keyName
	 *            CertificateInformation Map key name to be translated
	 * @param language
	 *            ISO Language code to be used for getting the String
	 *            equivalence
	 * @return The string equivalence of the certificate map key name
	 */
	public static String getKeyNameStr(String keyName, String language) {
		if (language.equalsIgnoreCase("ES")) {
			return KEY_NAME_STR_LOOK_UP.get(keyName + "_ES");
		} else {
			return KEY_NAME_STR_LOOK_UP.get(keyName);
		}

	}

	public static final Hashtable<String, String> KEY_NAME_STR_LOOK_UP = new Hashtable<String, String>();
	public static final Hashtable<String, String> KEY_CODE_LOOK_UP = new Hashtable<String, String>();
	public static final List<String> CUSTOM_EXTENSION = new LinkedList<String>();

	static {
		DEFAULT_NAME_LOOK_UP.put(BCStyle.C, COUNTRY);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.O, ORGANIZATION);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.T, TITLE);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.OU, ORGANIZATION_UNITY);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.CN, FULL_COMMON_NAME);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.L, LOCALITY);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.ST, STATE);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.SN, DEVICE_SERIAL_NUMBER_NAME);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.EmailAddress, EmailAddress);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.DC, DC);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.UID, UID);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.STREET, STREET);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.SURNAME, SURNAME);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.GIVENNAME, GIVENNAME);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.INITIALS, INITIALS);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.GENERATION, GENERATION);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.UnstructuredAddress,
				UnstructuredAddress);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.UnstructuredName, UnstructuredName);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.UNIQUE_IDENTIFIER, UNIQUE_IDENTIFIER);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.DN_QUALIFIER, DN_QUALIFIER);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.PSEUDONYM, PSEUDONYM);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.POSTAL_ADDRESS, POSTAL_ADDRESS);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.NAME_AT_BIRTH, NAME_AT_BIRTH);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.COUNTRY_OF_CITIZENSHIP,
				COUNTRY_OF_CITIZENSHIP);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.COUNTRY_OF_RESIDENCE,
				COUNTRY_OF_RESIDENCE);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.GENDER, GENDER);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.PLACE_OF_BIRTH, PLACE_OF_BIRTH);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.DATE_OF_BIRTH, DATE_OF_BIRTH);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.POSTAL_CODE, POSTAL_CODE);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.BUSINESS_CATEGORY, BUSINESS_CATEGORY);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.TELEPHONE_NUMBER, TELEPHONE_NUMBER);
		DEFAULT_NAME_LOOK_UP.put(BCStyle.NAME, NAME);
		DEFAULT_NAME_LOOK_UP.put(USER_ID_OID, USER_ID);
		DEFAULT_NAME_LOOK_UP.put(DEVICE_ID_OID, DEVICE_ID);
		DEFAULT_NAME_LOOK_UP.put(USER_PERMISSION_OID, USER_PERMISSION_ID);
		DEFAULT_NAME_LOOK_UP.put(IDENTIFICATION_DOCUMENT_OID,
				IDENTIFICATION_DOCUMENT);
		DEFAULT_NAME_LOOK_UP.put(CREATION_POSITION_LATITUDE_OID,
				CREATION_POSITION_LATITUDE);
		DEFAULT_NAME_LOOK_UP.put(CREATION_POSITION_LONGITUDE_OID,
				CREATION_POSITION_LONGITUDE);

		ASN1_OID_LOOK_UP.put(COUNTRY, BCStyle.C);
		ASN1_OID_LOOK_UP.put(ORGANIZATION, BCStyle.O);
		ASN1_OID_LOOK_UP.put(TITLE, BCStyle.T);
		ASN1_OID_LOOK_UP.put(ORGANIZATION_UNITY, BCStyle.OU);
		ASN1_OID_LOOK_UP.put(FULL_COMMON_NAME, BCStyle.CN);
		ASN1_OID_LOOK_UP.put(LOCALITY, BCStyle.L);
		ASN1_OID_LOOK_UP.put(STATE, BCStyle.ST);
		ASN1_OID_LOOK_UP.put(DEVICE_SERIAL_NUMBER_NAME, BCStyle.SN);
		ASN1_OID_LOOK_UP.put("serialnumber", BCStyle.SN);
		ASN1_OID_LOOK_UP.put(STREET, BCStyle.STREET);
		ASN1_OID_LOOK_UP.put(EmailAddress, BCStyle.E);
		ASN1_OID_LOOK_UP.put(DC, BCStyle.DC);
		ASN1_OID_LOOK_UP.put("e", BCStyle.E);
		ASN1_OID_LOOK_UP.put(UID, BCStyle.UID);
		ASN1_OID_LOOK_UP.put(SURNAME, BCStyle.SURNAME);
		ASN1_OID_LOOK_UP.put(GIVENNAME, BCStyle.GIVENNAME);
		ASN1_OID_LOOK_UP.put(INITIALS, BCStyle.INITIALS);
		ASN1_OID_LOOK_UP.put(GENERATION, BCStyle.GENERATION);
		ASN1_OID_LOOK_UP.put(UnstructuredAddress, BCStyle.UnstructuredAddress);
		ASN1_OID_LOOK_UP.put(UnstructuredName, BCStyle.UnstructuredName);
		ASN1_OID_LOOK_UP.put(UNIQUE_IDENTIFIER, BCStyle.UNIQUE_IDENTIFIER);
		ASN1_OID_LOOK_UP.put(DN_QUALIFIER, BCStyle.DN_QUALIFIER);
		ASN1_OID_LOOK_UP.put(PSEUDONYM, BCStyle.PSEUDONYM);
		ASN1_OID_LOOK_UP.put(POSTAL_ADDRESS, BCStyle.POSTAL_ADDRESS);
		ASN1_OID_LOOK_UP.put(NAME_AT_BIRTH, BCStyle.NAME_AT_BIRTH);
		ASN1_OID_LOOK_UP.put(COUNTRY_OF_CITIZENSHIP,
				BCStyle.COUNTRY_OF_CITIZENSHIP);
		ASN1_OID_LOOK_UP
				.put(COUNTRY_OF_RESIDENCE, BCStyle.COUNTRY_OF_RESIDENCE);
		ASN1_OID_LOOK_UP.put(GENDER, BCStyle.GENDER);
		ASN1_OID_LOOK_UP.put(PLACE_OF_BIRTH, BCStyle.PLACE_OF_BIRTH);
		ASN1_OID_LOOK_UP.put(DATE_OF_BIRTH, BCStyle.DATE_OF_BIRTH);
		ASN1_OID_LOOK_UP.put(POSTAL_CODE, BCStyle.POSTAL_CODE);
		ASN1_OID_LOOK_UP.put(BUSINESS_CATEGORY, BCStyle.BUSINESS_CATEGORY);
		ASN1_OID_LOOK_UP.put(TELEPHONE_NUMBER, BCStyle.TELEPHONE_NUMBER);
		ASN1_OID_LOOK_UP.put(NAME, BCStyle.NAME);
		ASN1_OID_LOOK_UP.put(USER_ID, USER_ID_OID);
		ASN1_OID_LOOK_UP.put(DEVICE_ID, DEVICE_ID_OID);
		ASN1_OID_LOOK_UP.put(USER_PERMISSION_ID, USER_PERMISSION_OID);
		ASN1_OID_LOOK_UP.put(IDENTIFICATION_DOCUMENT,
				IDENTIFICATION_DOCUMENT_OID);
		ASN1_OID_LOOK_UP.put(CREATION_POSITION_LATITUDE,
				CREATION_POSITION_LATITUDE_OID);
		ASN1_OID_LOOK_UP.put(CREATION_POSITION_LONGITUDE,
				CREATION_POSITION_LONGITUDE_OID);

		/** English **/
		KEY_NAME_STR_LOOK_UP.put(COUNTRY, "Country");
		KEY_NAME_STR_LOOK_UP.put(ORGANIZATION, "Organization");
		KEY_NAME_STR_LOOK_UP.put(TITLE, "Title");
		KEY_NAME_STR_LOOK_UP.put(ORGANIZATION_UNITY, "Organization unity");
		KEY_NAME_STR_LOOK_UP.put(FULL_COMMON_NAME, "Common name");
		KEY_NAME_STR_LOOK_UP.put(LOCALITY, "Locality");
		KEY_NAME_STR_LOOK_UP.put(STATE, "State");
		KEY_NAME_STR_LOOK_UP.put(DEVICE_SERIAL_NUMBER_NAME, "Serial number");
		KEY_NAME_STR_LOOK_UP.put("serialnumber", "Serial number");
		KEY_NAME_STR_LOOK_UP.put(STREET, "Street");
		KEY_NAME_STR_LOOK_UP.put(EmailAddress, "Email address");
		KEY_NAME_STR_LOOK_UP.put(DC, "DC");
		KEY_NAME_STR_LOOK_UP.put("e", "Email address");
		KEY_NAME_STR_LOOK_UP.put(UID, "UID");
		KEY_NAME_STR_LOOK_UP.put(SURNAME, "Surname");
		KEY_NAME_STR_LOOK_UP.put(GIVENNAME, "Given name");
		KEY_NAME_STR_LOOK_UP.put(INITIALS, "Initials");
		KEY_NAME_STR_LOOK_UP.put(GENERATION, "Generation");
		KEY_NAME_STR_LOOK_UP.put(UnstructuredAddress, "Unstructured address");
		KEY_NAME_STR_LOOK_UP.put(UnstructuredName, "Unstructured name");
		KEY_NAME_STR_LOOK_UP.put(UNIQUE_IDENTIFIER, "Unique identifier");
		KEY_NAME_STR_LOOK_UP.put(DN_QUALIFIER, "DN Qualifier");
		KEY_NAME_STR_LOOK_UP.put(PSEUDONYM, "Pseudonym");
		KEY_NAME_STR_LOOK_UP.put(POSTAL_ADDRESS, "Postal address");
		KEY_NAME_STR_LOOK_UP.put(NAME_AT_BIRTH, "Name at birth");
		KEY_NAME_STR_LOOK_UP.put(COUNTRY_OF_CITIZENSHIP,
				"Country of citizenship");
		KEY_NAME_STR_LOOK_UP.put(COUNTRY_OF_RESIDENCE, "Country of residence");
		KEY_NAME_STR_LOOK_UP.put(GENDER, "Gender");
		KEY_NAME_STR_LOOK_UP.put(PLACE_OF_BIRTH, "Place of birth");
		KEY_NAME_STR_LOOK_UP.put(DATE_OF_BIRTH, "Date of birth");
		KEY_NAME_STR_LOOK_UP.put(POSTAL_CODE, "Postal code");
		KEY_NAME_STR_LOOK_UP.put(BUSINESS_CATEGORY, "Business category");
		KEY_NAME_STR_LOOK_UP.put(TELEPHONE_NUMBER, "Telephone number");
		KEY_NAME_STR_LOOK_UP.put(NAME, "Name");
		KEY_NAME_STR_LOOK_UP.put(USER_ID, "Company user ID");
		KEY_NAME_STR_LOOK_UP.put(DEVICE_ID, "Device ID");
		KEY_NAME_STR_LOOK_UP.put(USER_PERMISSION_ID, "User permission IDs");
		KEY_NAME_STR_LOOK_UP.put(IDENTIFICATION_DOCUMENT,
				"Identification document");
		KEY_NAME_STR_LOOK_UP.put(CREATION_POSITION_LATITUDE,
				"Creation position (X)");
		KEY_NAME_STR_LOOK_UP.put(CREATION_POSITION_LONGITUDE,
				"Creation position (Y)");

		/** Spanish **/
		KEY_NAME_STR_LOOK_UP.put(COUNTRY + "_ES", "País");
		KEY_NAME_STR_LOOK_UP.put(ORGANIZATION + "_ES", "Organización");
		KEY_NAME_STR_LOOK_UP.put(TITLE + "_ES", "Título");
		KEY_NAME_STR_LOOK_UP.put(ORGANIZATION_UNITY + "_ES",
				"Unidad organizacional");
		KEY_NAME_STR_LOOK_UP.put(FULL_COMMON_NAME + "_ES", "Nombre común");
		KEY_NAME_STR_LOOK_UP.put(LOCALITY + "_ES", "Localidad");
		KEY_NAME_STR_LOOK_UP.put(STATE + "_ES", "Estado");
		KEY_NAME_STR_LOOK_UP.put(DEVICE_SERIAL_NUMBER_NAME + "_ES",
				"Número de serie");
		KEY_NAME_STR_LOOK_UP.put("serialnumber" + "_ES", "Número de serie");
		KEY_NAME_STR_LOOK_UP.put(STREET + "_ES", "Calle");
		KEY_NAME_STR_LOOK_UP.put(EmailAddress + "_ES", "Correo electrónico");
		KEY_NAME_STR_LOOK_UP.put(DC + "_ES", "DC");
		KEY_NAME_STR_LOOK_UP.put("e" + "_ES", "Correo electrónico");
		KEY_NAME_STR_LOOK_UP.put(UID + "_ES", "UID");
		KEY_NAME_STR_LOOK_UP.put(SURNAME + "_ES", "Apellido");
		KEY_NAME_STR_LOOK_UP.put(GIVENNAME + "_ES", "Nombre de pila");
		KEY_NAME_STR_LOOK_UP.put(INITIALS + "_ES", "Iniciales");
		KEY_NAME_STR_LOOK_UP.put(GENERATION + "_ES", "Generación");
		KEY_NAME_STR_LOOK_UP.put(UnstructuredAddress + "_ES",
				"Dirección (sin estructura)");
		KEY_NAME_STR_LOOK_UP.put(UnstructuredName + "_ES",
				"Nombre (sin estructura)");
		KEY_NAME_STR_LOOK_UP.put(UNIQUE_IDENTIFIER + "_ES",
				"Identificador único");
		KEY_NAME_STR_LOOK_UP.put(DN_QUALIFIER + "_ES", "Calificador DN");
		KEY_NAME_STR_LOOK_UP.put(PSEUDONYM + "_ES", "Pseudónimo");
		KEY_NAME_STR_LOOK_UP.put(POSTAL_ADDRESS + "_ES", "Dirección postal");
		KEY_NAME_STR_LOOK_UP.put(NAME_AT_BIRTH + "_ES", "Nombre de nacimiento");
		KEY_NAME_STR_LOOK_UP
				.put(COUNTRY_OF_CITIZENSHIP + "_ES", "Nacionalidad");
		KEY_NAME_STR_LOOK_UP.put(COUNTRY_OF_RESIDENCE + "_ES",
				"País de residencia");
		KEY_NAME_STR_LOOK_UP.put(GENDER + "_ES", "Genero");
		KEY_NAME_STR_LOOK_UP.put(PLACE_OF_BIRTH + "_ES", "Lugar de nacimiento");
		KEY_NAME_STR_LOOK_UP.put(DATE_OF_BIRTH + "_ES", "Fecha de nacimiento");
		KEY_NAME_STR_LOOK_UP.put(POSTAL_CODE + "_ES", "Código Postal");
		KEY_NAME_STR_LOOK_UP.put(BUSINESS_CATEGORY + "_ES",
				"Categoría del negocio");
		KEY_NAME_STR_LOOK_UP
				.put(TELEPHONE_NUMBER + "_ES", "Número de telefono");
		KEY_NAME_STR_LOOK_UP.put(NAME + "_ES", "Nombre");
		KEY_NAME_STR_LOOK_UP.put(USER_ID + "_ES",
				"Id de usuario en la organización");
		KEY_NAME_STR_LOOK_UP.put(DEVICE_ID + "_ES", "ID Dispositivo");
		KEY_NAME_STR_LOOK_UP.put(USER_PERMISSION_ID + "_ES",
				"Permisos en la organización");
		KEY_NAME_STR_LOOK_UP.put(IDENTIFICATION_DOCUMENT + "_ES",
				"Documento de identificación");
		KEY_NAME_STR_LOOK_UP.put(CREATION_POSITION_LATITUDE + "_ES",
				"Ubicación GPS de creación (X)");
		KEY_NAME_STR_LOOK_UP.put(CREATION_POSITION_LONGITUDE + "_ES",
				"Ubicación GPS de creación (Y)");

		/** English **/
		KEY_CODE_LOOK_UP.put("country", COUNTRY);
		KEY_CODE_LOOK_UP.put("organization", ORGANIZATION);
		KEY_CODE_LOOK_UP.put("title", TITLE);
		KEY_CODE_LOOK_UP.put("organization unity", ORGANIZATION_UNITY);
		KEY_CODE_LOOK_UP.put("common name", FULL_COMMON_NAME);
		KEY_CODE_LOOK_UP.put("locality", LOCALITY);
		KEY_CODE_LOOK_UP.put("state", STATE);
		KEY_CODE_LOOK_UP.put("serial number", DEVICE_SERIAL_NUMBER_NAME);
		KEY_CODE_LOOK_UP.put("street", STREET);
		KEY_CODE_LOOK_UP.put("email address", EmailAddress);
		KEY_CODE_LOOK_UP.put("dc", DC);
		KEY_CODE_LOOK_UP.put("uid", UID);
		KEY_CODE_LOOK_UP.put("surname", SURNAME);
		KEY_CODE_LOOK_UP.put("given name", GIVENNAME);
		KEY_CODE_LOOK_UP.put("initials", INITIALS);
		KEY_CODE_LOOK_UP.put("generation", GENERATION);
		KEY_CODE_LOOK_UP.put("unstructured address", UnstructuredAddress);
		KEY_CODE_LOOK_UP.put("unstructured name", UnstructuredName);
		KEY_CODE_LOOK_UP.put("unique identifier", UNIQUE_IDENTIFIER);
		KEY_CODE_LOOK_UP.put("dn qualifier", DN_QUALIFIER);
		KEY_CODE_LOOK_UP.put("pseudonym", PSEUDONYM);
		KEY_CODE_LOOK_UP.put("postal address", POSTAL_ADDRESS);
		KEY_CODE_LOOK_UP.put("name at birth", NAME_AT_BIRTH);
		KEY_CODE_LOOK_UP.put("country of citizenship", COUNTRY_OF_CITIZENSHIP);
		KEY_CODE_LOOK_UP.put("country of residence", COUNTRY_OF_RESIDENCE);
		KEY_CODE_LOOK_UP.put("gender", GENDER);
		KEY_CODE_LOOK_UP.put("place of birth", PLACE_OF_BIRTH);
		KEY_CODE_LOOK_UP.put("date of birth", DATE_OF_BIRTH);
		KEY_CODE_LOOK_UP.put("postal code", POSTAL_CODE);
		KEY_CODE_LOOK_UP.put("business category", BUSINESS_CATEGORY);
		KEY_CODE_LOOK_UP.put("telephone number", TELEPHONE_NUMBER);
		KEY_CODE_LOOK_UP.put("name", NAME);
		KEY_CODE_LOOK_UP.put("company user id", USER_ID);
		KEY_CODE_LOOK_UP.put("device id", DEVICE_ID);
		KEY_CODE_LOOK_UP.put("user permission ids", USER_PERMISSION_ID);
		KEY_CODE_LOOK_UP
				.put("Identification document", IDENTIFICATION_DOCUMENT);
		KEY_CODE_LOOK_UP.put("creation position (x)",
				CREATION_POSITION_LATITUDE);
		KEY_CODE_LOOK_UP.put("creation position (y)",
				CREATION_POSITION_LONGITUDE);

		/** Spanish **/
		KEY_CODE_LOOK_UP.put("país", COUNTRY);
		KEY_CODE_LOOK_UP.put("organización", ORGANIZATION);
		KEY_CODE_LOOK_UP.put("título", TITLE);
		KEY_CODE_LOOK_UP.put("unidad organizacional", ORGANIZATION_UNITY);
		KEY_CODE_LOOK_UP.put("nombre común", FULL_COMMON_NAME);
		KEY_CODE_LOOK_UP.put("localidad", LOCALITY);
		KEY_CODE_LOOK_UP.put("estado", STATE);
		KEY_CODE_LOOK_UP.put("número de serie", DEVICE_SERIAL_NUMBER_NAME);
		KEY_CODE_LOOK_UP.put("calle", STREET);
		KEY_CODE_LOOK_UP.put("correo electrónico", EmailAddress);
		KEY_CODE_LOOK_UP.put("apellido", SURNAME);
		KEY_CODE_LOOK_UP.put("nombre de pila", GIVENNAME);
		KEY_CODE_LOOK_UP.put("iniciales", INITIALS);
		KEY_CODE_LOOK_UP.put("generación", GENERATION);
		KEY_CODE_LOOK_UP.put("dirección (sin estructura)", UnstructuredAddress);
		KEY_CODE_LOOK_UP.put("nombre (sin estructura)", UnstructuredName);
		KEY_CODE_LOOK_UP.put("identificador único", UNIQUE_IDENTIFIER);
		KEY_CODE_LOOK_UP.put("calificador dn", DN_QUALIFIER);
		KEY_CODE_LOOK_UP.put("pseudónimo", PSEUDONYM);
		KEY_CODE_LOOK_UP.put("dirección postal", POSTAL_ADDRESS);
		KEY_CODE_LOOK_UP.put("nombre de nacimiento", NAME_AT_BIRTH);
		KEY_CODE_LOOK_UP.put("nacionalidad", COUNTRY_OF_CITIZENSHIP);
		KEY_CODE_LOOK_UP.put("país de residencia", COUNTRY_OF_RESIDENCE);
		KEY_CODE_LOOK_UP.put("genero", GENDER);
		KEY_CODE_LOOK_UP.put("lugar de nacimiento", PLACE_OF_BIRTH);
		KEY_CODE_LOOK_UP.put("fecha de nacimiento", DATE_OF_BIRTH);
		KEY_CODE_LOOK_UP.put("código Postal", POSTAL_CODE);
		KEY_CODE_LOOK_UP.put("categoría del negocio", BUSINESS_CATEGORY);
		KEY_CODE_LOOK_UP.put("número de telefono", TELEPHONE_NUMBER);
		KEY_CODE_LOOK_UP.put("nombre", NAME);
		KEY_CODE_LOOK_UP.put("id de usuario en la organización", USER_ID);
		KEY_CODE_LOOK_UP.put("id dispositivo", DEVICE_ID);
		KEY_CODE_LOOK_UP.put("permisos en la organización", USER_PERMISSION_ID);
		KEY_CODE_LOOK_UP.put("documento de identificación",
				IDENTIFICATION_DOCUMENT);
		KEY_CODE_LOOK_UP.put("ubicación gps de creación (x)",
				CREATION_POSITION_LATITUDE);
		KEY_CODE_LOOK_UP.put("ubicación gps de creación (y)",
				CREATION_POSITION_LONGITUDE);

		CUSTOM_EXTENSION.add(USER_ID);
		CUSTOM_EXTENSION.add(USER_PERMISSION_ID);
		CUSTOM_EXTENSION.add(IDENTIFICATION_DOCUMENT);
		CUSTOM_EXTENSION.add(CREATION_POSITION_LATITUDE);
		CUSTOM_EXTENSION.add(CREATION_POSITION_LONGITUDE);
		CUSTOM_EXTENSION.add(DEVICE_ID);
		CUSTOM_EXTENSION.add(SIGN_DEVICE_ID);
		CUSTOM_EXTENSION.add(CA_CERTIFICATE_SERIAL_NUMBER);
		CUSTOM_EXTENSION.add(CA_CERTIFICATE_SIGN_DEVICE_ID);
		CUSTOM_EXTENSION.add(CA_CERTIFICATE_SIGN_AUTHORITY_KEY_ID);

	}

}
