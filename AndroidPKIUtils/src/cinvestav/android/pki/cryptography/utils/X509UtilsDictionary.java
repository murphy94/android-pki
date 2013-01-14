/**
 *  Created on  : 22/06/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	
 */
package cinvestav.android.pki.cryptography.utils;

/**
 * This class only contains static attributes that are useful for X509Utils
 * class
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 22/06/2012
 * @version 1.0
 */
public class X509UtilsDictionary {

	public static final String EC_X509_SIGN_ALGORITHM_SHA1withECDSA = "SHA1withECDSA";
	public static final String EC_X509_SIGN_ALGORITHM_SHA224withECDSA = "SHA224withECDSA";
	public static final String EC_X509_SIGN_ALGORITHM_SHA256withECDSA = "SHA256withECDSA";
	public static final String EC_X509_SIGN_ALGORITHM_SHA384withECDSA = "SHA384withECDSA";
	public static final String EC_X509_SIGN_ALGORITHM_SHA512withECDSA = "SHA512withECDSA";

	public static final String RSA_X509_SIGN_ALGORITHM_MD2withRSA = "MD2withRSA";
	public static final String RSA_X509_SIGN_ALGORITHM_MD5withRSA = "MD5withRSA";
	public static final String RSA_X509_SIGN_ALGORITHM_SHA1withRSA = "SHA1withRSA";
	public static final String RSA_X509_SIGN_ALGORITHM_SHA224withRSA = "SHA224withRSA";
	public static final String RSA_X509_SIGN_ALGORITHM_SHA256withRSA = "SHA256withRSA";
	public static final String RSA_X509_SIGN_ALGORITHM_SHA384withRSA = "SHA384withRSA";
	public static final String RSA_X509_SIGN_ALGORITHM_SHA512withRSA = "SHA512withRSA";
	public static final String RSA_X509_SIGN_ALGORITHM_RIPEMD160withRSA = "RIPEMD160withRSA";
	public static final String RSA_X509_SIGN_ALGORITHM_RIPEMD128withRSA = "RIPEMD128withRSA";
	public static final String RSA_X509_SIGN_ALGORITHM_RIPEMD256withRSA = "RIPEMD256withRSA";

	/**
	 * If the certificate is valid
	 */
	public static final Integer X509_CERTIFICATE_STATUS_VALID = 0;
	/**
	 * If the certificate is invalid, due to CA signature errors
	 */
	public static final Integer X509_CERTIFICATE_STATUS_INVALID = 1;
	/**
	 * If the certificate is in a CRL
	 */
	public static final Integer X509_CERTIFICATE_STATUS_REVOKED = 2;
	/**
	 * If the certificate validity date has expired
	 */
	public static final Integer X509_CERTIFICATE_STATUS_EXPIRED = 3;
	/**
	 * If the certificate is not yet valid, because the initial validity date
	 * has not passed
	 */
	public static final Integer X509_CERTIFICATE_STATUS_NOT_YET_VALID = 4;

	/**
	 * If the Certificate Revocation List is valid;
	 */
	public static final Integer X509_CRL_STATUS_VALID = 0;
	/**
	 * If the signature of the CRL is invalid,
	 */
	public static final Integer X509_CRL_STATUS_INVALID = 1;
	/**
	 * If the CRL is old (for today), so a newer CRL should have been published
	 */
	public static final Integer X509_CRL_STATUS_OLD = 2;

	/**
	 * Subject public key is used with a digital signature mechanism to support
	 * security services other than certificate signing, or CRL signing Digital
	 * signature mechanisms are often used for entity authentication and data
	 * origin authentication with integrity.
	 */
	public static final Integer X509_KEYUSAGE_DIGITAL_SIGNATURE = 0;
	/**
	 * Subject public key is used to verify digital signatures used to provide a
	 * non- repudiation service which protects against the signing entity
	 * falsely denying some action
	 */
	public static final Integer X509_KEYUSAGE_NONREPUDIATION = 1;
	/**
	 * Subject public key is used for key transport. For example, when an RSA
	 * key is to be used for key management, then this bit is set.
	 */
	public static final Integer X509_KEYUSAGE_KEY_ENCIPHERMENT = 2;
	/**
	 * Subject public key is used for enciphering user data, other than
	 * cryptographic keys.
	 */
	public static final Integer X509_KEYUSAGE_DATA_ENCIPHERMENT = 3;
	/**
	 * Subject public key is used for key agreement
	 */
	public static final Integer X509_KEYUSAGE_KEY_AGREEMENT = 4;
	/**
	 * Subject public key is used for verifying a signature on public key
	 * certificates. If f the keyCertSign bit is asserted, then the cA bit in
	 * the basic constraints extension (section 4.2.1.10) MUST also be asserted.
	 */
	public static final Integer X509_KEYUSAGE_KEY_CERT_SIGN = 5;
	/**
	 * Subject public key is used for verifying a signature on certificate
	 * revocation list. This bit MUST be asserted in certificates that are used
	 * to verify signatures on CRLs.
	 */
	public static final Integer X509_KEYUSAGE_CRL_SIGN = 6;
	/**
	 * When the encipherOnly bit is asserted and the keyAgreement bit is also
	 * set, the subject public key may be used only for enciphering data while
	 * performing key agreement.
	 */
	public static final Integer X509_KEYUSAGE_ENCIPHER_ONLY = 7;
	/**
	 * When the decipherOnly bit is asserted and the keyAgreement bit is also
	 * set, the subject public key may be used only for deciphering data while
	 * performing key agreement.
	 */
	public static final Integer X509_KEYUSAGE_DECIPHER_ONLY = 8;

	/**
	 * Return a multilanguage String equivalence of key usage value, if the
	 * desired language is not available the key name will be returned in
	 * English
	 * 
	 * @param keyUsage
	 *            Needed Key Usage value
	 * @param language
	 *            ISO Language code to be used for getting the String
	 *            equivalence
	 * @return The string equivalence of the key usage
	 */
	public static String getX509KeyUsageStr(Integer keyUsage, String language) {
		if (language.equalsIgnoreCase("ES")) {
			switch (keyUsage) {
			case 0:
				return "Firma digital";
			case 1:
				return "No repudio";
			case 2:
				return "Cifrado de llaves";
			case 3:
				return "Cifrado de datos";
			case 4:
				return "Acuerdo de claves";
			case 5:
				return "Firma de claves y certificados";
			case 6:
				return "Firma de CRL";
			case 7:
				return "Solo cifrado";
			case 8:
				return "Solo descifrado";
			default:
				return "Valor no válido";
			}
		}

		// If language is different from ES
		switch (keyUsage) {
		case 0:
			return "Digital signature";
		case 1:
			return "Non repudation";
		case 2:
			return "Key encipherment";
		case 3:
			return "Data encipherment";
		case 4:
			return "Key agreement";
		case 5:
			return "Key and Certificate signature";
		case 6:
			return "CRL signature";
		case 7:
			return "Encipher only";
		case 8:
			return "Decipher only";
		default:
			return "Invalid value";
		}
	}

	/**
	 * This certificate will be only for root CA's, so the owner could issue as
	 * many certificates as it likes
	 */
	public static final String CERTIFICATE_TYPE_ROOT_CA = "CERTIFICATE_TYPE_ROOT_CA";
	/**
	 * This certificate type, indicates that the owner is and intermediate CA,
	 * so could only issue FINAL_CA and END_OWNER certificates, but has no limit
	 * in the of its certification path length
	 */
	public static final String CERTIFICATE_TYPE_INTERMEDIATE_CA = "CERTIFICATE_TYPE_INTERMEDIATE_CA";
	/**
	 * This certificate type, indicates that the owner only could issue
	 * END_OWNER certificates, so the certificate path length is 0
	 */
	public static final String CERTIFICATE_TYPE_FINAL_CA = "CERTIFICATE_TYPE_FINAL_CA";
	/**
	 * Final owner certificate, could not issue certificates to the
	 * KeyUsage.keyCertSign should not be present
	 */
	public static final String CERTIFICATE_TYPE_END_OWNER = "CERTIFICATE_TYPE_END_OWNER";

	/**
	 * Used for identify the self-signed certificates, this certificates are
	 * signed by the certificate holder using its private key, this kind of
	 * certificates are used commonly for proving the key pair possession, in
	 * order to identify a certificate as self signed, the authority key
	 * identifier and the subject key identifier certificate extensions must be
	 * present in the certificate extensions and must be the equals
	 */
	public static final Integer CERTIFICATE_SIGN_TYPE_SELF_SIGNED = 0;

	/**
	 * Used for identify the CA-signed certificates, this certificates are
	 * signed by a CA distinct of the certificate holder using its private key,
	 * this kind of certificates are used commonly for proving verifying the
	 * identity of its holder, in order to identify a certificate as CA-signed,
	 * the authority key identifier and the subject key identifier certificate
	 * extensions must be present in the certificate extensions and must be the
	 * different
	 */
	public static final Integer CERTIFICATE_SIGN_TYPE_CA_SIGNED = 1;

	/**
	 * This type is for certificates that does not have neither the the
	 * authority key identifier nor the subject key in its certificate
	 * extensions
	 */
	public static final Integer CERTIFICATE_SIGN_TYPE_UNKNOWN = 2;

}
