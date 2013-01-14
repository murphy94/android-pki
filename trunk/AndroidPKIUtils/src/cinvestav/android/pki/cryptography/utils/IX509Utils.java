/**
 *  Created on  : 22/05/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	 Interface for X509 Certiticate Utils, contains common functions for x509
 * certificate and CRLs
 */
package cinvestav.android.pki.cryptography.utils;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import cinvestav.android.pki.cryptography.cert.X509CRLRevokedCertificateEntry;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;
import cinvestav.android.pki.cryptography.exception.CryptoUtilsX509ExtensionException;
import cinvestav.android.pki.cryptography.key.ECKeyPair;
import cinvestav.android.pki.cryptography.key.ECPrivateKey;
import cinvestav.android.pki.cryptography.key.ECPublicKey;
import cinvestav.android.pki.cryptography.key.RSAKeyPair;
import cinvestav.android.pki.cryptography.key.RSAPrivateKey;
import cinvestav.android.pki.cryptography.key.RSAPublicKey;

/**
 * Interface for X509 Certiticate Utils, contains common functions for x509 and
 * CRLs certificate
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 22/05/2012
 * @version 1.0
 */
public interface IX509Utils {

	/**
	 * Create self-signed X509 v3 Certificate for RSA Keys using SHA1withRSA
	 * algorithm as signing algorithm
	 * 
	 * @param pubKey
	 *            Public Key to be certified
	 * @param caPrivKey
	 *            PrivateKey of the signer CA
	 * @param serial
	 *            Serial Number for the certificate
	 * @param notBefore
	 *            Not Before Validity date
	 * @param notAfter
	 *            Not After Validity date
	 * @param caCert
	 *            CA PublicKey Certificate
	 * @param certificateInformationMap
	 *            Map filled out with the certificate information using the
	 *            Field key (
	 *            {@link cinvestav.android.pki.cryptography.cert.CertificateInformationKeys}
	 *            Supported Keys) and the field value
	 * @param keyUsageList
	 *            List of Key Usages, see supported keyUsages at
	 *            X509UtilsDictionary, i.e.
	 *            X509UtilsDictionary.X509_KEYUSAGE_DECIPHER_ONLY
	 * @param certType
	 *            Certificate type, see supported types at X509UtilsDictionary,
	 *            i.e. X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA
	 * @see cinvestav.android.pki.cryptography.cert.CertificateInformationKeys
	 * @return A new signed X509 Public key certificate
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 * @throws CryptoUtilsX509ExtensionException
	 *             If something was not OK with the X509 Certificate extension
	 *             verification, for example: DEVICE_ID is missing in the
	 *             certificateInformationMap or If the CA can't issue
	 *             Certificates according its KeyUsage certificate extension
	 */
	public X509Certificate createV3Cert(RSAPublicKey pubKey,
			RSAPrivateKey privKey, BigInteger serial, Date notBefore,
			Date notAfter, HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException;

	/**
	 * Create self-signed X509 v3 Certificate for RSA Keys using the selected
	 * algorithm for sign the certificate
	 * 
	 * @param pubKey
	 *            Public Key to be certified
	 * @param caPrivKey
	 *            PrivateKey of the signer CA
	 * @param serial
	 *            Serial Number for the certificate
	 * @param notBefore
	 *            Not Before Validity date
	 * @param notAfter
	 *            Not After Validity date
	 * @param caCert
	 *            CA PublicKey Certificate
	 * @param certificateInformationMap
	 *            Map filled out with the certificate information using the
	 *            Field key (
	 *            {@link cinvestav.android.pki.cryptography.cert.CertificateInformationKeys}
	 *            Supported Keys) and the field value
	 * @param keyUsageList
	 *            List of Key Usages, see supported keyUsages at
	 *            X509UtilsDictionary, i.e.
	 *            X509UtilsDictionary.X509_KEYUSAGE_DECIPHER_ONLY
	 * @param certType
	 *            Certificate type, see supported types at X509UtilsDictionary,
	 *            i.e. X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA
	 * @param algorithm
	 *            Signing algorithm, see supported algorithms in
	 *            X509UtilsDictionary, i.e.
	 *            X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_SHA1withRSA
	 * @see cinvestav.android.pki.cryptography.cert.CertificateInformationKeys
	 * @return A new signed X509 Public key certificate
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 * @throws CryptoUtilsX509ExtensionException
	 *             If something was not OK with the X509 Certificate extension
	 *             verification, for example: DEVICE_ID is missing in the
	 *             certificateInformationMap or If the CA can't issue
	 *             Certificates according its KeyUsage certificate extension
	 */
	public X509Certificate createV3Cert(RSAPublicKey pubKey,
			RSAPrivateKey privKey, BigInteger serial, Date notBefore,
			Date notAfter, HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType, String algorithm)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException;

	/**
	 * Create X509 v3 Certificate for RSA Keys using SHA1withRSA algorithm as
	 * signing algorithm
	 * 
	 * @param pubKey
	 *            Public Key to be certified
	 * @param caPrivKey
	 *            PrivateKey of the signer CA
	 * @param serial
	 *            Serial Number for the certificate
	 * @param notBefore
	 *            Not Before Validity date
	 * @param notAfter
	 *            Not After Validity date
	 * @param caCert
	 *            CA PublicKey Certificate
	 * @param certificateInformationMap
	 *            Map filled out with the certificate information using the
	 *            Field key (
	 *            {@link cinvestav.android.pki.cryptography.cert.CertificateInformationKeys}
	 *            Supported Keys) and the field value
	 * @param keyUsageList
	 *            List of Key Usages, see supported keyUsages at
	 *            X509UtilsDictionary, i.e.
	 *            X509UtilsDictionary.X509_KEYUSAGE_DECIPHER_ONLY
	 * @param certType
	 *            Certificate type, see supported types at X509UtilsDictionary,
	 *            i.e. X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA
	 * @see cinvestav.android.pki.cryptography.cert.CertificateInformationKeys
	 * @return A new signed X509 Public key certificate
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 * @throws CryptoUtilsX509ExtensionException
	 *             If something was not OK with the X509 Certificate extension
	 *             verification, for example: DEVICE_ID is missing in the
	 *             certificateInformationMap or If the CA can't issue
	 *             Certificates according its KeyUsage certificate extension
	 */
	public X509Certificate createV3Cert(RSAPublicKey pubKey,
			RSAPrivateKey caPrivKey, BigInteger serial, Date notBefore,
			Date notAfter, X509Certificate caCert,
			HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException;

	/**
	 * Create X509 v3 Certificate for RSA Keys using the selected algorithm as
	 * signing algorithm
	 * 
	 * @param pubKey
	 *            Public Key to be certified
	 * @param caPrivKey
	 *            PrivateKey of the signer CA
	 * @param serial
	 *            Serial Number for the certificate
	 * @param notBefore
	 *            Not Before Validity date
	 * @param notAfter
	 *            Not After Validity date
	 * @param caCert
	 *            CA PublicKey Certificate
	 * @param certificateInformationMap
	 *            Map filled out with the certificate information using the
	 *            Field key (
	 *            {@link cinvestav.android.pki.cryptography.cert.CertificateInformationKeys}
	 *            Supported Keys) and the field value
	 * @param keyUsageList
	 *            List of Key Usages, see supported keyUsages at
	 *            X509UtilsDictionary, i.e.
	 *            X509UtilsDictionary.X509_KEYUSAGE_DECIPHER_ONLY
	 * @param certType
	 *            Certificate type, see supported types at X509UtilsDictionary,
	 *            i.e. X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA
	 * @param algorithm
	 *            Signing algorithm, see supported algorithms in
	 *            X509UtilsDictionary, i.e. X509UtilsDictionary.
	 *            RSA_X509_SIGN_ALGORITHM_SHA1withRSA
	 * @see cinvestav.android.pki.cryptography.cert.CertificateInformationKeys
	 * @return A new signed X509 Public key certificate
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 * @throws CryptoUtilsX509ExtensionException
	 *             If something was not OK with the X509 Certificate extension
	 *             verification, for example: DEVICE_ID is missing in the
	 *             certificateInformationMap or If the CA can't issue
	 *             Certificates according its KeyUsage certificate extension
	 */
	public X509Certificate createV3Cert(RSAPublicKey pubKey,
			RSAPrivateKey caPrivKey, BigInteger serial, Date notBefore,
			Date notAfter, X509Certificate caCert,
			HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType, String algorithm)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException;

	/**
	 * Create self-signed X509 v3 Certificate for EC Keys using SHA1withECDSA as
	 * signing algorithm
	 * 
	 * @param pubKey
	 *            Public Key to be certified
	 * @param caPrivKey
	 *            PrivateKey of the signer CA
	 * @param serial
	 *            Serial Number for the certificate
	 * @param notBefore
	 *            Not Before Validity date
	 * @param notAfter
	 *            Not After Validity date
	 * @param caCert
	 *            CA PublicKey Certificate
	 * @param certificateInformationMap
	 *            Map filled out with the certificate information using the
	 *            Field key (
	 *            {@link cinvestav.android.pki.cryptography.cert.CertificateInformationKeys}
	 *            Supported Keys) and the field value
	 * @param keyUsageList
	 *            List of Key Usages, see supported keyUsages at
	 *            X509UtilsDictionary, i.e.
	 *            X509UtilsDictionary.X509_KEYUSAGE_DECIPHER_ONLY
	 * @param certType
	 *            Certificate type, see supported types at X509UtilsDictionary,
	 *            i.e. X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA
	 * @see cinvestav.android.pki.cryptography.cert.CertificateInformationKeys
	 * @return A new signed X509 Public key certificate
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 * @throws CryptoUtilsX509ExtensionException
	 *             If something was not OK with the X509 Certificate extension
	 *             verification, for example: DEVICE_ID is missing in the
	 *             certificateInformationMap or If the CA can't issue
	 *             Certificates according its KeyUsage certificate extension
	 */
	public X509Certificate createV3Cert(ECPublicKey pubKey,
			ECPrivateKey privKey, BigInteger serial, Date notBefore,
			Date notAfter, HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException;

	/**
	 * Create self-signed X509 v3 Certificate for EC Keys
	 * 
	 * @param pubKey
	 *            Public Key to be certified
	 * @param caPrivKey
	 *            PrivateKey of the signer CA
	 * @param serial
	 *            Serial Number for the certificate
	 * @param notBefore
	 *            Not Before Validity date
	 * @param notAfter
	 *            Not After Validity date
	 * @param caCert
	 *            CA PublicKey Certificate
	 * @param certificateInformationMap
	 *            Map filled out with the certificate information using the
	 *            Field key (
	 *            {@link cinvestav.android.pki.cryptography.cert.CertificateInformationKeys}
	 *            Supported Keys) and the field value
	 * @param keyUsageList
	 *            List of Key Usages, see supported keyUsages at
	 *            X509UtilsDictionary, i.e.
	 *            X509UtilsDictionary.X509_KEYUSAGE_DECIPHER_ONLY
	 * @param certType
	 *            Certificate type, see supported types at X509UtilsDictionary,
	 *            i.e. X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA
	 * @param algorithm
	 *            Signing algorithm, see supported algorithms in
	 *            X509UtilsDictionary, i.e. X509UtilsDictionary.
	 *            EC_X509_SIGN_ALGORITHM_SHA1withECDSA
	 * @see cinvestav.android.pki.cryptography.cert.CertificateInformationKeys
	 * @return A new signed X509 Public key certificate
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 * @throws CryptoUtilsX509ExtensionException
	 *             If something was not OK with the X509 Certificate extension
	 *             verification, for example: DEVICE_ID is missing in the
	 *             certificateInformationMap or If the CA can't issue
	 *             Certificates according its KeyUsage certificate extension
	 */
	public X509Certificate createV3Cert(ECPublicKey pubKey,
			ECPrivateKey privKey, BigInteger serial, Date notBefore,
			Date notAfter, HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType, String algorithm)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException;

	/**
	 * Create X509 v3 Certificate for EC Keys using SHA1withECDSA as signing
	 * algorithm
	 * 
	 * @param pubKey
	 *            Public Key to be certified
	 * @param caPrivKey
	 *            PrivateKey of the signer CA
	 * @param serial
	 *            Serial Number for the certificate
	 * @param notBefore
	 *            Not Before Validity date
	 * @param notAfter
	 *            Not After Validity date
	 * @param caCert
	 *            CA PublicKey Certificate
	 * @param certificateInformationMap
	 *            Map filled out with the certificate information using the
	 *            Field key (
	 *            {@link cinvestav.android.pki.cryptography.cert.CertificateInformationKeys}
	 *            Supported Keys) and the field value
	 * @param keyUsageList
	 *            List of Key Usages, see supported keyUsages at
	 *            X509UtilsDictionary, i.e.
	 *            X509UtilsDictionary.X509_KEYUSAGE_DECIPHER_ONLY
	 * @param certType
	 *            Certificate type, see supported types at X509UtilsDictionary,
	 *            i.e. X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA
	 * @see cinvestav.android.pki.cryptography.cert.CertificateInformationKeys
	 * @return A new signed X509 Public key certificate
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 * @throws CryptoUtilsX509ExtensionException
	 *             If something was not OK with the X509 Certificate extension
	 *             verification, for example: DEVICE_ID is missing in the
	 *             certificateInformationMap or If the CA can't issue
	 *             Certificates according its KeyUsage certificate extension
	 */
	public X509Certificate createV3Cert(ECPublicKey pubKey,
			ECPrivateKey caPrivKey, BigInteger serial, Date notBefore,
			Date notAfter, X509Certificate caCert,
			HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException;

	/**
	 * Create X509 v3 Certificate for EC Keys using the selected EC algorithm
	 * for sign the certificate
	 * 
	 * @param pubKey
	 *            Public Key to be certified
	 * @param caPrivKey
	 *            PrivateKey of the signer CA
	 * @param serial
	 *            Serial Number for the certificate
	 * @param notBefore
	 *            Not Before Validity date
	 * @param notAfter
	 *            Not After Validity date
	 * @param caCert
	 *            CA PublicKey Certificate
	 * @param certificateInformationMap
	 *            Map filled out with the certificate information using the
	 *            Field key (
	 *            {@link cinvestav.android.pki.cryptography.cert.CertificateInformationKeys}
	 *            Supported Keys) and the field value
	 * @param keyUsageList
	 *            List of Key Usages, see supported keyUsages at
	 *            X509UtilsDictionary, i.e.
	 *            X509UtilsDictionary.X509_KEYUSAGE_DECIPHER_ONLY
	 * @param certType
	 *            Certificate type, see supported types at X509UtilsDictionary,
	 *            i.e. X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA
	 * @param algorithm
	 *            Signing algorithm, see supported algorithms in
	 *            X509UtilsDictionary, i.e. X509UtilsDictionary.
	 *            EC_X509_SIGN_ALGORITHM_SHA1withECDSA
	 * @see cinvestav.android.pki.cryptography.cert.CertificateInformationKeys
	 * @return A new signed X509 Public key certificate
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 * @throws CryptoUtilsX509ExtensionException
	 *             If something was not OK with the X509 Certificate extension
	 *             verification, for example: DEVICE_ID is missing in the
	 *             certificateInformationMap or If the CA can't issue
	 *             Certificates according its KeyUsage certificate extension
	 */
	public X509Certificate createV3Cert(ECPublicKey pubKey,
			ECPrivateKey caPrivKey, BigInteger serial, Date notBefore,
			Date notAfter, X509Certificate caCert,
			HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType, String algorithm)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException;

	/**
	 * Create X509 v3 Certificate using mixes keys types (owner EC Keys and CAs
	 * RSA keys) using the selected algorithm as signing algorithm
	 * 
	 * @param pubKey
	 *            Certificate owner EC Public Key to be certified
	 * @param caPrivKey
	 *            RSA PrivateKey of the signer CA
	 * @param serial
	 *            Serial Number for the certificate
	 * @param notBefore
	 *            Not Before Validity date
	 * @param notAfter
	 *            Not After Validity date
	 * @param caCert
	 *            CA PublicKey Certificate
	 * @param certificateInformationMap
	 *            Map filled out with the certificate information using the
	 *            Field key (
	 *            {@link cinvestav.android.pki.cryptography.cert.CertificateInformationKeys}
	 *            Supported Keys) and the field value
	 * @param keyUsageList
	 *            List of Key Usages, see supported keyUsages at
	 *            X509UtilsDictionary, i.e.
	 *            X509UtilsDictionary.X509_KEYUSAGE_DECIPHER_ONLY
	 * @param certType
	 *            Certificate type, see supported types at X509UtilsDictionary,
	 *            i.e. X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA
	 * @param algorithm
	 *            Signing algorithm, see supported algorithms in
	 *            X509UtilsDictionary, i.e. X509UtilsDictionary.
	 *            RSA_X509_SIGN_ALGORITHM_MD2withRSA
	 * @see cinvestav.android.pki.cryptography.cert.CertificateInformationKeys
	 * @return A new signed X509 Public key certificate
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 * @throws CryptoUtilsX509ExtensionException
	 *             If something was not OK with the X509 Certificate extension
	 *             verification, for example: DEVICE_ID is missing in the
	 *             certificateInformationMap or If the CA can't issue
	 *             Certificates according its KeyUsage certificate extension
	 */
	public X509Certificate createV3Cert(ECPublicKey pubKey,
			RSAPrivateKey caPrivKey, BigInteger serial, Date notBefore,
			Date notAfter, X509Certificate caCert,
			HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType, String algorithm)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException;

	/**
	 * Create X509 v3 Certificate using mixes keys (owner EC Keys and CAs RSA
	 * keys) using SHA1withRSA algorithm as signing algorithm
	 * 
	 * @param pubKey
	 *            Owner's EC Public Key to be certified
	 * @param caPrivKey
	 *            RSA PrivateKey of the signer CA
	 * @param serial
	 *            Serial Number for the certificate
	 * @param notBefore
	 *            Not Before Validity date
	 * @param notAfter
	 *            Not After Validity date
	 * @param caCert
	 *            CA PublicKey Certificate
	 * @param certificateInformationMap
	 *            Map filled out with the certificate information using the
	 *            Field key (
	 *            {@link cinvestav.android.pki.cryptography.cert.CertificateInformationKeys}
	 *            Supported Keys) and the field value
	 * @param keyUsageList
	 *            List of Key Usages, see supported keyUsages at
	 *            X509UtilsDictionary, i.e.
	 *            X509UtilsDictionary.X509_KEYUSAGE_DECIPHER_ONLY
	 * @param certType
	 *            Certificate type, see supported types at X509UtilsDictionary,
	 *            i.e. X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA
	 * @see cinvestav.android.pki.cryptography.cert.CertificateInformationKeys
	 * @return A new signed X509 Public key certificate
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 * @throws CryptoUtilsX509ExtensionException
	 *             If something was not OK with the X509 Certificate extension
	 *             verification, for example: DEVICE_ID is missing in the
	 *             certificateInformationMap or If the CA can't issue
	 *             Certificates according its KeyUsage certificate extension
	 */
	public X509Certificate createV3Cert(ECPublicKey pubKey,
			RSAPrivateKey caPrivKey, BigInteger serial, Date notBefore,
			Date notAfter, X509Certificate caCert,
			HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException;

	/**
	 * Create X509 v3 Certificate using mixes keys types (owner RSA Keys and CAs
	 * EC keys) using the selected algorithm as signing algorithm
	 * 
	 * @param pubKey
	 *            Certificate owner RSA Public Key to be certified
	 * @param caPrivKey
	 *            EC PrivateKey of the signer CA
	 * @param serial
	 *            Serial Number for the certificate
	 * @param notBefore
	 *            Not Before Validity date
	 * @param notAfter
	 *            Not After Validity date
	 * @param caCert
	 *            CA PublicKey Certificate
	 * @param certificateInformationMap
	 *            Map filled out with the certificate information using the
	 *            Field key (
	 *            {@link cinvestav.android.pki.cryptography.cert.CertificateInformationKeys}
	 *            Supported Keys) and the field value
	 * @param keyUsageList
	 *            List of Key Usages, see supported keyUsages at
	 *            X509UtilsDictionary, i.e.
	 *            X509UtilsDictionary.X509_KEYUSAGE_DECIPHER_ONLY
	 * @param certType
	 *            Certificate type, see supported types at X509UtilsDictionary,
	 *            i.e. X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA
	 * @param algorithm
	 *            Signing algorithm, see supported algorithms in
	 *            X509UtilsDictionary, i.e. X509UtilsDictionary.
	 *            EC_X509_SIGN_ALGORITHM_SHA1withECDSA
	 * @see cinvestav.android.pki.cryptography.cert.CertificateInformationKeys
	 * @return A new signed X509 Public key certificate
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 * @throws CryptoUtilsX509ExtensionException
	 *             If something was not OK with the X509 Certificate extension
	 *             verification, for example: DEVICE_ID is missing in the
	 *             certificateInformationMap or If the CA can't issue
	 *             Certificates according its KeyUsage certificate extension
	 */
	public X509Certificate createV3Cert(RSAPublicKey pubKey,
			ECPrivateKey caPrivKey, BigInteger serial, Date notBefore,
			Date notAfter, X509Certificate caCert,
			HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType, String algorithm)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException;

	/**
	 * Create X509 v3 Certificate using mixes keys (owner RSA Keys and CAs EC
	 * keys) using SHA1withECDSA algorithm as signing algorithm
	 * 
	 * @param pubKey
	 *            Owner RSA Public Key to be certified
	 * @param caPrivKey
	 *            EC PrivateKey of the signer CA
	 * @param serial
	 *            Serial Number for the certificate
	 * @param notBefore
	 *            Not Before Validity date
	 * @param notAfter
	 *            Not After Validity date
	 * @param caCert
	 *            CA PublicKey Certificate
	 * @param certificateInformationMap
	 *            Map filled out with the certificate information using the
	 *            Field key (
	 *            {@link cinvestav.android.pki.cryptography.cert.CertificateInformationKeys}
	 *            Supported Keys) and the field value
	 * @param keyUsageList
	 *            List of Key Usages, see supported keyUsages at
	 *            X509UtilsDictionary, i.e.
	 *            X509UtilsDictionary.X509_KEYUSAGE_DECIPHER_ONLY
	 * @param certType
	 *            Certificate type, see supported types at X509UtilsDictionary,
	 *            i.e. X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA
	 * @see cinvestav.android.pki.cryptography.cert.CertificateInformationKeys
	 * @return A new signed X509 Public key certificate
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 * @throws CryptoUtilsX509ExtensionException
	 *             If something was not OK with the X509 Certificate extension
	 *             verification, for example: DEVICE_ID is missing in the
	 *             certificateInformationMap or If the CA can't issue
	 *             Certificates according its KeyUsage certificate extension
	 */
	public X509Certificate createV3Cert(RSAPublicKey pubKey,
			ECPrivateKey caPrivKey, BigInteger serial, Date notBefore,
			Date notAfter, X509Certificate caCert,
			HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException;

	/**
	 * Create X509 v3 Certificate using a self-signed certificate (in order to
	 * prove that the owner has the key pair) signed with the CA's key using the
	 * selected algorithm
	 * 
	 * @param pubKeyCert
	 *            Owners Self-signed certificate, that proves that the owner has
	 *            the keyPair
	 * @param caPrivKey
	 *            RSA PrivateKey of the signer CA
	 * @param serial
	 *            Serial Number for the certificate
	 * @param notBefore
	 *            Not Before Validity date
	 * @param notAfter
	 *            Not After Validity date
	 * @param caCert
	 *            CA PublicKey Certificate
	 * @param certificateInformationMap
	 *            Map filled out with the certificate information using the
	 *            Field key (
	 *            {@link cinvestav.android.pki.cryptography.cert.CertificateInformationKeys}
	 *            Supported Keys) and the field value
	 * @param keyUsageList
	 *            List of Key Usages, see supported keyUsages at
	 *            X509UtilsDictionary, i.e.
	 *            X509UtilsDictionary.X509_KEYUSAGE_DECIPHER_ONLY
	 * @param certType
	 *            Certificate type, see supported types at X509UtilsDictionary,
	 *            i.e. X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA
	 * @param algorithm
	 *            Signing algorithm, see supported algorithms in
	 *            X509UtilsDictionary, i.e. X509UtilsDictionary.
	 *            RSA_X509_SIGN_ALGORITHM_MD2withRSA
	 * @see cinvestav.android.pki.cryptography.cert.CertificateInformationKeys
	 * @return A new signed X509 Public key certificate
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 * @throws CryptoUtilsX509ExtensionException
	 *             If something was not OK with the X509 Certificate extension
	 *             verification, for example: DEVICE_ID is missing in the
	 *             certificateInformationMap or If the CA can't issue
	 *             Certificates according its KeyUsage certificate extension
	 */
	public X509Certificate createV3Cert(X509Certificate pubKeyCert,
			RSAPrivateKey caPrivKey, BigInteger serial, Date notBefore,
			Date notAfter, X509Certificate caCert,
			HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType, String algorithm)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException;

	/**
	 * Create X509 v3 Certificate using a self-signed certificate (in order to
	 * prove that the owner has the key pair) signed with the CA's key using
	 * SHA1withRSA algorithm
	 * 
	 * @param pubKeyCert
	 *            Owners Self-signed certificate, that proves that the owner has
	 *            the keyPair
	 * @param caPrivKey
	 *            RSA PrivateKey of the signer CA
	 * @param serial
	 *            Serial Number for the certificate
	 * @param notBefore
	 *            Not Before Validity date
	 * @param notAfter
	 *            Not After Validity date
	 * @param caCert
	 *            CA PublicKey Certificate
	 * @param certificateInformationMap
	 *            Map filled out with the certificate information using the
	 *            Field key (
	 *            {@link cinvestav.android.pki.cryptography.cert.CertificateInformationKeys}
	 *            Supported Keys) and the field value
	 * @param keyUsageList
	 *            List of Key Usages, see supported keyUsages at
	 *            X509UtilsDictionary, i.e.
	 *            X509UtilsDictionary.X509_KEYUSAGE_DECIPHER_ONLY
	 * @param certType
	 *            Certificate type, see supported types at X509UtilsDictionary,
	 *            i.e. X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA
	 * @see cinvestav.android.pki.cryptography.cert.CertificateInformationKeys
	 * @return A new signed X509 Public key certificate
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 * @throws CryptoUtilsX509ExtensionException
	 *             If something was not OK with the X509 Certificate extension
	 *             verification, for example: DEVICE_ID is missing in the
	 *             certificateInformationMap or If the CA can't issue
	 *             Certificates according its KeyUsage certificate extension
	 */
	public X509Certificate createV3Cert(X509Certificate pubKeyCert,
			RSAPrivateKey caPrivKey, BigInteger serial, Date notBefore,
			Date notAfter, X509Certificate caCert,
			HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException;

	/**
	 * Create X509 v3 Certificate using a self-signed certificate (in order to
	 * prove that the owner has the key pair) signed with the CA's key using the
	 * selected algorithm
	 * 
	 * @param pubKeyCert
	 *            Owners Self-signed certificate, that proves that the owner has
	 *            the keyPair
	 * @param caPrivKey
	 *            EC PrivateKey of the signer CA
	 * @param serial
	 *            Serial Number for the certificate
	 * @param notBefore
	 *            Not Before Validity date
	 * @param notAfter
	 *            Not After Validity date
	 * @param caCert
	 *            CA PublicKey Certificate
	 * @param certificateInformationMap
	 *            Map filled out with the certificate information using the
	 *            Field key (
	 *            {@link cinvestav.android.pki.cryptography.cert.CertificateInformationKeys}
	 *            Supported Keys) and the field value
	 * @param keyUsageList
	 *            List of Key Usages, see supported keyUsages at
	 *            X509UtilsDictionary, i.e.
	 *            X509UtilsDictionary.X509_KEYUSAGE_DECIPHER_ONLY
	 * @param certType
	 *            Certificate type, see supported types at X509UtilsDictionary,
	 *            i.e. X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA
	 * @param algorithm
	 *            Signing algorithm, see supported algorithms in
	 *            X509UtilsDictionary, i.e. X509UtilsDictionary.
	 *            EC_X509_SIGN_ALGORITHM_SHA1withECDSA
	 * @see cinvestav.android.pki.cryptography.cert.CertificateInformationKeys
	 * @return A new signed X509 Public key certificate
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 * @throws CryptoUtilsX509ExtensionException
	 *             If something was not OK with the X509 Certificate extension
	 *             verification, for example: DEVICE_ID is missing in the
	 *             certificateInformationMap or If the CA can't issue
	 *             Certificates according its KeyUsage certificate extension
	 */
	public X509Certificate createV3Cert(X509Certificate pubKeyCert,
			ECPrivateKey caPrivKey, BigInteger serial, Date notBefore,
			Date notAfter, X509Certificate caCert,
			HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType, String algorithm)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException;

	/**
	 * Create X509 v3 Certificate using a self-signed certificate (in order to
	 * prove that the owner has the key pair) signed with the CA's key using
	 * SHA1withECDSA algorithm
	 * 
	 * @param pubKeyCert
	 *            Owners Self-signed certificate, that proves that the owner has
	 *            the keyPair
	 * @param caPrivKey
	 *            EC PrivateKey of the signer CA
	 * @param serial
	 *            Serial Number for the certificate
	 * @param notBefore
	 *            Not Before Validity date
	 * @param notAfter
	 *            Not After Validity date
	 * @param caCert
	 *            CA PublicKey Certificate
	 * @param certificateInformationMap
	 *            Map filled out with the certificate information using the
	 *            Field key (
	 *            {@link cinvestav.android.pki.cryptography.cert.CertificateInformationKeys}
	 *            Supported Keys) and the field value
	 * @param keyUsageList
	 *            List of Key Usages, see supported keyUsages at
	 *            X509UtilsDictionary, i.e.
	 *            X509UtilsDictionary.X509_KEYUSAGE_DECIPHER_ONLY
	 * @param certType
	 *            Certificate type, see supported types at X509UtilsDictionary,
	 *            i.e. X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA
	 * @see cinvestav.android.pki.cryptography.cert.CertificateInformationKeys
	 * @return A new signed X509 Public key certificate
	 * @throws CryptoUtilsException
	 *             If something goes wrong
	 * @throws CryptoUtilsX509ExtensionException
	 *             If something was not OK with the X509 Certificate extension
	 *             verification, for example: DEVICE_ID is missing in the
	 *             certificateInformationMap or If the CA can't issue
	 *             Certificates according its KeyUsage certificate extension
	 */
	public X509Certificate createV3Cert(X509Certificate pubKeyCert,
			ECPrivateKey caPrivKey, BigInteger serial, Date notBefore,
			Date notAfter, X509Certificate caCert,
			HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException;

	/**
	 * Stores a certificate in disk using the specified fileName and DER as
	 * default encoding
	 * 
	 * @param fileName
	 *            File Name for the certificate, must include the full path in
	 *            which will be saved
	 * @param certificate
	 *            X509Certificate to be saved
	 * @throws CryptoUtilsException
	 *             If unsupported encoding is selected, or something goes wrong
	 *             while writing the certificate
	 */
	public void saveCertificate(String fileName, X509Certificate certificate)
			throws CryptoUtilsException;

	/**
	 * Stores a certificate in disk using the specified fileName and the
	 * selected encoding
	 * 
	 * @param fileName
	 *            File Name for the certificate, must include the full path in
	 *            which will be saved
	 * @param certificate
	 *            X509Certificate to be saved
	 * @param encoding
	 *            Encoding to be used for save the certificate
	 * @throws CryptoUtilsException
	 *             If unsupported encoding is selected, or something goes wrong
	 *             while writing the certificate
	 */
	public void saveCertificate(String fileName, X509Certificate certificate,
			String encoding) throws CryptoUtilsException;

	/**
	 * Load a X509 certificate using an specific encoding from file
	 * 
	 * @param fileName
	 *            Full path and name of the file containing the x509 certificate
	 * @param encoding
	 *            Encoding of the certificate, could be DER or PEM
	 * @return X509 certificate contained in the file
	 * @throws CryptoUtilsException
	 *             If the certificate could not be loaded, because wrong
	 *             encoding selected or the file does not contain a valid X509
	 *             certificate
	 */
	public X509Certificate loadCertificate(String fileName, String encoding)
			throws CryptoUtilsException;

	/**
	 * Load a X509 certificate, this function tries both supported encoding
	 * types, so it could be a bit slower than the function in which the encoded
	 * is selected
	 * 
	 * @param fileName
	 *            Full path and name of the file containing the x509 certificate
	 * @return X509 certificate contained in the file
	 * @throws CryptoUtilsException
	 *             If the certificate could not be loaded, because file does not
	 *             contain a valid X509 certificate
	 */
	public X509Certificate loadCertificate(String fileName)
			throws CryptoUtilsException;

	/**
	 * Load the certificate
	 * 
	 * @param fileName
	 *            File in which are stored the certificates
	 * @param keyStorePwd
	 *            Password for the key store
	 * @return The certificate chain array stored in the pkcs12 file
	 * @throws CryptoUtilsException
	 */
	public Certificate[] loadCertificateChainPKCS12(String fileName,
			String keyStorePwd) throws CryptoUtilsException;

	/**
	 * Creates a new X509 V2 Certificate Revocation List (CRL) signed using
	 * SHA256withRSAEncryption
	 * 
	 * @param issuerKeyPair
	 *            RSA Key Pair of the issuer of the CRL, will be used for sign
	 *            the CRL
	 * @param issuerCertificate
	 *            X509Certificate of the issuer of the CRL
	 * @param revokedCertificates
	 *            List of the revoked certificates to be added in the CRL
	 * @param nextUpdate
	 *            Next update for the CRL
	 * @param crlNumber
	 *            The CRL number is a non-critical CRL extension that conveys a
	 *            monotonically increasing sequence number for a given CRL scope
	 *            and CRL issuer
	 * @return a new CRL signed using SHA256withRSAEncryption with dated at the
	 *         current date
	 * 
	 * @throws CryptoUtilsException
	 * @throws CryptoUtilsX509ExtensionException
	 *             If the CA can't issue CRL according its KeyUsage certificate
	 *             extension
	 */
	public X509CRL createCRL(RSAKeyPair issuerKeyPair,
			X509Certificate issuerCertificate,
			List<X509CRLRevokedCertificateEntry> revokedCertificates,
			Date nextUpdate, BigInteger crlNumber) throws CryptoUtilsException,
			CryptoUtilsX509ExtensionException;

	/**
	 * Creates a new X509 V2 Certificate Revocation List (CRL) signed using the
	 * selected algorithm
	 * 
	 * @param issuerKeyPair
	 *            RSA Key Pair of the issuer of the CRL, will be used for sign
	 *            the CRL
	 * @param issuerCertificate
	 *            X509Certificate of the issuer of the CRL
	 * @param revokedCertificates
	 *            List of the revoked certificates to be added in the CRL
	 * @param nextUpdate
	 *            Next update for the CRL
	 * @param crlNumber
	 *            The CRL number is a non-critical CRL extension that conveys a
	 *            monotonically increasing sequence number for a given CRL scope
	 *            and CRL issuer
	 * @param algorithm
	 *            Selected algorithm to perform the sign of the CRL
	 * @return a new CRL signed using SHA256withRSAEncryption with dated at the
	 *         current date
	 * 
	 * @throws CryptoUtilsException
	 * @throws CryptoUtilsX509ExtensionException
	 *             If the CA can't issue CRL according its KeyUsage certificate
	 *             extension
	 * 
	 */
	public X509CRL createCRL(RSAKeyPair issuerKeyPair,
			X509Certificate issuerCertificate,
			List<X509CRLRevokedCertificateEntry> revokedCertificates,
			Date nextUpdate, BigInteger crlNumber, String algorithm)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException;

	/**
	 * Creates a new X509 V2 Certificate Revocation List (CRL) signed using
	 * SHA1withECDSA
	 * 
	 * @param issuerKeyPair
	 *            EC Key Pair of the issuer of the CRL, will be used for sign
	 *            the CRL
	 * @param issuerCertificate
	 *            X509Certificate of the issuer of the CRL
	 * @param revokedCertificates
	 *            List of the revoked certificates to be added in the CRL
	 * @param nextUpdate
	 *            Next update for the CRL
	 * @param crlNumber
	 *            The CRL number is a non-critical CRL extension that conveys a
	 *            monotonically increasing sequence number for a given CRL scope
	 *            and CRL issuer
	 * @return a new CRL with dated at the current date
	 * @throws CryptoUtilsException
	 * @throws CryptoUtilsX509ExtensionException
	 *             If the CA can't issue CRL according its KeyUsage certificate
	 *             extension
	 */
	public X509CRL createCRL(ECKeyPair issuerKeyPair,
			X509Certificate issuerCertificate,
			List<X509CRLRevokedCertificateEntry> revokedCertificates,
			Date nextUpdate, BigInteger crlNumber) throws CryptoUtilsException,
			CryptoUtilsX509ExtensionException;

	/**
	 * Creates a new X509 V2 Certificate Revocation List (CRL) signed using the
	 * selected EC algorithm
	 * 
	 * @param issuerKeyPair
	 *            EC Key Pair of the issuer of the CRL, will be used for sign
	 *            the CRL
	 * @param issuerCertificate
	 *            X509Certificate of the issuer of the CRL
	 * @param revokedCertificates
	 *            List of the revoked certificates to be added in the CRL
	 * @param nextUpdate
	 *            Next update for the CRL
	 * @param crlNumber
	 *            The CRL number is a non-critical CRL extension that conveys a
	 *            monotonically increasing sequence number for a given CRL scope
	 *            and CRL issuer * @param algorithm EC Algorithm to be used for
	 *            sign the CRL
	 * 
	 * @return a new CRL with dated at the current date
	 * @throws CryptoUtilsException
	 * @throws CryptoUtilsX509ExtensionException
	 *             If the CA can't issue CRL according its KeyUsage certificate
	 *             extension
	 */
	public X509CRL createCRL(ECKeyPair issuerKeyPair,
			X509Certificate issuerCertificate,
			List<X509CRLRevokedCertificateEntry> revokedCertificates,
			Date nextUpdate, BigInteger crlNumber, String algorithm)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException;

	/**
	 * Stores a X509 CRL in disk using the specified fileName and DER as default
	 * encoding
	 * 
	 * @param fileName
	 *            File Name for the CRL, must include the full path in which
	 *            will be saved
	 * @param crl
	 *            Certificate Revocation List (CRL) to be saved
	 * @throws CryptoUtilsException
	 *             If unsupported encoding is selected, or something goes wrong
	 *             while writing the CRL
	 */
	public void saveCRL(String fileName, X509CRL crl)
			throws CryptoUtilsException;

	/**
	 * Stores a CRL in disk using the specified fileName and the selected
	 * encoding
	 * 
	 * @param fileName
	 *            File Name for the CRL, must include the full path in which
	 *            will be saved
	 * @param crl
	 *            Certificate Revocation List (CRL) to be saved
	 * @param encoding
	 *            Encoding to be used for save the CRL
	 * @throws CryptoUtilsException
	 *             If unsupported encoding is selected, or something goes wrong
	 *             while writing the CRL
	 */
	public void saveCRL(String fileName, X509CRL crl, String encoding)
			throws CryptoUtilsException;

	/**
	 * Load a X509 CRL using an specific encoding from file
	 * 
	 * @param fileName
	 *            Full path and name of the file containing the x509 CRL
	 * @param encoding
	 *            Encoding of the CRL, could be DER or PEM
	 * @return X509 CRL contained in the file
	 * @throws CryptoUtilsException
	 *             If the CRL could not be loaded, because wrong encoding
	 *             selected or the file does not contain a valid X509 CRL
	 */
	public X509CRL loadCRL(String fileName, String encoding)
			throws CryptoUtilsException;

	/**
	 * Load a X509 CRL, this function tries both supported encoding types, so it
	 * could be a bit slower than the function in which the encoded is selected
	 * 
	 * @param fileName
	 *            Full path and name of the file containing the x509 CRL
	 * @return X509 CRL contained in the file
	 * @throws CryptoUtilsException
	 *             If the CRL could not be loaded, because file does not contain
	 *             a valid X509 CRL
	 */
	public X509CRL loadCRL(String fileName) throws CryptoUtilsException;

	/**
	 * Verify the status of a certificate
	 * 
	 * @param cert
	 *            Certificate to be verified
	 * @param cacert
	 *            CA certificate, for verify the certificate signature
	 * @param crl
	 *            Certificate Revocation List to with the certificate should be
	 *            compared
	 * @return An integer representing the certificate status, see possible
	 *         status as static attributes of X509UtilsDictionary, i.e,
	 *         X509UtilsDictionary.X509_CERTIFICATE_STATUS_XXXXXX
	 * @throws CryptoUtilsException
	 *             if something is wrong with the certificate encoding or
	 *             content
	 */
	public Integer verifyCertificate(X509Certificate cert,
			X509Certificate cacert, X509CRL crl) throws CryptoUtilsException;

	/**
	 * Verifies if the CRL is valid using its issuers certificate
	 * 
	 * @param crl
	 *            Certificate Revocation List (CRL) to be verified
	 * @param cacert
	 *            Certificate of the CA that issues the CRL
	 * @return An integer representing the CRL status, see possible status as
	 *         static attributes of X509UtilsDictionary, i.e,
	 *         X509UtilsDictionary.X509_CRL_STATUS_XXXXXX
	 * @throws CryptoUtilsException
	 *             if the CRL is not a valid X509 Certificate Revocation List
	 */
	public Integer verifyCRL(X509CRL crl, X509Certificate cacert)
			throws CryptoUtilsException;

	/**
	 * Gets the Certificate Authority Key Identifier from a X509 Certificate
	 * 
	 * @param cert
	 *            X509 certificate that contains the authorityKeyIdentifier
	 *            extension
	 * @return a byte array representing the key identifier, or null if the
	 *         extension is not present in the certificate
	 */
	public byte[] getAuthorityKeyIdentifier(X509Certificate cert);

	/**
	 * Gets the Certificate Subject Key Identifier from a X509 Certificate
	 * 
	 * @param cert
	 *            X509 certificate that contains the subjectKeyIdentifier
	 *            extension
	 * @return a byte array representing the key identifier, or null if the
	 *         extension is not present in the certificate
	 */
	public byte[] getSubjectKeyIdentifier(X509Certificate cert);

	/**
	 * Gets the list of key usage saved in the X509 Certificate
	 * 
	 * @param cert
	 *            X509 certificate that contains the keyUsage extension
	 * @return List of Key Usages, see supported keyUsages values at
	 *         X509UtilsDictionary, i.e.
	 *         X509UtilsDictionary.X509_KEYUSAGE_DECIPHER_ONLY, or null if the
	 *         extension is not present in the certificate
	 */
	public List<Integer> getKeyUsageList(X509Certificate cert);

	/**
	 * Get the certificate type, in base of the basicConstrain certificate
	 * extension
	 * 
	 * @param cert
	 *            X509 certificate that contains the basicConstrains extension
	 * @param language
	 *            ISO Language code to be used for getting the String
	 *            equivalence
	 * @return Certificate type, see supported types at X509UtilsDictionary,
	 *         i.e. X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA, or null if the
	 *         extension is not present in the certificate
	 */
	public String getExtensionCertificateType(X509Certificate cert,
			String language);

	/**
	 * Get the certificate information map from a X509 Certificate
	 * 
	 * @param cert
	 *            X509 certificate that contains the basicConstrains extension
	 * @return Map filled out with the certificate information using the Field
	 *         key (
	 *         {@link cinvestav.android.pki.cryptography.cert.CertificateInformationKeys}
	 *         Supported Keys) and the field value
	 */
	public HashMap<String, String> getCertificateInformationMap(
			X509Certificate cert);

	/**
	 * Get the certificate DEVICE_ID extension
	 * 
	 * @param cert
	 *            X509 certificate that contains the DEVICE_ID extension
	 * @return String representing the value of the DEVICE_ID extension if
	 *         present, or null otherwise
	 */
	public String getExtensionDeviceId(X509Certificate cert);

	/**
	 * Get the certificate SIGN_DEVICE_ID extension
	 * 
	 * @param cert
	 *            X509 certificate that contains the SIGN_DEVICE_ID extension
	 * @return String representing the value of the SIGN_DEVICE_ID extension if
	 *         present, or null otherwise
	 */
	public String getExtensionSignDeviceId(X509Certificate cert);

	/**
	 * Get the certificate USER_ID extension
	 * 
	 * @param cert
	 *            X509 certificate that contains the USER_ID extension
	 * @return String representing the value of the USER_ID extension if
	 *         present, or null otherwise
	 */
	public String getExtensionUserId(X509Certificate cert);

	/**
	 * Get the certificate USER_PERMISSION_ID extension
	 * 
	 * @param cert
	 *            X509 certificate that contains the USER_PERMISSION_ID
	 *            extension
	 * @return String representing the value of the USER_PERMISSION_ID extension
	 *         if present, or null otherwise
	 */
	public String getExtensionUserPermissionId(X509Certificate cert);

	/**
	 * Get the certificate IDENTIFICATION_DOCUMENT extension
	 * 
	 * @param cert
	 *            X509 certificate that contains the IDENTIFICATION_DOCUMENT
	 *            extension
	 * @return String representing the value of the IDENTIFICATION_DOCUMENT
	 *         extension if present, or null otherwise
	 */
	public String getExtensionIdentificationDocument(X509Certificate cert);

	/**
	 * Get the certificate creation position latitude coordinate extension
	 * 
	 * @param cert
	 *            X509 certificate that contains CREATION_POSITION_LATITUDE
	 *            extension
	 * @return String representing the value of the certificate creation
	 *         position X extension if present, or null otherwise
	 */
	public String getExtensionCreationPositionLatitude(X509Certificate cert);

	/**
	 * Get the certificate creation position longitude coordinate extension
	 * 
	 * @param cert
	 *            X509 certificate that contains CREATION_POSITION_LONGITUDE
	 *            extension
	 * @return String representing the value of the certificate creation
	 *         position Y extension if present, or null otherwise
	 */
	public String getExtensionCreationPositionLongitude(X509Certificate cert);

	/**
	 * Get the certificate CA_CERTIFICATE_SERIAL_NUMBER extension
	 * 
	 * @param cert
	 *            X509 certificate that contains the
	 *            CA_CERTIFICATE_SERIAL_NUMBER extension
	 * @return String representing the value of the CA_CERTIFICATE_SERIAL_NUMBER
	 *         extension if present, or null otherwise
	 */
	public String getExtensionCACertificateSerialNumber(X509Certificate cert);

	/**
	 * Get the certificate CA_CERTIFICATE_SIGN_DEVICE_ID extension
	 * 
	 * @param cert
	 *            X509 certificate that contains the
	 *            CA_CERTIFICATE_SIGN_DEVICE_ID extension
	 * @return String representing the value of the
	 *         CA_CERTIFICATE_SIGN_DEVICE_ID extension if present, or null
	 *         otherwise
	 */
	public String getExtensionCACertificateSignDeviceId(X509Certificate cert);

	/**
	 * Get the certificate CA_CERTIFICATE_SIGN_AUTHORITY_KEY_ID extension
	 * 
	 * @param cert
	 *            X509 certificate that contains the
	 *            CA_CERTIFICATE_SIGN_AUTHORITY_KEY_ID extension
	 * @return String representing the value of the
	 *         CA_CERTIFICATE_SIGN_AUTHORITY_KEY_ID extension if present, or
	 *         null otherwise
	 */
	public String getExtensionCACertificateAuthorityKeyId(X509Certificate cert);

}
