/**
 *  Created on  : 21/05/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Implements a set of functions for X509 certificates and CRLs
 *  
 */
package cinvestav.android.pki.cryptography.utils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Reader;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;

import javax.security.auth.x500.X500Principal;

import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERBMPString;
import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x500.RDN;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x500.X500NameBuilder;
import org.spongycastle.asn1.x500.style.BCStrictStyle;
import org.spongycastle.asn1.x500.style.BCStyle;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.AuthorityKeyIdentifier;
import org.spongycastle.asn1.x509.BasicConstraints;
import org.spongycastle.asn1.x509.CRLNumber;
import org.spongycastle.asn1.x509.ExtendedKeyUsage;
import org.spongycastle.asn1.x509.KeyPurposeId;
import org.spongycastle.asn1.x509.KeyUsage;
import org.spongycastle.asn1.x509.SubjectKeyIdentifier;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.asn1.x509.X509Extension;
import org.spongycastle.cert.CertIOException;
import org.spongycastle.cert.X509CRLHolder;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.X509v2CRLBuilder;
import org.spongycastle.cert.X509v3CertificateBuilder;
import org.spongycastle.cert.jcajce.JcaX509CRLConverter;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.cert.jcajce.JcaX509CertificateHolder;
import org.spongycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.spongycastle.jce.X509KeyUsage;
import org.spongycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openssl.PEMReader;
import org.spongycastle.openssl.PEMWriter;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.spongycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.bc.BcRSAContentSignerBuilder;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.x509.extension.X509ExtensionUtil;

import android.util.SparseIntArray;

import cinvestav.android.pki.cryptography.cert.CertificateInformationKeys;
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
 * Implements a set of functions for X509 certificates and CRLs
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 21/05/2012
 * @version 1.0
 */
/**
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 19/09/2012
 * @version 1.0
 */
public class X509Utils implements IX509Utils {

	/**
	 * List containing all the EC sign Algorithm supported by this class
	 */
	public static final List<String> supportedECSignAlgorithm = Arrays.asList(
			X509UtilsDictionary.EC_X509_SIGN_ALGORITHM_SHA1withECDSA,
			X509UtilsDictionary.EC_X509_SIGN_ALGORITHM_SHA224withECDSA,
			X509UtilsDictionary.EC_X509_SIGN_ALGORITHM_SHA256withECDSA,
			X509UtilsDictionary.EC_X509_SIGN_ALGORITHM_SHA384withECDSA,
			X509UtilsDictionary.EC_X509_SIGN_ALGORITHM_SHA512withECDSA);

	/**
	 * List containing all the RSA sign Algorithm supported by this class
	 */
	public static final List<String> supportedRSASignAlgorithm = Arrays.asList(
			X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_MD2withRSA,
			X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_MD5withRSA,
			X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_SHA1withRSA,
			X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_SHA224withRSA,
			X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_SHA256withRSA,
			X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_SHA384withRSA,
			X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_SHA512withRSA,
			X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_RIPEMD160withRSA,
			X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_RIPEMD128withRSA,
			X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_RIPEMD256withRSA);

	private static final SparseIntArray keyUsageMap = new SparseIntArray();

	static {
		Security.addProvider(new BouncyCastleProvider());
		keyUsageMap.put(X509UtilsDictionary.X509_KEYUSAGE_CRL_SIGN,
				KeyUsage.cRLSign);
		keyUsageMap.put(X509UtilsDictionary.X509_KEYUSAGE_DATA_ENCIPHERMENT,
				KeyUsage.dataEncipherment);
		keyUsageMap.put(X509UtilsDictionary.X509_KEYUSAGE_DECIPHER_ONLY,
				KeyUsage.decipherOnly);
		keyUsageMap.put(X509UtilsDictionary.X509_KEYUSAGE_DIGITAL_SIGNATURE,
				KeyUsage.digitalSignature);
		keyUsageMap.put(X509UtilsDictionary.X509_KEYUSAGE_ENCIPHER_ONLY,
				KeyUsage.encipherOnly);
		keyUsageMap.put(X509UtilsDictionary.X509_KEYUSAGE_KEY_AGREEMENT,
				KeyUsage.keyAgreement);
		keyUsageMap.put(X509UtilsDictionary.X509_KEYUSAGE_KEY_CERT_SIGN,
				KeyUsage.keyCertSign);
		keyUsageMap.put(X509UtilsDictionary.X509_KEYUSAGE_KEY_ENCIPHERMENT,
				KeyUsage.keyEncipherment);
		keyUsageMap.put(X509UtilsDictionary.X509_KEYUSAGE_NONREPUDIATION,
				KeyUsage.nonRepudiation);
	}

	JcaX509ExtensionUtils jcaX509ExtensionUtils;
	KeyStore store;
	CertificateFactory fact;

	public X509Utils() throws CryptoUtilsException {
		super();
		try {
			jcaX509ExtensionUtils = new JcaX509ExtensionUtils();

			fact = CertificateFactory
					.getInstance("X.509", CryptoUtils.PROVIDER);
		} catch (CertificateException e) {
			throw new CryptoUtilsException("Create X509 utils error: " + e, e);
		} catch (NoSuchProviderException e) {
			throw new CryptoUtilsException("Create X509 utils error: " + e, e);

		} catch (NoSuchAlgorithmException e) {

			throw new CryptoUtilsException("Create X509 utils error: " + e, e);
		}
	}

	public static Boolean comparePrincipal(X500Principal principal1,
			X500Principal principal2) {
		X500Name p1 = X500Name.getInstance(principal1.getEncoded());
		X500Name p2 = X500Name.getInstance(principal2.getEncoded());

		return p1.equals(p2);

	}

	/**
	 * Generates a x500NameBuilder using a hashMap that contains the necessary
	 * information,
	 * 
	 * @param certificateInformationMap
	 *            Map filled out with the certificate information using the
	 *            Field key (
	 *            {@link cinvestav.android.pki.cryptography.cert.CertificateInformationKeys}
	 *            Supported Keys) and the field value
	 * @see cinvestav.android.pki.cryptography.cert.CertificateInformationKeys
	 * @return
	 */
	private static X500NameBuilder generateX500NameBuilder(
			HashMap<String, String> certificateInformationMap) {
		X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
		BCStyle style = new BCStrictStyle();

		Iterator<Entry<String, String>> it = certificateInformationMap
				.entrySet().iterator();
		while (it.hasNext()) {
			Entry<String, String> pair = it.next();
			try {
				// Try to look up the key Name and add the field to the builder
				builder.addRDN(style.attrNameToOID(pair.getKey()),
						pair.getValue());
			} catch (IllegalArgumentException ex) {
				// If the key hasn't been found in the lookup table
			}
		}

		return builder;
	}

	/**
	 * Validate if the algorithm is supported by this class
	 * 
	 * @param algorithm
	 * @return True if the algorithm is supported, false otherwise
	 */
	private Boolean validateECSignAlgorithm(String algorithm) {
		return supportedECSignAlgorithm.contains(algorithm);
	}

	/**
	 * Validate if the algorithm is supported by this class
	 * 
	 * @param algorithm
	 * @return True if the algorithm is supported, false otherwise
	 */
	private Boolean validateRSASignAlgorithm(String algorithm) {
		return supportedRSASignAlgorithm.contains(algorithm);
	}

	/**
	 * Add an X509 Extension for KeyUsage Extension, using the list of the
	 * desired key usages
	 * 
	 * @param isCritical
	 *            If the extension should be marked as critical or not
	 * @param keyUsageList
	 *            List of Key Usages, see supported keyUsages at
	 *            X509UtilsDictionary, i.e.
	 *            X509UtilsDictionary.X509_KEYUSAGE_DECIPHER_ONLY
	 * @return an X509 Extension corresponding to Key usage
	 * @throws IOException
	 */
	private X509v3CertificateBuilder addKeyUsageExtension(
			X509v3CertificateBuilder v3CertGen, Boolean isCritical,
			List<Integer> keyUsageList) throws IOException {
		int usage = 0;
		for (Integer keyUsage : keyUsageList) {
			usage |= keyUsageMap.get(keyUsage);
		}
		v3CertGen.addExtension(X509Extension.keyUsage, true, new X509KeyUsage(
				usage));
		return v3CertGen;
	}

	/**
	 * Adds basic Constrain extension to a certificate builder, using the type
	 * of certificate
	 * 
	 * @param v3CertGen
	 *            V3 Certificate Builder to which the extension will be added
	 * @param certType
	 *            Certificate type
	 * @return The Certificate builder with the added extension
	 * @throws CertIOException
	 */
	private X509v3CertificateBuilder addBasicConstrainExtension(
			X509v3CertificateBuilder v3CertGen, String certType)
			throws CertIOException {
		// If the certificate is an END_OWNER cert, the owner could not issue
		// other certificates
		if (certType
				.equalsIgnoreCase(X509UtilsDictionary.CERTIFICATE_TYPE_END_OWNER)) {
			return v3CertGen.addExtension(X509Extension.basicConstraints,
					false, new BasicConstraints(Boolean.FALSE));
		}
		if (certType
				.equalsIgnoreCase(X509UtilsDictionary.CERTIFICATE_TYPE_FINAL_CA)) {
			return v3CertGen.addExtension(X509Extension.basicConstraints, true,
					new BasicConstraints(10));
		}

		if (certType
				.equalsIgnoreCase(X509UtilsDictionary.CERTIFICATE_TYPE_INTERMEDIATE_CA)) {
			return v3CertGen.addExtension(X509Extension.basicConstraints, true,
					new BasicConstraints(100));
		}

		return v3CertGen.addExtension(X509Extension.basicConstraints, true,
				new BasicConstraints(1000));
	}

	/**
	 * Add the PKI Personal Extension to a certificate builder, using the
	 * certificate information map to fill the corresponding fields, the
	 * extensions may include:
	 * <ul>
	 * <li>device id
	 * <li>user id
	 * <li>creation position
	 * <li>user permissions,
	 * <li>identification document
	 * <li>sign device id
	 * <li>CA certificate serial number
	 * <li>CA sign device id
	 * <li>CA authority key id
	 * </ul>
	 * 
	 * @param v3CertGen
	 *            V3 Certificate Builder to which the extension will be added
	 * @param certificateInformationMap
	 *            Map filled out with the certificate information using the
	 *            Field key (
	 *            {@link cinvestav.android.pki.cryptography.cert.CertificateInformationKeys}
	 *            Supported Keys) and the field value
	 * @param caCertificateSerialNumber
	 *            Serial number of the CA certificate used for sign the
	 *            certificate
	 * @param caSignDeviceId
	 *            Sign Device ID of the CA certificate
	 * @param caAuthorityKey
	 *            Authority Key ID value of the CA certificate
	 * @return The Certificate builder with the added extensions
	 * @throws CertIOException
	 * @throws CryptoUtilsX509ExtensionException
	 *             if the device Id is not present in the
	 *             certificateInformationMap
	 */
	private X509v3CertificateBuilder addCustomExtensions(
			X509v3CertificateBuilder v3CertGen,
			HashMap<String, String> certificateInformationMap,
			BigInteger caCertificateSerialNumber, String caSignDeviceId,
			byte[] caAuthorityKey) throws CertIOException,
			CryptoUtilsX509ExtensionException {

		// If device ID is present in the certificateInformationMap add its
		// extension to the certificate
		if (certificateInformationMap
				.containsKey(CertificateInformationKeys.DEVICE_ID)) {
			v3CertGen.addExtension(
					CertificateInformationKeys.DEVICE_ID_OID,
					true,
					new DEROctetString(certificateInformationMap.get(
							CertificateInformationKeys.DEVICE_ID).getBytes()));
		} else {
			throw new CryptoUtilsX509ExtensionException(
					"Device Id must be present in the certificateInformationMap in order to create a certificate");
		}

		// If device ID is present in the certificateInformationMap add its
		// extension to the certificate
		if (certificateInformationMap
				.containsKey(CertificateInformationKeys.SIGN_DEVICE_ID)) {
			v3CertGen.addExtension(
					CertificateInformationKeys.SIGN_DEVICE_ID_OID,
					true,
					new DEROctetString(certificateInformationMap.get(
							CertificateInformationKeys.SIGN_DEVICE_ID)
							.getBytes()));
		} else {
			throw new CryptoUtilsX509ExtensionException(
					"Sign Device Id must be present in the certificateInformationMap in order to create a certificate");
		}

		// If CREATION_POSITION_LATITUDE is present in the
		// certificateInformationMap
		// add
		// its extension to the certificate
		if (certificateInformationMap
				.containsKey(CertificateInformationKeys.CREATION_POSITION_LATITUDE)) {
			v3CertGen
					.addExtension(
							CertificateInformationKeys.CREATION_POSITION_LATITUDE_OID,
							false,
							new DEROctetString(
									certificateInformationMap
											.get(CertificateInformationKeys.CREATION_POSITION_LATITUDE)
											.getBytes()));
		}

		// If CREATION_POSITION_LONGITUDE is present in the
		// certificateInformationMap
		// add
		// its extension to the certificate
		if (certificateInformationMap
				.containsKey(CertificateInformationKeys.CREATION_POSITION_LONGITUDE)) {
			v3CertGen
					.addExtension(
							CertificateInformationKeys.CREATION_POSITION_LONGITUDE_OID,
							false,
							new DEROctetString(
									certificateInformationMap
											.get(CertificateInformationKeys.CREATION_POSITION_LONGITUDE)
											.getBytes()));
		}

		// If user ID is present in the certificateInformationMap add its
		// extension to the certificate
		if (certificateInformationMap
				.containsKey(CertificateInformationKeys.USER_ID)) {
			v3CertGen.addExtension(
					CertificateInformationKeys.USER_ID_OID,
					false,
					new DEROctetString(certificateInformationMap.get(
							CertificateInformationKeys.USER_ID).getBytes()));
		}

		// If identification document is present in the
		// certificateInformationMap add its extension to the certificate
		if (certificateInformationMap
				.containsKey(CertificateInformationKeys.IDENTIFICATION_DOCUMENT)) {
			v3CertGen.addExtension(
					CertificateInformationKeys.IDENTIFICATION_DOCUMENT_OID,
					false,
					new DEROctetString(certificateInformationMap.get(
							CertificateInformationKeys.IDENTIFICATION_DOCUMENT)
							.getBytes()));
		}

		// If User permission id is present in the certificateInformationMap add
		// its extension to the certificate
		if (certificateInformationMap
				.containsKey(CertificateInformationKeys.USER_PERMISSION_ID)) {
			v3CertGen.addExtension(
					CertificateInformationKeys.USER_PERMISSION_OID,
					false,
					new DEROctetString(certificateInformationMap.get(
							CertificateInformationKeys.USER_PERMISSION_ID)
							.getBytes()));
		}

		if (caCertificateSerialNumber != null) {
			// Add CAs certificate serial number
			v3CertGen
					.addExtension(
							CertificateInformationKeys.CA_CERTIFICATE_SERIAL_NUMBER_OID,
							true, new DEROctetString(caCertificateSerialNumber
									.toString().getBytes()));
		} else {
			throw new CryptoUtilsX509ExtensionException(
					"CA Certificate Serial Number must not be null in order to create a certificate");
		}

		if (caAuthorityKey != null) {
			// Add CAs certificate authorityKeyId
			v3CertGen
					.addExtension(
							CertificateInformationKeys.CA_CERTIFICATE_SIGN_AUTHORITY_KEY_ID_OID,
							false, new DEROctetString(caAuthorityKey));
		}

		if (caSignDeviceId != null) {
			// Add CAs certificate Sign device id
			v3CertGen
					.addExtension(
							CertificateInformationKeys.CA_CERTIFICATE_SIGN_DEVICE_ID_OID,
							false,
							new DEROctetString(caSignDeviceId.getBytes()));
		}

		return v3CertGen;
	}

	/**
	 * Check if the CA Certificate full fill the requirements for X509
	 * certificate signing depending on its X509Extensions (keyUsage and
	 * BasicConstraint) and the desired certificate type that will be issued
	 * 
	 * @param caCert
	 *            Certificate that will be used for sign the certificate
	 * @param certType
	 *            Certificate type that will be issued
	 * @throws CryptoUtilsX509ExtensionException
	 *             If the CA certificate has expired or has not the correct
	 *             basic constraints and key usage values needed for issue a
	 *             certificate
	 */
	private void checkX509CACertificateRequirements(X509Certificate caCert,
			String certType) throws CryptoUtilsX509ExtensionException {

		if (caCert == null) {
			throw new CryptoUtilsX509ExtensionException(
					"Create X509 V3 Certificate error: NULL CA certificate");
		}
		// CAs cert validation
		try {
			// if the certificate is not valid due to time constrains an
			// exception will be raised
			caCert.checkValidity();
		} catch (CertificateExpiredException e1) {
			throw new CryptoUtilsX509ExtensionException(
					"Create X509 V3 Certificate error: CA certificate has expired");
		} catch (CertificateNotYetValidException e1) {
			throw new CryptoUtilsX509ExtensionException(
					"Create X509 V3 Certificate error: CA certificate is not yet valid");
		}

		// Basic Constraint verification
		String basicConstraintOID = X509Extension.basicConstraints.toString();
		BasicConstraints basicConstraint;
		try {
			byte[] basicConstraintArray = caCert
					.getExtensionValue(basicConstraintOID);
			// If the extension is not present in the certificate
			if (basicConstraintArray == null) {
				throw new CryptoUtilsX509ExtensionException(
						"X509 V3 Certificate Extension error: "
								+ "CA certificate has no basic constrain extension, "
								+ "so it should not be used for certificate signing");
			}

			basicConstraint = BasicConstraints.getInstance(X509ExtensionUtil
					.fromExtensionValue(basicConstraintArray));

			// Check if the CA certificate is marked as CA
			if (!basicConstraint.isCA()) {
				throw new CryptoUtilsX509ExtensionException(
						"Basic constraint verification error: "
								+ "Only certificates marked as CA certificate could sign other certificates");
			}

			BigInteger pathLength = basicConstraint.getPathLenConstraint();
			// If the pathLength is zero, so the CA is a FINAL_CA and only
			// should issue END_OWNER certificates
			if (pathLength.equals(new BigInteger("10"))
					&& !certType
							.equalsIgnoreCase(X509UtilsDictionary.CERTIFICATE_TYPE_END_OWNER)
					&& !certType
							.equalsIgnoreCase(X509UtilsDictionary.CERTIFICATE_TYPE_FINAL_CA)) {
				throw new CryptoUtilsX509ExtensionException(
						"Basic constraint verification error: "
								+ "FINAL_CA only should issue END_OWNER type certificates "
								+ "and its trying to issue a " + certType
								+ " certificate");
			}
			// If pathLength is 100, so the CA is a INTERMEDIATE_CA so it should
			// not issue root ca certificates
			if (pathLength.equals(new BigInteger("100"))
					&& certType
							.equalsIgnoreCase(X509UtilsDictionary.CERTIFICATE_TYPE_ROOT_CA)) {
				throw new CryptoUtilsX509ExtensionException(
						"Basic constraint verification error: "
								+ "INTERMEDIATE CA should not issue ROOT CA type certificates ");

			}

		} catch (IOException e1) {
			throw new CryptoUtilsX509ExtensionException(
					"Create X509 V3 Certificate error: " + e1, e1);
		}

		boolean keyUsage[] = caCert.getKeyUsage();
		if (keyUsage == null || !keyUsage[5]) {
			throw new CryptoUtilsX509ExtensionException(
					"KeyUsage extension verification error: "
							+ "CAs key is not marked as valid for certificate signing");
		}
	}

	/**
	 * Check if the CA Certificate full fill the requirements for X509 CRL
	 * signing depending on its X509Extensions (keyUsage) and the desired
	 * certificate type that will be issued
	 * 
	 * @param caCert
	 *            Certificate that will be used for sign the certificate
	 * @throws CryptoUtilsX509ExtensionException
	 *             If the CA certificate has expired or has not the correct key
	 *             usage values needed for issue a certificate
	 */
	private void checkX509CRLCACertificateRequirements(X509Certificate caCert)
			throws CryptoUtilsX509ExtensionException {

		if (caCert == null) {
			throw new CryptoUtilsX509ExtensionException(
					"Create X509 V3 Certificate error: NULL CA certificate");
		}
		// CAs cert validation
		try {
			// if the certificate is not valid due to time constrains an
			// exception will be raised
			caCert.checkValidity();
		} catch (CertificateExpiredException e1) {
			throw new CryptoUtilsX509ExtensionException(
					"Create X509 V3 Certificate error: CA certificate has expired");
		} catch (CertificateNotYetValidException e1) {
			throw new CryptoUtilsX509ExtensionException(
					"Create X509 V3 Certificate error: CA certificate is not yet valid");
		}

		boolean keyUsage[] = caCert.getKeyUsage();
		if (keyUsage == null || !keyUsage[6]) {
			throw new CryptoUtilsX509ExtensionException(
					"KeyUsage extension verification error: "
							+ "CAs key is not marked as valid for CRL signing");
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#createV3Cert(cinvestav
	 * .android.pki.cryptography.key.RSAPublicKey,
	 * cinvestav.android.pki.cryptography.key.RSAPrivateKey,
	 * java.math.BigInteger, java.util.Date, java.util.Date,
	 * java.security.cert.X509Certificate, java.util.HashMap, java.util.List,
	 * java.lang.String)
	 */
	@Override
	public X509Certificate createV3Cert(RSAPublicKey pubKey,
			RSAPrivateKey caPrivKey, BigInteger serial, Date notBefore,
			Date notAfter, X509Certificate caCert,
			HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException {
		return createV3Cert(pubKey, caPrivKey, serial, notBefore, notAfter,
				caCert, certificateInformationMap, keyUsageList, certType,
				X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_SHA1withRSA);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#createV3Cert(cinvestav
	 * .android.pki.cryptography.key.RSAPublicKey,
	 * cinvestav.android.pki.cryptography.key.RSAPrivateKey,
	 * java.math.BigInteger, java.util.Date, java.util.Date, java.util.HashMap,
	 * java.util.List, java.lang.String)
	 */
	@Override
	public X509Certificate createV3Cert(RSAPublicKey pubKey,
			RSAPrivateKey privKey, BigInteger serial, Date notBefore,
			Date notAfter, HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException {
		return createV3Cert(pubKey, privKey, serial, notBefore, notAfter,
				certificateInformationMap, keyUsageList, certType,
				X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_SHA1withRSA);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#createV3Cert(cinvestav
	 * .android.pki.cryptography.key.RSAPublicKey,
	 * cinvestav.android.pki.cryptography.key.RSAPrivateKey,
	 * java.math.BigInteger, java.util.Date, java.util.Date, java.util.HashMap,
	 * java.util.List, java.lang.String, java.lang.String)
	 */
	@Override
	public X509Certificate createV3Cert(RSAPublicKey pubKey,
			RSAPrivateKey privKey, BigInteger serial, Date notBefore,
			Date notAfter, HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType, String algorithm)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException {
		if (!validateRSASignAlgorithm(algorithm))
			throw new CryptoUtilsException(
					"Create X509 V3 Certificate error: Selected algorithm ["
							+ algorithm + "] is not supported");

		X509v3CertificateBuilder v3CertGen;

		// Get x500 name Builder from the certificateInformationMap
		X500NameBuilder builder = generateX500NameBuilder(certificateInformationMap);

		// Signer Algorithm ID
		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
				.find(algorithm);

		// Digest Algorithm ID
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
				.find(sigAlgId);

		ContentSigner contentSigner;
		try {
			// Create content Signer Object from using the CAs privateKey
			contentSigner = new BcRSAContentSignerBuilder(sigAlgId, digAlgId)
					.build(privKey.parseToRSAPrivateCrtKeyParameters());

			// Get the Public key contained in the certificate
			SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo(
					new AlgorithmIdentifier(
							PKCSObjectIdentifiers.rsaEncryption,
							DERNull.INSTANCE), pubKey.parseToRSAPublicKey());

			//
			// create the certificate - version 3
			//
			X500Name issuer = builder.build();
			X500Name subject = builder.build();
			v3CertGen = new X509v3CertificateBuilder(issuer, serial, notBefore,
					notAfter, subject, pubInfo);

			//
			// extensions
			//
			// AuthorityKeyIdentifier
			AuthorityKeyIdentifier authorityKeyId = jcaX509ExtensionUtils
					.createAuthorityKeyIdentifier(pubKey
							.parseToJCERSAPublicKey());
			v3CertGen.addExtension(X509Extension.authorityKeyIdentifier, false,
					authorityKeyId);

			// SubjectKeyIdentifier
			v3CertGen.addExtension(X509Extension.subjectKeyIdentifier, true,
					jcaX509ExtensionUtils.createSubjectKeyIdentifier(pubKey
							.parseToJCERSAPublicKey()));
			// KeyUsage
			v3CertGen = addKeyUsageExtension(v3CertGen, Boolean.TRUE,
					keyUsageList);

			// Subject Alternative Name
			// TODO Agregar extension

			// Basic Constrain
			v3CertGen = addBasicConstrainExtension(v3CertGen, certType);

			// Extended Key Usage
			ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(
					KeyPurposeId.anyExtendedKeyUsage);
			v3CertGen.addExtension(X509Extension.extendedKeyUsage, false,
					extendedKeyUsage);

			// Add the custom extensions to the certificate, the extensions
			// include:
			// device id, user id, creation position, user permissions,
			// identification document
			v3CertGen = addCustomExtensions(v3CertGen,
					certificateInformationMap, serial,
					certificateInformationMap
							.get(CertificateInformationKeys.SIGN_DEVICE_ID),
					authorityKeyId.getKeyIdentifier());

			X509CertificateHolder certHolder = v3CertGen.build(contentSigner);
			X509Certificate cert = new JcaX509CertificateConverter()
					.setProvider(CryptoUtils.PROVIDER).getCertificate(
							certHolder);

			// cert.checkValidity(new Date());

			cert.verify(pubKey.parseToJCERSAPublicKey());

			PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) cert;

			//
			// this is actually optional - but if you want to have control
			// over setting the friendly name this is the way to do it...
			//
			if (certificateInformationMap
					.containsKey(CertificateInformationKeys.FRIENDLY_NAME)) {
				bagAttr.setBagAttribute(
						PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
						new DERBMPString(certificateInformationMap
								.get(CertificateInformationKeys.FRIENDLY_NAME)));
			}

			SubjectKeyIdentifier keyID = SubjectKeyIdentifier
					.getInstance(jcaX509ExtensionUtils
							.createSubjectKeyIdentifier(pubKey
									.parseToJCERSAPublicKey()));
			bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
					keyID.toASN1Primitive());

			return cert;
		} catch (OperatorCreationException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (CertificateException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (InvalidKeyException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (NoSuchAlgorithmException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (NoSuchProviderException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (SignatureException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (CertIOException e) {
			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (IOException e) {
			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#createV3Cert(cinvestav
	 * .android.pki.cryptography.key.RSAPublicKey,
	 * cinvestav.android.pki.cryptography.key.RSAPrivateKey,
	 * java.math.BigInteger, java.util.Date, java.util.Date,
	 * java.security.cert.X509Certificate, java.util.HashMap, java.util.List,
	 * java.lang.String, java.lang.String)
	 */
	@Override
	public X509Certificate createV3Cert(RSAPublicKey pubKey,
			RSAPrivateKey caPrivKey, BigInteger serial, Date notBefore,
			Date notAfter, X509Certificate caCert,
			HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType, String algorithm)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException {
		if (!validateRSASignAlgorithm(algorithm))
			throw new CryptoUtilsException(
					"Create X509 V3 Certificate error: Selected algorithm ["
							+ algorithm + "] is not supported");

		// Check if the CA certificate full fill the requirements for issuing
		// the desired certificate
		checkX509CACertificateRequirements(caCert, certType);

		X509v3CertificateBuilder v3CertGen;

		// Get x500 name Builder from the certificateInformationMap
		X500NameBuilder builder = generateX500NameBuilder(certificateInformationMap);

		// Signer Algorithm ID
		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
				.find(algorithm);

		// Digest Algorithm ID
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
				.find(sigAlgId);

		ContentSigner contentSigner;
		try {
			// Create content Signer Object from using the CAs privateKey
			contentSigner = new BcRSAContentSignerBuilder(sigAlgId, digAlgId)
					.build(caPrivKey.parseToRSAPrivateCrtKeyParameters());

			// Get the Public key contained in the certificate
			SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo(
					new AlgorithmIdentifier(
							PKCSObjectIdentifiers.rsaEncryption,
							DERNull.INSTANCE), pubKey.parseToRSAPublicKey());

			//
			// create the certificate - version 3
			//
			v3CertGen = new X509v3CertificateBuilder(new X500Name(caCert
					.getSubjectX500Principal().getName()), serial, notBefore,
					notAfter, builder.build(), pubInfo);

			//
			// extensions
			//
			// AuthorityKeyIdentifier
			v3CertGen.addExtension(X509Extension.authorityKeyIdentifier, false,
					jcaX509ExtensionUtils.createAuthorityKeyIdentifier(caCert
							.getPublicKey()));

			// SubjectKeyIdentifier
			v3CertGen.addExtension(X509Extension.subjectKeyIdentifier, true,
					jcaX509ExtensionUtils.createSubjectKeyIdentifier(pubKey
							.parseToJCERSAPublicKey()));
			// KeyUsage
			v3CertGen = addKeyUsageExtension(v3CertGen, Boolean.TRUE,
					keyUsageList);

			// Subject Alternative Name
			// TODO Agregar extension

			// Basic Constrain
			v3CertGen = addBasicConstrainExtension(v3CertGen, certType);

			// Extended Key Usage
			ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(
					KeyPurposeId.anyExtendedKeyUsage);
			v3CertGen.addExtension(X509Extension.extendedKeyUsage, false,
					extendedKeyUsage);

			// Add the custom extensions to the certificate, the extensions
			// include:
			// device id, user id, creation position, user permissions,
			// identification document
			v3CertGen = addCustomExtensions(v3CertGen,
					certificateInformationMap, caCert.getSerialNumber(),
					getExtensionSignDeviceId(caCert),
					getAuthorityKeyIdentifier(caCert));

			X509CertificateHolder certHolder = v3CertGen.build(contentSigner);

			X509Certificate cert = new JcaX509CertificateConverter()
					.setProvider(CryptoUtils.PROVIDER).getCertificate(
							certHolder);

			// cert.checkValidity(new Date());

			cert.verify(caCert.getPublicKey());

			PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) cert;

			//
			// this is actually optional - but if you want to have control
			// over setting the friendly name this is the way to do it...
			//
			if (certificateInformationMap
					.containsKey(CertificateInformationKeys.FRIENDLY_NAME)) {
				bagAttr.setBagAttribute(
						PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
						new DERBMPString(certificateInformationMap
								.get(CertificateInformationKeys.FRIENDLY_NAME)));
			}

			SubjectKeyIdentifier keyID = SubjectKeyIdentifier
					.getInstance(jcaX509ExtensionUtils
							.createSubjectKeyIdentifier(pubKey
									.parseToJCERSAPublicKey()));
			bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
					keyID.toASN1Primitive());

			return cert;
		} catch (OperatorCreationException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (CertificateException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (InvalidKeyException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (NoSuchProviderException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (SignatureException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (CertIOException e) {
			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (IOException e) {
			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#createV3Cert(cinvestav
	 * .android.pki.cryptography.key.ECPublicKey,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey,
	 * java.math.BigInteger, java.util.Date, java.util.Date, java.util.HashMap,
	 * java.util.List, java.lang.String, java.lang.String)
	 */
	@Override
	public X509Certificate createV3Cert(ECPublicKey pubKey,
			ECPrivateKey privKey, BigInteger serial, Date notBefore,
			Date notAfter, HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType, String algorithm)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException {
		// Validate if the selected algorithm is supported
		if (!validateECSignAlgorithm(algorithm))
			throw new CryptoUtilsException(
					"Create X509 V3 Certificate error: Selected algorithm ["
							+ algorithm + "] is not supported");

		X509v3CertificateBuilder v3CertGen;

		// Get x500 name Builder from the certificateInformationMap
		X500NameBuilder builder = generateX500NameBuilder(certificateInformationMap);

		ContentSigner contentSigner;
		try {
			// Create content Signer Object from using the CAs privateKey
			contentSigner = new JcaContentSignerBuilder(algorithm).setProvider(
					CryptoUtils.PROVIDER).build(
					privKey.parseToJCEECPrivateKey());

			// Get the Public key contained in the certificate
			SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo
					.getInstance(pubKey.parseToJCEECPublic().getEncoded());

			//
			// create the certificate - version 3
			//
			v3CertGen = new X509v3CertificateBuilder(builder.build(), serial,
					notBefore, notAfter, builder.build(), pubInfo);

			//
			// extensions
			//
			// AuthorityKeyIdentifier
			AuthorityKeyIdentifier authorityKeyId = jcaX509ExtensionUtils
					.createAuthorityKeyIdentifier(pubKey.parseToJCEECPublic());
			v3CertGen.addExtension(X509Extension.authorityKeyIdentifier, false,
					authorityKeyId);

			// SubjectKeyIdentifier
			v3CertGen.addExtension(X509Extension.subjectKeyIdentifier, true,
					jcaX509ExtensionUtils.createSubjectKeyIdentifier(pubKey
							.parseToJCEECPublic()));
			// KeyUsage
			v3CertGen = addKeyUsageExtension(v3CertGen, Boolean.TRUE,
					keyUsageList);

			// Subject Alternative Name
			// TODO Agregar extension

			// Basic Constrain
			v3CertGen = addBasicConstrainExtension(v3CertGen, certType);

			// Extended Key Usage
			ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(
					KeyPurposeId.anyExtendedKeyUsage);
			v3CertGen.addExtension(X509Extension.extendedKeyUsage, false,
					extendedKeyUsage);

			// Add the custom extensions to the certificate, the extensions
			// include:
			// device id, user id, creation position, user permissions,
			// identification document

			v3CertGen = addCustomExtensions(v3CertGen,
					certificateInformationMap, serial,
					certificateInformationMap
							.get(CertificateInformationKeys.SIGN_DEVICE_ID),
					authorityKeyId.getKeyIdentifier());

			X509CertificateHolder certHolder = v3CertGen.build(contentSigner);
			X509Certificate cert = new JcaX509CertificateConverter()
					.setProvider(CryptoUtils.PROVIDER).getCertificate(
							certHolder);

			// cert.checkValidity(new Date());

			cert.verify(pubKey.parseToJCEECPublic());

			PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) cert;

			//
			// this is actually optional - but if you want to have control
			// over setting the friendly name this is the way to do it...
			//
			if (certificateInformationMap
					.containsKey(CertificateInformationKeys.FRIENDLY_NAME)) {
				bagAttr.setBagAttribute(
						PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
						new DERBMPString(certificateInformationMap
								.get(CertificateInformationKeys.FRIENDLY_NAME)));
			}

			SubjectKeyIdentifier keyID = SubjectKeyIdentifier
					.getInstance(jcaX509ExtensionUtils
							.createSubjectKeyIdentifier(pubKey
									.parseToJCEECPublic()));
			bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
					keyID.toASN1Primitive());

			return cert;
		} catch (OperatorCreationException e) {
			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (CertificateException e) {
			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (InvalidKeyException e) {
			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (NoSuchProviderException e) {
			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (SignatureException e) {
			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (CertIOException e) {
			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (IOException e) {
			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#createV3Cert(cinvestav
	 * .android.pki.cryptography.key.ECPublicKey,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey,
	 * java.math.BigInteger, java.util.Date, java.util.Date,
	 * java.security.cert.X509Certificate, java.util.HashMap, java.util.List,
	 * java.lang.String, java.lang.String)
	 */
	@Override
	public X509Certificate createV3Cert(ECPublicKey pubKey,
			ECPrivateKey caPrivKey, BigInteger serial, Date notBefore,
			Date notAfter, X509Certificate caCert,
			HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType, String algorithm)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException {
		// Validate if the selected algorithm is supported
		if (!validateECSignAlgorithm(algorithm))
			throw new CryptoUtilsException(
					"Create X509 V3 Certificate error: Selected algorithm ["
							+ algorithm + "] is not supported");

		// Check if the CA certificate full fill the requirements for issuing
		// the desired certificate
		checkX509CACertificateRequirements(caCert, certType);

		X509v3CertificateBuilder v3CertGen;

		// Get x500 name Builder from the certificateInformationMap
		X500NameBuilder builder = generateX500NameBuilder(certificateInformationMap);

		ContentSigner contentSigner;
		try {
			// Create content Signer Object from using the CAs privateKey
			contentSigner = new JcaContentSignerBuilder(algorithm).setProvider(
					CryptoUtils.PROVIDER).build(
					caPrivKey.parseToJCEECPrivateKey());

			// Get the Public key contained in the certificate
			SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo
					.getInstance(pubKey.parseToJCEECPublic().getEncoded());

			//
			// create the certificate - version 3
			//
			v3CertGen = new X509v3CertificateBuilder(
					X500Name.getInstance(caCert.getSubjectX500Principal()
							.getEncoded()), serial, notBefore, notAfter,
					builder.build(), pubInfo);

			//
			// extensions
			//
			// AuthorityKeyIdentifier
			v3CertGen.addExtension(X509Extension.authorityKeyIdentifier, false,
					jcaX509ExtensionUtils.createAuthorityKeyIdentifier(caCert
							.getPublicKey()));

			// SubjectKeyIdentifier
			SubjectKeyIdentifier keyID = SubjectKeyIdentifier
					.getInstance(jcaX509ExtensionUtils
							.createSubjectKeyIdentifier(pubKey
									.parseToJCEECPublic()));
			v3CertGen.addExtension(X509Extension.subjectKeyIdentifier, true,
					keyID);
			// KeyUsage
			v3CertGen = addKeyUsageExtension(v3CertGen, Boolean.TRUE,
					keyUsageList);

			// Subject Alternative Name
			// TODO Agregar extension

			// Basic Constrain
			v3CertGen = addBasicConstrainExtension(v3CertGen, certType);

			// Extended Key Usage
			ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(
					KeyPurposeId.anyExtendedKeyUsage);
			v3CertGen.addExtension(X509Extension.extendedKeyUsage, false,
					extendedKeyUsage);

			// Add the custom extensions to the certificate, the extensions
			// include:
			// device id, user id, creation position, user permissions,
			// identification document
			v3CertGen = addCustomExtensions(v3CertGen,
					certificateInformationMap, caCert.getSerialNumber(),
					getExtensionSignDeviceId(caCert),
					getAuthorityKeyIdentifier(caCert));

			X509CertificateHolder certHolder = v3CertGen.build(contentSigner);

			X509Certificate cert = new JcaX509CertificateConverter()
					.setProvider(CryptoUtils.PROVIDER).getCertificate(
							certHolder);

			// cert.checkValidity(new Date());

			cert.verify(caCert.getPublicKey());

			PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) cert;

			//
			// this is actually optional - but if you want to have control
			// over setting the friendly name this is the way to do it...
			//
			if (certificateInformationMap
					.containsKey(CertificateInformationKeys.FRIENDLY_NAME)) {
				bagAttr.setBagAttribute(
						PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
						new DERBMPString(certificateInformationMap
								.get(CertificateInformationKeys.FRIENDLY_NAME)));
			}

			bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
					keyID.toASN1Primitive());

			return cert;
		} catch (OperatorCreationException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (CertificateException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (InvalidKeyException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (NoSuchProviderException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (SignatureException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (CertIOException e) {
			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (IOException e) {
			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#createV3Cert(cinvestav
	 * .android.pki.cryptography.key.ECPublicKey,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey,
	 * java.math.BigInteger, java.util.Date, java.util.Date, java.util.HashMap,
	 * java.util.List, java.lang.String)
	 */
	@Override
	public X509Certificate createV3Cert(ECPublicKey pubKey,
			ECPrivateKey privKey, BigInteger serial, Date notBefore,
			Date notAfter, HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException {
		return createV3Cert(pubKey, privKey, serial, notBefore, notAfter,
				certificateInformationMap, keyUsageList, certType,
				X509UtilsDictionary.EC_X509_SIGN_ALGORITHM_SHA1withECDSA);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#createV3Cert(cinvestav
	 * .android.pki.cryptography.key.ECPublicKey,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey,
	 * java.math.BigInteger, java.util.Date, java.util.Date,
	 * java.security.cert.X509Certificate, java.util.HashMap, java.util.List,
	 * java.lang.String)
	 */
	@Override
	public X509Certificate createV3Cert(ECPublicKey pubKey,
			ECPrivateKey caPrivKey, BigInteger serial, Date notBefore,
			Date notAfter, X509Certificate caCert,
			HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException {
		return createV3Cert(pubKey, caPrivKey, serial, notBefore, notAfter,
				caCert, certificateInformationMap, keyUsageList, certType,
				X509UtilsDictionary.EC_X509_SIGN_ALGORITHM_SHA1withECDSA);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#createV3Cert(cinvestav
	 * .android.pki.cryptography.key.ECPublicKey,
	 * cinvestav.android.pki.cryptography.key.RSAPrivateKey,
	 * java.math.BigInteger, java.util.Date, java.util.Date,
	 * java.security.cert.X509Certificate, java.util.HashMap, java.util.List,
	 * java.lang.String, java.lang.String)
	 */
	@Override
	public X509Certificate createV3Cert(ECPublicKey pubKey,
			RSAPrivateKey caPrivKey, BigInteger serial, Date notBefore,
			Date notAfter, X509Certificate caCert,
			HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType, String algorithm)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException {

		if (!validateRSASignAlgorithm(algorithm))
			throw new CryptoUtilsException(
					"Create X509 V3 Certificate error: Selected algorithm ["
							+ algorithm + "] is not supported");

		// Check if the CA certificate full fill the requirements for issuing
		// the desired certificate
		checkX509CACertificateRequirements(caCert, certType);

		X509v3CertificateBuilder v3CertGen;

		// Get x500 name Builder from the certificateInformationMap
		X500NameBuilder builder = generateX500NameBuilder(certificateInformationMap);

		// Signer Algorithm ID
		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
				.find(algorithm);

		// Digest Algorithm ID
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
				.find(sigAlgId);

		ContentSigner contentSigner;
		try {
			// Create content Signer Object from using the CAs privateKey
			contentSigner = new BcRSAContentSignerBuilder(sigAlgId, digAlgId)
					.build(caPrivKey.parseToRSAPrivateCrtKeyParameters());

			// Get the Public key contained in the certificate
			SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo
					.getInstance(pubKey.parseToJCEECPublic().getEncoded());

			//
			// create the certificate - version 3
			//
			v3CertGen = new X509v3CertificateBuilder(new X500Name(caCert
					.getSubjectX500Principal().getName()), serial, notBefore,
					notAfter, builder.build(), pubInfo);

			//
			// extensions
			//
			// AuthorityKeyIdentifier
			v3CertGen.addExtension(X509Extension.authorityKeyIdentifier, false,
					jcaX509ExtensionUtils.createAuthorityKeyIdentifier(caCert
							.getPublicKey()));

			// SubjectKeyIdentifier
			SubjectKeyIdentifier keyID = SubjectKeyIdentifier
					.getInstance(jcaX509ExtensionUtils
							.createSubjectKeyIdentifier(pubKey
									.parseToJCEECPublic()));
			v3CertGen.addExtension(X509Extension.subjectKeyIdentifier, true,
					keyID);
			// KeyUsage
			v3CertGen = addKeyUsageExtension(v3CertGen, Boolean.TRUE,
					keyUsageList);

			// Subject Alternative Name
			// TODO Agregar extension

			// Basic Constrain
			v3CertGen = addBasicConstrainExtension(v3CertGen, certType);

			// Extended Key Usage
			ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(
					KeyPurposeId.anyExtendedKeyUsage);
			v3CertGen.addExtension(X509Extension.extendedKeyUsage, false,
					extendedKeyUsage);

			// Add the custom extensions to the certificate, the extensions
			// include:
			// device id, user id, creation position, user permissions,
			// identification document
			v3CertGen = addCustomExtensions(v3CertGen,
					certificateInformationMap, caCert.getSerialNumber(),
					getExtensionSignDeviceId(caCert),
					getAuthorityKeyIdentifier(caCert));

			X509CertificateHolder certHolder = v3CertGen.build(contentSigner);

			X509Certificate cert = new JcaX509CertificateConverter()
					.setProvider(CryptoUtils.PROVIDER).getCertificate(
							certHolder);

			// cert.checkValidity(new Date());

			cert.verify(caCert.getPublicKey());

			PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) cert;

			//
			// this is actually optional - but if you want to have control
			// over setting the friendly name this is the way to do it...
			//
			if (certificateInformationMap
					.containsKey(CertificateInformationKeys.FRIENDLY_NAME)) {
				bagAttr.setBagAttribute(
						PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
						new DERBMPString(certificateInformationMap
								.get(CertificateInformationKeys.FRIENDLY_NAME)));
			}

			bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
					keyID.toASN1Primitive());

			return cert;
		} catch (OperatorCreationException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (CertificateException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (InvalidKeyException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (NoSuchProviderException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (SignatureException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (CertIOException e) {
			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (IOException e) {
			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#createV3Cert(cinvestav
	 * .android.pki.cryptography.key.ECPublicKey,
	 * cinvestav.android.pki.cryptography.key.RSAPrivateKey,
	 * java.math.BigInteger, java.util.Date, java.util.Date,
	 * java.security.cert.X509Certificate, java.util.HashMap, java.util.List,
	 * java.lang.String)
	 */
	@Override
	public X509Certificate createV3Cert(ECPublicKey pubKey,
			RSAPrivateKey caPrivKey, BigInteger serial, Date notBefore,
			Date notAfter, X509Certificate caCert,
			HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException {
		return createV3Cert(pubKey, caPrivKey, serial, notBefore, notAfter,
				caCert, certificateInformationMap, keyUsageList, certType,
				X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_SHA1withRSA);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#createV3Cert(cinvestav
	 * .android.pki.cryptography.key.RSAPublicKey,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey,
	 * java.math.BigInteger, java.util.Date, java.util.Date,
	 * java.security.cert.X509Certificate, java.util.HashMap, java.util.List,
	 * java.lang.String, java.lang.String)
	 */
	@Override
	public X509Certificate createV3Cert(RSAPublicKey pubKey,
			ECPrivateKey caPrivKey, BigInteger serial, Date notBefore,
			Date notAfter, X509Certificate caCert,
			HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType, String algorithm)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException {

		// Validate if the selected algorithm is supported
		if (!validateECSignAlgorithm(algorithm))
			throw new CryptoUtilsException(
					"Create X509 V3 Certificate error: Selected algorithm ["
							+ algorithm + "] is not supported");

		// Check if the CA certificate full fill the requirements for issuing
		// the desired certificate
		checkX509CACertificateRequirements(caCert, certType);

		X509v3CertificateBuilder v3CertGen;

		// Get x500 name Builder from the certificateInformationMap
		X500NameBuilder builder = generateX500NameBuilder(certificateInformationMap);

		ContentSigner contentSigner;
		try {
			// Create content Signer Object from using the CAs privateKey
			contentSigner = new JcaContentSignerBuilder(algorithm).setProvider(
					CryptoUtils.PROVIDER).build(
					caPrivKey.parseToJCEECPrivateKey());

			// Get the Public key contained in the certificate
			SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo
					.getInstance(pubKey.parseToJCERSAPublicKey().getEncoded());

			//
			// create the certificate - version 3
			//
			v3CertGen = new X509v3CertificateBuilder(
					X500Name.getInstance(caCert.getSubjectX500Principal()
							.getEncoded()), serial, notBefore, notAfter,
					builder.build(), pubInfo);

			//
			// extensions
			//
			// AuthorityKeyIdentifier
			v3CertGen.addExtension(X509Extension.authorityKeyIdentifier, false,
					jcaX509ExtensionUtils.createAuthorityKeyIdentifier(caCert
							.getPublicKey()));

			// SubjectKeyIdentifier
			SubjectKeyIdentifier keyID = SubjectKeyIdentifier
					.getInstance(jcaX509ExtensionUtils
							.createSubjectKeyIdentifier(pubKey
									.parseToJCERSAPublicKey()));
			v3CertGen.addExtension(X509Extension.subjectKeyIdentifier, true,
					keyID);

			// KeyUsage
			v3CertGen = addKeyUsageExtension(v3CertGen, Boolean.TRUE,
					keyUsageList);

			// Subject Alternative Name
			// TODO Agregar extension

			// Basic Constrain
			v3CertGen = addBasicConstrainExtension(v3CertGen, certType);

			// Extended Key Usage
			ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(
					KeyPurposeId.anyExtendedKeyUsage);
			v3CertGen.addExtension(X509Extension.extendedKeyUsage, false,
					extendedKeyUsage);

			// Add the custom extensions to the certificate, the extensions
			// include:
			// device id, user id, creation position, user permissions,
			// identification document
			v3CertGen = addCustomExtensions(v3CertGen,
					certificateInformationMap, caCert.getSerialNumber(),
					getExtensionSignDeviceId(caCert),
					getAuthorityKeyIdentifier(caCert));

			/*
			 * v3CertGen.addExtension( X509Extensions.AuthorityKeyIdentifier,
			 * false, new AuthorityKeyIdentifierStructure(caCert));
			 * 
			 * v3CertGen.addExtension( X509Extensions.BasicConstraints, true,
			 * new BasicConstraints(0));
			 */

			X509CertificateHolder certHolder = v3CertGen.build(contentSigner);

			X509Certificate cert = new JcaX509CertificateConverter()
					.setProvider(CryptoUtils.PROVIDER).getCertificate(
							certHolder);

			// cert.checkValidity(new Date());

			cert.verify(caCert.getPublicKey());

			PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) cert;

			//
			// this is actually optional - but if you want to have control
			// over setting the friendly name this is the way to do it...
			//
			if (certificateInformationMap
					.containsKey(CertificateInformationKeys.FRIENDLY_NAME)) {
				bagAttr.setBagAttribute(
						PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
						new DERBMPString(certificateInformationMap
								.get(CertificateInformationKeys.FRIENDLY_NAME)));
			}

			bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
					keyID.toASN1Primitive());

			return cert;
		} catch (OperatorCreationException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (CertificateException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (InvalidKeyException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (NoSuchProviderException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (SignatureException e) {

			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (CertIOException e) {
			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		} catch (IOException e) {
			throw new CryptoUtilsException("Create X509 V3 Certificate error: "
					+ e, e);
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#createV3Cert(cinvestav
	 * .android.pki.cryptography.key.RSAPublicKey,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey,
	 * java.math.BigInteger, java.util.Date, java.util.Date,
	 * java.security.cert.X509Certificate, java.util.HashMap, java.util.List,
	 * java.lang.String)
	 */
	@Override
	public X509Certificate createV3Cert(RSAPublicKey pubKey,
			ECPrivateKey caPrivKey, BigInteger serial, Date notBefore,
			Date notAfter, X509Certificate caCert,
			HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException {
		return createV3Cert(pubKey, caPrivKey, serial, notBefore, notAfter,
				caCert, certificateInformationMap, keyUsageList, certType,
				X509UtilsDictionary.EC_X509_SIGN_ALGORITHM_SHA1withECDSA);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#createV3Cert(java
	 * .security.cert.X509Certificate,
	 * cinvestav.android.pki.cryptography.key.RSAPrivateKey,
	 * java.math.BigInteger, java.util.Date, java.util.Date,
	 * java.security.cert.X509Certificate, java.util.HashMap, java.util.List,
	 * java.lang.String, java.lang.String)
	 */
	@Override
	public X509Certificate createV3Cert(X509Certificate pubKeyCert,
			RSAPrivateKey caPrivKey, BigInteger serial, Date notBefore,
			Date notAfter, X509Certificate caCert,
			HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType, String algorithm)
			throws CryptoUtilsException {
		// TODO Auto-generated method stub
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#createV3Cert(java
	 * .security.cert.X509Certificate,
	 * cinvestav.android.pki.cryptography.key.RSAPrivateKey,
	 * java.math.BigInteger, java.util.Date, java.util.Date,
	 * java.security.cert.X509Certificate, java.util.HashMap, java.util.List,
	 * java.lang.String)
	 */
	@Override
	public X509Certificate createV3Cert(X509Certificate pubKeyCert,
			RSAPrivateKey caPrivKey, BigInteger serial, Date notBefore,
			Date notAfter, X509Certificate caCert,
			HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType)
			throws CryptoUtilsException {
		// TODO Auto-generated method stub
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#createV3Cert(java
	 * .security.cert.X509Certificate,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey,
	 * java.math.BigInteger, java.util.Date, java.util.Date,
	 * java.security.cert.X509Certificate, java.util.HashMap, java.util.List,
	 * java.lang.String, java.lang.String)
	 */
	@Override
	public X509Certificate createV3Cert(X509Certificate pubKeyCert,
			ECPrivateKey caPrivKey, BigInteger serial, Date notBefore,
			Date notAfter, X509Certificate caCert,
			HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType, String algorithm)
			throws CryptoUtilsException {
		// TODO Auto-generated method stub
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#createV3Cert(java
	 * .security.cert.X509Certificate,
	 * cinvestav.android.pki.cryptography.key.ECPrivateKey,
	 * java.math.BigInteger, java.util.Date, java.util.Date,
	 * java.security.cert.X509Certificate, java.util.HashMap, java.util.List,
	 * java.lang.String)
	 */
	@Override
	public X509Certificate createV3Cert(X509Certificate pubKeyCert,
			ECPrivateKey caPrivKey, BigInteger serial, Date notBefore,
			Date notAfter, X509Certificate caCert,
			HashMap<String, String> certificateInformationMap,
			List<Integer> keyUsageList, String certType)
			throws CryptoUtilsException {
		// TODO Auto-generated method stub
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#saveCertificate(java
	 * .lang.String, java.security.cert.X509Certificate, java.lang.String)
	 */
	@Override
	public void saveCertificate(String fileName, X509Certificate certificate,
			String encoding) throws CryptoUtilsException {
		// Choose encoding type
		if (encoding.equalsIgnoreCase(CryptoUtils.ENCODING_DER)) {
			saveCertificateDER(fileName, certificate);
			return;
		}
		if (encoding.equalsIgnoreCase(CryptoUtils.ENCODING_PEM)) {
			saveCertificatePEM(fileName, certificate);
			return;
		}

		// If the encoding is different from DER or PEM throws the exception
		throw new CryptoUtilsException(
				"Save Certificate error: Unsupported Encoding [" + encoding
						+ "]");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#saveCertificate(java
	 * .lang.String, java.security.cert.X509Certificate)
	 */
	@Override
	public void saveCertificate(String fileName, X509Certificate certificate)
			throws CryptoUtilsException {
		saveCertificate(fileName, certificate, "DER");
	}

	/**
	 * Saves a certificate in PEM format
	 * 
	 * @param fileName
	 *            File in which the certificate will be saved
	 * @param certificate
	 *            Certificate to save
	 * @throws CryptoUtilsException
	 *             If writing error appears
	 */
	private void saveCertificatePEM(String fileName, X509Certificate certificate)
			throws CryptoUtilsException {

		try {
			File file = new File(fileName);
			if (!file.exists()) {
				file.createNewFile();
			}

			PEMWriter pWrt = new PEMWriter(new FileWriter(file),
					CryptoUtils.PROVIDER);

			pWrt.writeObject(certificate);

			pWrt.close();

		} catch (IOException e) {

			throw new CryptoUtilsException("Save Certificate [PEM]: " + e, e);
		}

	}

	/**
	 * Saves a certificate in DEM format
	 * 
	 * @param fileName
	 *            File in which the certificate will be saved
	 * @param certificate
	 *            Certificate to save
	 * @throws CryptoUtilsException
	 *             If writing error appears
	 */
	private void saveCertificateDER(String fileName, X509Certificate certificate)
			throws CryptoUtilsException {
		try {
			// Create file from fileName
			File file = new File(fileName);
			if (!file.exists()) {
				file.createNewFile();
			}
			// As the certificate is already encoded using DER format, we
			// must only get bytes and write them into the file
			FileOutputStream fos = new FileOutputStream(file);
			fos.write(certificate.getEncoded());
			fos.flush();
			fos.close();
		} catch (FileNotFoundException e) {

			throw new CryptoUtilsException("Save Certificate [DER]: " + e, e);

		} catch (IOException e) {

			throw new CryptoUtilsException("Save Certificate [DER]: " + e, e);

		} catch (CertificateEncodingException e) {

			throw new CryptoUtilsException("Save Certificate [DER]: " + e, e);
		}

	}

	/**
	 * Load a X509 certificate encoded using DER from file
	 * 
	 * @param fileName
	 *            Full path and name of the file containing the x509 certificate
	 * @return X509 certificate contained in the file
	 * @throws CryptoUtilsException
	 *             If the file does not contain a valid DER X509 certificate
	 */
	private X509Certificate loadCertificatePEM(String fileName)
			throws CryptoUtilsException {
		Reader reader;
		PEMReader pemReader;
		try {
			reader = new FileReader(fileName);

			pemReader = new PEMReader(reader);
			Certificate cert = (Certificate) pemReader.readObject();
			pemReader.close();
			if (cert == null) {
				throw new CryptoUtilsException(
						"Load Certificate [PEM] error: File does not contains a PEM encoded certificate");
			}
			return (X509Certificate) cert;
		} catch (FileNotFoundException e) {

			throw new CryptoUtilsException("Load Certificate: " + e, e);
		} catch (IOException e) {

			throw new CryptoUtilsException("Load Certificate: " + e, e);
		}
	}

	/**
	 * Load a X509 certificate encoded using DER from file
	 * 
	 * @param fileName
	 *            Full path and name of the file containing the x509 certificate
	 * @return X509 certificate contained in the file
	 * @throws CryptoUtilsException
	 *             If the file does not contain a valid DER X509 certificate
	 */
	private X509Certificate loadCertificateDER(String fileName)
			throws CryptoUtilsException {
		ByteArrayInputStream bIn;
		byte[] certBytes;

		File keyFile = new File(fileName);

		if (keyFile.exists()) {
			certBytes = new byte[(int) keyFile.length()];

			try {
				FileInputStream fis = new FileInputStream(keyFile);
				fis.read(certBytes);

				bIn = new ByteArrayInputStream(certBytes);

				CertificateFactory fact = CertificateFactory.getInstance(
						"X.509", CryptoUtils.PROVIDER);

				Certificate cert = fact.generateCertificate(bIn);
				fis.close();
				return (X509Certificate) cert;

			} catch (FileNotFoundException e) {

				throw new CryptoUtilsException("Load Certificate: " + e, e);
			} catch (IOException e) {

				throw new CryptoUtilsException("Load Certificate: " + e, e);
			} catch (CertificateException e) {

				throw new CryptoUtilsException("Load Certificate: " + e, e);
			} catch (NoSuchProviderException e) {

				throw new CryptoUtilsException("Load Certificate: " + e, e);
			}
		} else {
			throw new CryptoUtilsException("Load Certificate: No such file ["
					+ fileName + "]");
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#loadCertificate(java
	 * .lang.String, java.lang.String)
	 */
	@Override
	public X509Certificate loadCertificate(String fileName, String encoding)
			throws CryptoUtilsException {
		// Choose encoding type
		if (encoding.equalsIgnoreCase(CryptoUtils.ENCODING_DER)) {
			return loadCertificateDER(fileName);
		}
		if (encoding.equalsIgnoreCase(CryptoUtils.ENCODING_PEM)) {
			return loadCertificatePEM(fileName);
		}

		// If the encoding is different from DER or PEM throws the exception
		throw new CryptoUtilsException(
				"Load Certificate error: Unsupported Encoding [" + encoding
						+ "]");

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#loadCertificate(java
	 * .lang.String)
	 */
	@Override
	public X509Certificate loadCertificate(String fileName)
			throws CryptoUtilsException {
		X509Certificate c;
		try {
			c = loadCertificatePEM(fileName);
		} catch (CryptoUtilsException ex) {
			c = loadCertificateDER(fileName);
		}
		return c;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.android.pki.cryptography.utils.IX509Utils#
	 * loadCertificateChainPKCS12(java.lang.String, java.lang.String)
	 */
	@Override
	public Certificate[] loadCertificateChainPKCS12(String fileName,
			String keyStorePwd) throws CryptoUtilsException {

		// KeyStore store;

		try {
			FileInputStream fin = new FileInputStream(fileName);

			// store = KeyStore.getInstance("PKCS12",
			// AndroidCryptoUtils.PROVIDER);
			store = KeyStore.getInstance("PKCS12", CryptoUtils.PROVIDER);
			store.load(fin, keyStorePwd.toCharArray());
			fin.close();

			Enumeration<String> alias = store.aliases();

			// Iterate the store, and return the first certificate chain found
			while (alias.hasMoreElements()) {
				String keyAlias = alias.nextElement();
				if (store.isKeyEntry(keyAlias)) {
					return store.getCertificateChain(keyAlias);
				}
			}

			// If no elements were found in the key store throws and exception
			throw new CryptoUtilsException(
					"Load PKCS12 Certificate chain error: Empty key store");
		} catch (KeyStoreException e) {

			throw new CryptoUtilsException(
					"Load PKCS12 Certificate chain error: " + e, e);
		} catch (FileNotFoundException e) {

			throw new CryptoUtilsException(
					"Load PKCS12 Certificate chain error: " + e, e);
		} catch (NoSuchAlgorithmException e) {

			throw new CryptoUtilsException(
					"Load PKCS12 Certificate chain error: " + e, e);
		} catch (CertificateException e) {

			throw new CryptoUtilsException(
					"Load PKCS12 Certificate chain error: " + e, e);
		} catch (IOException e) {

			throw new CryptoUtilsException(
					"Load PKCS12 Certificate chain error: " + e, e);
		} catch (NoSuchProviderException e) {
			throw new CryptoUtilsException(
					"Load PKCS12 Certificate chain error: " + e, e);
		}
	}

	/**
	 * Encodes X509 certificate object as a base64 encoded byte array using DER
	 * 
	 * @param certificate
	 *            Certificate to be encoded
	 * @return a byte array representing the certificate base64 encoding
	 * @throws CryptoUtilsException
	 */
	public byte[] encode(X509Certificate certificate)
			throws CryptoUtilsException {
		try {
			return Base64.encode(certificate.getEncoded());
		} catch (CertificateEncodingException e) {
			throw new CryptoUtilsException(
					"Encode X509Certificate error: " + e, e);
		}
	}

	/**
	 * Decode X509 certificate object using a base63 encoded byte array
	 * 
	 * @param encodedCertificate
	 *            Base64 encoded certificate byte array
	 * @return a new X509Certificate object
	 * @throws CryptoUtilsException
	 */
	public X509Certificate decode(byte[] encodedCertificate)
			throws CryptoUtilsException {
		try {
			ByteArrayInputStream bIn = new ByteArrayInputStream(
					Base64.decode(encodedCertificate));

			Certificate cert = fact.generateCertificate(bIn);

			return (X509Certificate) cert;
		} catch (CertificateEncodingException e) {
			throw new CryptoUtilsException(
					"Decode X509Certificate error: " + e, e);
		} catch (CertificateException e) {
			throw new CryptoUtilsException(
					"Decode X509Certificate error: " + e, e);
		}
	}

	/**
	 * Encodes X509 CRL object as a base64 encoded byte array using DER
	 * 
	 * @param crl
	 *            CRL to be encoded
	 * @return a byte array representing the CRL base64 encoding
	 * @throws CryptoUtilsException
	 */
	public byte[] encode(X509CRL crl) throws CryptoUtilsException {
		try {
			return Base64.encode(crl.getEncoded());
		} catch (CRLException e) {
			throw new CryptoUtilsException("Encode X509CRL error: " + e, e);
		}
	}

	/**
	 * Decode X509 CRL object using a base64 encoded byte array
	 * 
	 * @param encodedCRL
	 *            Base64 encoded CRL byte array
	 * @return a new X509CRL object
	 * @throws CryptoUtilsException
	 */
	public X509CRL decodeCRL(byte[] encodedCertificate)
			throws CryptoUtilsException {
		try {
			ByteArrayInputStream bIn = new ByteArrayInputStream(
					Base64.decode(encodedCertificate));

			CRL crl = fact.generateCRL(bIn);

			return (X509CRL) crl;
		} catch (CRLException e) {
			throw new CryptoUtilsException("Decode X509CRL error: " + e, e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#createCRL(cinvestav
	 * .android.pki.cryptography.key.RSAKeyPair,
	 * java.security.cert.X509Certificate, java.util.List, java.util.Date,
	 * java.math.BigInteger)
	 */
	@Override
	public X509CRL createCRL(RSAKeyPair issuerKeyPair,
			X509Certificate issuerCertificate,
			List<X509CRLRevokedCertificateEntry> revokedCertificates,
			Date nextUpdate, BigInteger crlNumber) throws CryptoUtilsException,
			CryptoUtilsX509ExtensionException {
		return createCRL(issuerKeyPair, issuerCertificate, revokedCertificates,
				nextUpdate, crlNumber,
				X509UtilsDictionary.RSA_X509_SIGN_ALGORITHM_SHA1withRSA);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#createCRL(cinvestav
	 * .android.pki.cryptography.key.RSAKeyPair,
	 * java.security.cert.X509Certificate, java.util.List, java.util.Date,
	 * java.math.BigInteger, java.lang.String)
	 */
	@Override
	public X509CRL createCRL(RSAKeyPair issuerKeyPair,
			X509Certificate issuerCertificate,
			List<X509CRLRevokedCertificateEntry> revokedCertificates,
			Date nextUpdate, BigInteger crlNumber, String algorithm)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException {

		if (!validateRSASignAlgorithm(algorithm))
			throw new CryptoUtilsException(
					"Create X509 CRL error: Selected algorithm [" + algorithm
							+ "] is not supported");

		if (!(issuerCertificate instanceof X509Certificate)) {
			throw new CryptoUtilsException(
					"Create X509 CRL error: Issuer Certificate is not an X509 certificate");
		}

		if (revokedCertificates.size() <= 0) {
			throw new CryptoUtilsException(
					"Create X509 CRL error: Empty CRL cannot be created");
		}

		// Create CRL issue date
		Date now = new Date();
		// Parse the issuer certificate to X509 Certificate in order to get all
		// the necessary values
		X509Certificate issuerX509Cert = (X509Certificate) issuerCertificate;

		// Check if the CA is valid for issue CRL
		checkX509CRLCACertificateRequirements(issuerX509Cert);

		X500Name issuerName = new X500Name(issuerX509Cert
				.getSubjectX500Principal().getName());
		X509v2CRLBuilder crlGen = new X509v2CRLBuilder(issuerName, now);

		crlGen.setNextUpdate(nextUpdate);

		// Iterate the revoked certificate list and add each entry to the CRL
		for (X509CRLRevokedCertificateEntry revokedCertificate : revokedCertificates) {
			crlGen.addCRLEntry(revokedCertificate.getCertificateSerialNumber(),
					revokedCertificate.getRevocationDate(),
					revokedCertificate.getRevocationReason(),
					revokedCertificate.getInvalidityDate());
		}

		// Add Authority Key Identifier extension to the CRL as a non critical
		// extension
		try {
			crlGen.addExtension(X509Extension.authorityKeyIdentifier, false,
					jcaX509ExtensionUtils
							.createAuthorityKeyIdentifier(issuerKeyPair
									.getPublicKey().parseToJCERSAPublicKey()));

			// Add CRL number extension to the CRL as a non critical extension
			crlGen.addExtension(X509Extension.cRLNumber, false, new CRLNumber(
					crlNumber));

			// Sign the CRL with the selected algorithm
			X509CRLHolder crlHolder = crlGen
					.build(new JcaContentSignerBuilder(algorithm).setProvider(
							CryptoUtils.PROVIDER).build(
							issuerKeyPair.getPrivateKey()
									.parseToJCERSAPrivateCrtKey()));

			X509CRL crl = new JcaX509CRLConverter().setProvider(
					CryptoUtils.PROVIDER).getCRL(crlHolder);
			return crl;
		} catch (CertIOException e) {

			throw new CryptoUtilsException("Create X509 CRL error: " + e, e);
		} catch (OperatorCreationException e) {
			throw new CryptoUtilsException("Create X509 CRL error: " + e, e);
		} catch (CRLException e) {
			throw new CryptoUtilsException("Create X509 CRL error: " + e, e);
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#createCRL(cinvestav
	 * .android.pki.cryptography.key.ECKeyPair,
	 * java.security.cert.X509Certificate, java.util.List, java.util.Date,
	 * java.math.BigInteger)
	 */
	@Override
	public X509CRL createCRL(ECKeyPair issuerKeyPair,
			X509Certificate issuerCertificate,
			List<X509CRLRevokedCertificateEntry> revokedCertificates,
			Date nextUpdate, BigInteger crlNumber) throws CryptoUtilsException,
			CryptoUtilsX509ExtensionException {
		return createCRL(issuerKeyPair, issuerCertificate, revokedCertificates,
				nextUpdate, crlNumber,
				X509UtilsDictionary.EC_X509_SIGN_ALGORITHM_SHA1withECDSA);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#createCRL(cinvestav
	 * .android.pki.cryptography.key.ECKeyPair,
	 * java.security.cert.X509Certificate, java.util.List, java.util.Date,
	 * java.math.BigInteger, java.lang.String)
	 */
	@Override
	public X509CRL createCRL(ECKeyPair issuerKeyPair,
			X509Certificate issuerCertificate,
			List<X509CRLRevokedCertificateEntry> revokedCertificates,
			Date nextUpdate, BigInteger crlNumber, String algorithm)
			throws CryptoUtilsException, CryptoUtilsX509ExtensionException {
		if (!validateECSignAlgorithm(algorithm))
			throw new CryptoUtilsException(
					"Create X509 CRL error: Selected algorithm [" + algorithm
							+ "] is not supported");

		if (!(issuerCertificate instanceof X509Certificate)) {
			throw new CryptoUtilsException(
					"Create X509 CRL error: Issuer Certificate is not an X509 certificate");
		}

		if (revokedCertificates.size() <= 0) {
			throw new CryptoUtilsException(
					"Create X509 CRL error: Empty CRL cannot be created");
		}

		// Create CRL issue date
		Date now = new Date();
		// Parse the issuer certificate to X509 Certificate in order to get all
		// the necessary values
		X509Certificate issuerX509Cert = (X509Certificate) issuerCertificate;

		// Check if the CA is valid for issue CRL
		checkX509CRLCACertificateRequirements(issuerX509Cert);
		X500Name issuerName = new X500Name(issuerX509Cert
				.getSubjectX500Principal().getName());
		X509v2CRLBuilder crlGen = new X509v2CRLBuilder(issuerName, now);

		crlGen.setNextUpdate(nextUpdate);

		// Iterate the revoked certificate list and add each entry to the CRL
		for (X509CRLRevokedCertificateEntry revokedCertificate : revokedCertificates) {
			crlGen.addCRLEntry(revokedCertificate.getCertificateSerialNumber(),
					revokedCertificate.getRevocationDate(),
					revokedCertificate.getRevocationReason(),
					revokedCertificate.getInvalidityDate());
		}

		// Add Authority Key Identifier extension to the CRL as a non critical
		// extension
		try {
			crlGen.addExtension(X509Extension.authorityKeyIdentifier, false,
					jcaX509ExtensionUtils
							.createAuthorityKeyIdentifier(issuerKeyPair
									.getPublicKey().parseToJCEECPublic()));

			// Add CRL number extension to the CRL as a non critical extension
			crlGen.addExtension(X509Extension.cRLNumber, false, new CRLNumber(
					crlNumber));

			// Sign the CRL with the selected algorithm
			X509CRLHolder crlHolder = crlGen.build(new JcaContentSignerBuilder(
					algorithm).setProvider(CryptoUtils.PROVIDER).build(
					issuerKeyPair.getPrivateKey().parseToJCEECPrivateKey()));

			X509CRL crl = new JcaX509CRLConverter().setProvider(
					CryptoUtils.PROVIDER).getCRL(crlHolder);
			return crl;
		} catch (CertIOException e) {

			throw new CryptoUtilsException("Create X509 CRL error: " + e, e);
		} catch (OperatorCreationException e) {
			throw new CryptoUtilsException("Create X509 CRL error: " + e, e);
		} catch (CRLException e) {
			throw new CryptoUtilsException("Create X509 CRL error: " + e, e);
		}

	}

	/**
	 * Saves a CRL in PEM format
	 * 
	 * @param fileName
	 *            File in which the CRL will be saved
	 * @param crl
	 *            Certificate Revocation List (CRL) to save
	 * @throws CryptoUtilsException
	 *             If writing error appears
	 */
	private void saveCRLPEM(String fileName, X509CRL crl)
			throws CryptoUtilsException {

		try {
			File file = new File(fileName);
			if (!file.exists()) {
				file.createNewFile();
			}

			PEMWriter pWrt = new PEMWriter(new FileWriter(file),
					CryptoUtils.PROVIDER);

			pWrt.writeObject(crl);

			pWrt.close();

		} catch (IOException e) {

			throw new CryptoUtilsException("Save CRL [PEM]: " + e, e);
		}

	}

	/**
	 * Saves a CRL in DER format
	 * 
	 * @param fileName
	 *            File in which the certificate will be saved
	 * @param crl
	 *            Certificate Revocation List (CRL) to save
	 * @throws CryptoUtilsException
	 *             If writing error appears
	 */
	private void saveCRLDER(String fileName, X509CRL crl)
			throws CryptoUtilsException {
		try {
			// Create file from fileName
			File file = new File(fileName);
			if (!file.exists()) {
				file.createNewFile();
			}
			// As the certificate is already encoded using DER format, we
			// must only get bytes and write them into the file
			FileOutputStream fos = new FileOutputStream(file);
			fos.write(crl.getEncoded());
			fos.flush();
			fos.close();
		} catch (FileNotFoundException e) {
			throw new CryptoUtilsException("Save CRL [DER]: " + e, e);

		} catch (IOException e) {
			throw new CryptoUtilsException("Save CRL [DER]: " + e, e);

		} catch (CRLException e) {
			throw new CryptoUtilsException("Save CRL [DER]: " + e, e);
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.android.pki.cryptography.utils.IX509Utils#saveCRL(java
	 * .lang.String, java.security.cert.X509CRL)
	 */
	@Override
	public void saveCRL(String fileName, X509CRL crl)
			throws CryptoUtilsException {
		saveCRL(fileName, crl, "DER");

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.android.pki.cryptography.utils.IX509Utils#saveCRL(java
	 * .lang.String, java.security.cert.X509CRL, java.lang.String)
	 */
	@Override
	public void saveCRL(String fileName, X509CRL crl, String encoding)
			throws CryptoUtilsException {
		// Choose encoding type
		if (encoding.equalsIgnoreCase(CryptoUtils.ENCODING_DER)) {
			saveCRLDER(fileName, crl);
			return;
		}
		if (encoding.equalsIgnoreCase(CryptoUtils.ENCODING_PEM)) {
			saveCRLPEM(fileName, crl);
			return;
		}

		// If the encoding is different from DER or PEM throws the exception
		throw new CryptoUtilsException("Save CRL error: Unsupported Encoding ["
				+ encoding + "]");

	}

	/**
	 * Load a X509 CRL encoded using DER from file
	 * 
	 * @param fileName
	 *            Full path and name of the file containing the x509 CRL
	 * @return X509 CRL contained in the file
	 * @throws CryptoUtilsException
	 *             If the file does not contain a valid DER X509 CRL
	 */
	private X509CRL loadCRLPEM(String fileName) throws CryptoUtilsException {
		Reader reader;
		PEMReader pemReader;
		try {
			reader = new FileReader(fileName);

			pemReader = new PEMReader(reader);
			X509CRL cert = (X509CRL) pemReader.readObject();
			pemReader.close();
			if (cert == null) {
				throw new CryptoUtilsException(
						"Load CRL [PEM] error: File does not contains a PEM encoded CRL");
			}
			return cert;
		} catch (FileNotFoundException e) {
			throw new CryptoUtilsException("Load CRL: " + e, e);
		} catch (IOException e) {
			throw new CryptoUtilsException("Load CRL: " + e, e);
		}
	}

	/**
	 * Load a X509 CRL encoded using DER from file
	 * 
	 * @param fileName
	 *            Full path and name of the file containing the x509 CRL
	 * @return X509 CRL contained in the file
	 * @throws CryptoUtilsException
	 *             If the file does not contain a valid DER X509 CRL
	 */
	private X509CRL loadCRLDER(String fileName) throws CryptoUtilsException {
		ByteArrayInputStream bIn;
		byte[] certBytes;

		File keyFile = new File(fileName);

		if (keyFile.exists()) {
			certBytes = new byte[(int) keyFile.length()];

			try {
				FileInputStream fis = new FileInputStream(keyFile);
				fis.read(certBytes);
				fis.close();

				bIn = new ByteArrayInputStream(certBytes);

				CertificateFactory fact = CertificateFactory.getInstance(
						"X.509", CryptoUtils.PROVIDER);

				X509CRL crl = (X509CRL) fact.generateCRL(bIn);

				return crl;

			} catch (FileNotFoundException e) {

				throw new CryptoUtilsException("Load CRL: " + e, e);
			} catch (IOException e) {

				throw new CryptoUtilsException("Load CRL: " + e, e);
			} catch (CRLException e) {

				throw new CryptoUtilsException("Load CRL: " + e, e);
			} catch (NoSuchProviderException e) {

				throw new CryptoUtilsException("Load CRL: " + e, e);
			} catch (CertificateException e) {
				throw new CryptoUtilsException("Load CRL: " + e, e);
			}
		} else {
			throw new CryptoUtilsException("Load CRL: No such file ["
					+ fileName + "]");
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.android.pki.cryptography.utils.IX509Utils#loadCRL(java
	 * .lang.String, java.lang.String)
	 */
	@Override
	public X509CRL loadCRL(String fileName, String encoding)
			throws CryptoUtilsException {
		// Choose encoding type
		if (encoding.equalsIgnoreCase(CryptoUtils.ENCODING_DER)) {
			return loadCRLDER(fileName);
		}
		if (encoding.equalsIgnoreCase(CryptoUtils.ENCODING_PEM)) {
			return loadCRLPEM(fileName);
		}

		// If the encoding is different from DER or PEM throws the exception
		throw new CryptoUtilsException("Load CRL error: Unsupported Encoding ["
				+ encoding + "]");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.android.pki.cryptography.utils.IX509Utils#loadCRL(java
	 * .lang.String)
	 */
	@Override
	public X509CRL loadCRL(String fileName) throws CryptoUtilsException {
		X509CRL crl;
		try {
			crl = loadCRLPEM(fileName);
		} catch (CryptoUtilsException ex) {
			crl = loadCRLDER(fileName);
		}
		return crl;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#verifyCertificate
	 * (java.security.cert.X509Certificate, java.security.cert.X509Certificate,
	 * java.security.cert.X509CRL)
	 */
	public Integer verifyCertificate(X509Certificate cert,
			X509Certificate cacert, X509CRL crl) throws CryptoUtilsException {

		// Check if the certificate is in the crl
		if (crl.isRevoked(cert)) {
			return X509UtilsDictionary.X509_CERTIFICATE_STATUS_REVOKED;
		}
		try {
			// Check the validity of the certificate in terms of date
			cert.checkValidity(new Date());
		} catch (CertificateExpiredException e) {
			return X509UtilsDictionary.X509_CERTIFICATE_STATUS_EXPIRED;
		} catch (CertificateNotYetValidException e) {
			return X509UtilsDictionary.X509_CERTIFICATE_STATUS_NOT_YET_VALID;
		}
		try {
			// Verifies the validity of the certificate signature
			cert.verify(cacert.getPublicKey());
			return X509UtilsDictionary.X509_CERTIFICATE_STATUS_VALID;
		} catch (InvalidKeyException e) {
			return X509UtilsDictionary.X509_CERTIFICATE_STATUS_INVALID;
		} catch (SignatureException e) {
			return X509UtilsDictionary.X509_CERTIFICATE_STATUS_INVALID;
		} catch (CertificateException e) {
			throw new CryptoUtilsException("Verify Certificate: " + e, e);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoUtilsException("Verify Certificate: " + e, e);
		} catch (NoSuchProviderException e) {
			throw new CryptoUtilsException("Verify Certificate: " + e, e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#verifyCRL(java.security
	 * .cert.X509CRL, java.security.cert.X509Certificate)
	 */
	@Override
	public Integer verifyCRL(X509CRL crl, X509Certificate cacert)
			throws CryptoUtilsException {
		if (crl.getNextUpdate().before(new Date())) {
			return X509UtilsDictionary.X509_CRL_STATUS_OLD;
		}
		try {
			crl.verify(cacert.getPublicKey());
			return X509UtilsDictionary.X509_CRL_STATUS_VALID;
		} catch (InvalidKeyException e) {
			return X509UtilsDictionary.X509_CRL_STATUS_INVALID;
		} catch (CRLException e) {
			throw new CryptoUtilsException("Verify Certificate: " + e, e);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoUtilsException("Verify Certificate: " + e, e);
		} catch (NoSuchProviderException e) {
			throw new CryptoUtilsException("Verify Certificate: " + e, e);
		} catch (SignatureException e) {
			throw new CryptoUtilsException("Verify Certificate: " + e, e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#getAuthorityKeyIdentifier
	 * (java.security.cert.X509Certificate)
	 */
	@Override
	public byte[] getAuthorityKeyIdentifier(X509Certificate cert) {

		byte[] extvalue = cert
				.getExtensionValue(X509Extension.authorityKeyIdentifier.getId());
		if (extvalue == null) {
			return null;
		}
		DEROctetString oct;
		try {
			ASN1InputStream input = new ASN1InputStream(
					new ByteArrayInputStream(extvalue));
			oct = (DEROctetString) input.readObject();
			input.close();
			input = new ASN1InputStream(new ByteArrayInputStream(
					oct.getOctets()));
			AuthorityKeyIdentifier keyId = AuthorityKeyIdentifier
					.getInstance((ASN1Sequence) input.readObject());
			input.close();
			return keyId.getKeyIdentifier();
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#getSubjectKeyIdentifier
	 * (java.security.cert.X509Certificate)
	 */
	@Override
	public byte[] getSubjectKeyIdentifier(X509Certificate cert) {
		byte[] ext = cert.getExtensionValue(X509Extension.subjectKeyIdentifier
				.getId());

		if (ext != null) {
			return ASN1OctetString.getInstance(
					ASN1OctetString.getInstance(ext).getOctets()).getOctets();
		} else {
			return null;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#getKeyUsageList(java
	 * .security.cert.X509Certificate)
	 */
	@Override
	public List<Integer> getKeyUsageList(X509Certificate cert) {
		boolean[] keyUsage = cert.getKeyUsage();
		// Check if the extension is present in the certificate
		if (keyUsage == null)
			return null;

		List<Integer> res = new ArrayList<Integer>(8);
		for (int i = 0; i < keyUsage.length; i++) {
			if (keyUsage[i])
				res.add(i);
		}

		return res;

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.android.pki.cryptography.utils.IX509Utils#
	 * getExtensionCertificateType(java.security.cert.X509Certificate,
	 * java.lang.String)
	 */
	@Override
	public String getExtensionCertificateType(X509Certificate cert,
			String language) {
		int pathLength = cert.getBasicConstraints();
		if (language.equalsIgnoreCase("ES")) {
			if (pathLength == -1) {
				return "Certificado de usuario final";
			}

			if (pathLength == 0) {
				return "Certificado de usuario final";
			}

			if (pathLength > 0 && pathLength < 100) {
				return "Certificado de CA final";
			}

			if (pathLength >= 100 && pathLength < 1000) {
				return "Certificado de CA intermedia";
			}

			if (pathLength >= 1000) {
				return "Certificado de CA raíz";
			}

			return "Certificado de CA raíz";
		}

		if (pathLength == -1) {
			return "End owner certificate";
		}

		if (pathLength == 0) {
			return "End owner certificate";
		}

		if (pathLength > 0 && pathLength < 100) {
			return "Final CA certificate";
		}

		if (pathLength >= 100 && pathLength < 1000) {
			return "Intermediate CA certificate";
		}

		if (pathLength >= 1000) {
			return "Root CA certificate";
		}

		return "Root CA certificate";
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.android.pki.cryptography.utils.IX509Utils#
	 * getCertificateInformationMap(java.security.cert.X509Certificate)
	 */
	@Override
	public HashMap<String, String> getCertificateInformationMap(
			X509Certificate cert) {
		HashMap<String, String> res = new HashMap<String, String>();

		// Finally parse the subject principal information to complete the
		// certificate information map
		X500Name x500name;
		try {
			// Get the subject X500Name object
			x500name = new JcaX509CertificateHolder(cert).getSubject();

			// Get the attribute types array for the subject name
			ASN1ObjectIdentifier[] attsTypes = x500name.getAttributeTypes();
			// Go over the attribute array, and get the RN to add it to he
			// certificate information map with the corresponding key
			for (int i = 0; i < attsTypes.length; i++) {
				RDN rn = x500name.getRDNs(attsTypes[i])[0];
				res.put(CertificateInformationKeys.DEFAULT_NAME_LOOK_UP
						.get(attsTypes[i]), rn.getFirst().getValue().toString());
			}

		} catch (CertificateEncodingException e) {

		}

		return res;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#getExtensionDeviceId
	 * (java.security.cert.X509Certificate)
	 */
	@Override
	public String getExtensionDeviceId(X509Certificate cert) {
		// get device ID extension from certificate, and add it to the map
		byte[] asn1Octet;
		byte[] aux = cert
				.getExtensionValue(CertificateInformationKeys.DEVICE_ID_OID
						.getId());

		if (aux != null) {

			asn1Octet = ASN1OctetString.getInstance(
					ASN1OctetString.getInstance(aux).getOctets()).getOctets();
			return new String(asn1Octet);
		}
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#getExtensionUserId
	 * (java.security.cert.X509Certificate)
	 */
	@Override
	public String getExtensionUserId(X509Certificate cert) {
		// get user id extension from certificate, and add it to the map
		byte[] asn1Octet;
		byte[] aux = cert
				.getExtensionValue(CertificateInformationKeys.USER_ID_OID
						.getId());
		if (aux != null) {
			asn1Octet = ASN1OctetString.getInstance(
					ASN1OctetString.getInstance(aux).getOctets()).getOctets();
			return new String(asn1Octet);
		}
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.android.pki.cryptography.utils.IX509Utils#
	 * getExtensionUserPermissionId(java.security.cert.X509Certificate)
	 */
	@Override
	public String getExtensionUserPermissionId(X509Certificate cert) {
		// get user permission id extension from certificate, and add it to the
		// map
		byte[] asn1Octet;
		byte[] aux = cert
				.getExtensionValue(CertificateInformationKeys.USER_PERMISSION_OID
						.getId());
		if (aux != null) {
			asn1Octet = ASN1OctetString.getInstance(
					ASN1OctetString.getInstance(aux).getOctets()).getOctets();
			return new String(asn1Octet);
		}
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.android.pki.cryptography.utils.IX509Utils#
	 * getExtensionIdentificationDocument(java.security.cert.X509Certificate)
	 */
	@Override
	public String getExtensionIdentificationDocument(X509Certificate cert) {
		// get identification document extension from certificate, and add it to
		// the map
		byte[] asn1Octet;
		byte[] aux = cert
				.getExtensionValue(CertificateInformationKeys.IDENTIFICATION_DOCUMENT_OID
						.getId());
		if (aux != null) {
			asn1Octet = ASN1OctetString.getInstance(
					ASN1OctetString.getInstance(aux).getOctets()).getOctets();
			return new String(asn1Octet);
		}
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.android.pki.cryptography.utils.IX509Utils#
	 * getExtensionCreationPositionX(java.security.cert.X509Certificate)
	 */
	@Override
	public String getExtensionCreationPositionLatitude(X509Certificate cert) {
		// get creation position extension from certificate, and add it to the
		// map
		byte[] asn1Octet;
		byte[] aux = cert
				.getExtensionValue(CertificateInformationKeys.CREATION_POSITION_LATITUDE_OID
						.getId());
		if (aux != null) {
			asn1Octet = ASN1OctetString.getInstance(
					ASN1OctetString.getInstance(aux).getOctets()).getOctets();
			return new String(asn1Octet);
		}
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.android.pki.cryptography.utils.IX509Utils#
	 * getExtensionCreationPositionY(java.security.cert.X509Certificate)
	 */
	@Override
	public String getExtensionCreationPositionLongitude(X509Certificate cert) {
		// get creation position extension from certificate, and add it to the
		// map
		byte[] asn1Octet;
		byte[] aux = cert
				.getExtensionValue(CertificateInformationKeys.CREATION_POSITION_LONGITUDE_OID
						.getId());
		if (aux != null) {
			asn1Octet = ASN1OctetString.getInstance(
					ASN1OctetString.getInstance(aux).getOctets()).getOctets();
			return new String(asn1Octet);
		}
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * cinvestav.android.pki.cryptography.utils.IX509Utils#getExtensionSignDeviceId
	 * (java.security.cert.X509Certificate)
	 */
	@Override
	public String getExtensionSignDeviceId(X509Certificate cert) {
		// get device ID extension from certificate, and add it to the map
		byte[] asn1Octet;
		byte[] aux = cert
				.getExtensionValue(CertificateInformationKeys.SIGN_DEVICE_ID_OID
						.getId());

		if (aux != null) {

			asn1Octet = ASN1OctetString.getInstance(
					ASN1OctetString.getInstance(aux).getOctets()).getOctets();
			return new String(asn1Octet);
		}
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.android.pki.cryptography.utils.IX509Utils#
	 * getExtensionCACertificateSerialNumber(java.security.cert.X509Certificate)
	 */
	@Override
	public String getExtensionCACertificateSerialNumber(X509Certificate cert) {
		// get device ID extension from certificate, and return it
		byte[] asn1Octet;
		byte[] aux = cert
				.getExtensionValue(CertificateInformationKeys.CA_CERTIFICATE_SERIAL_NUMBER_OID
						.getId());

		if (aux != null) {

			asn1Octet = ASN1OctetString.getInstance(
					ASN1OctetString.getInstance(aux).getOctets()).getOctets();
			return new String(asn1Octet);
		}
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.android.pki.cryptography.utils.IX509Utils#
	 * getExtensionCACertificateSignDeviceId(java.security.cert.X509Certificate)
	 */
	@Override
	public String getExtensionCACertificateSignDeviceId(X509Certificate cert) {
		// get device ID extension from certificate, and return it
		byte[] asn1Octet;
		byte[] aux = cert
				.getExtensionValue(CertificateInformationKeys.CA_CERTIFICATE_SIGN_DEVICE_ID_OID
						.getId());

		if (aux != null) {

			asn1Octet = ASN1OctetString.getInstance(
					ASN1OctetString.getInstance(aux).getOctets()).getOctets();
			return new String(asn1Octet);
		}
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see cinvestav.android.pki.cryptography.utils.IX509Utils#
	 * getExtensionCACertificateAuthorityKeyId
	 * (java.security.cert.X509Certificate)
	 */
	@Override
	public String getExtensionCACertificateAuthorityKeyId(X509Certificate cert) {
		// get device ID extension from certificate, and return it
		byte[] asn1Octet;
		byte[] aux = cert
				.getExtensionValue(CertificateInformationKeys.CA_CERTIFICATE_SIGN_AUTHORITY_KEY_ID_OID
						.getId());

		if (aux != null) {

			asn1Octet = ASN1OctetString.getInstance(
					ASN1OctetString.getInstance(aux).getOctets()).getOctets();
			return new String(asn1Octet);
		}
		return null;
	}
}
