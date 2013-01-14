/**
 *  Created on  : 19/06/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	This class contains all the elements required by a x509 CRL in order to add
 * an entry for a revoked certificate, includes, the certificate to be revoked,
 * the reason, date and some other extensions
 */
package cinvestav.android.pki.cryptography.cert;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import cinvestav.android.pki.cryptography.exception.CryptoUtilsException;

/**
 * This class contains all the elements required by a x509 CRL in order to add
 * an entry for a revoked certificate, includes, the certificate to be revoked,
 * the reason, date and some other extensions
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 19/06/2012
 * @version 1.0
 */
public class X509CRLRevokedCertificateEntry {

	/**
	 * Serial number of revoked certificate.
	 */
	private BigInteger certificateSerialNumber;
	/**
	 * Date of certificate revocation.
	 */
	private Date revocationDate;

	/**
	 * The date on which the private key for the certificate became compromised
	 * or the certificate became invalid.
	 */
	private Date invalidityDate;

	/**
	 * the reason code, as indicated in X509RevokedCertificate, i.e
	 * X509RevokedCertificateReason.KEY_COMPROMISE or 0 if not to be used.
	 */
	private Integer revocationReason;

	/**
	 * Default constructor, initialize all the attributes of this class with
	 * default values
	 */
	public X509CRLRevokedCertificateEntry() {
		this.certificateSerialNumber = BigInteger.ZERO;
		this.invalidityDate = new Date();
		this.revocationDate = new Date();
		this.revocationReason = X509RevokedCertificateReason.UNSPECIFIED;
	}

	/**
	 * Constructor that receives the certificate to be revoked
	 * 
	 * @param certificate
	 *            Certificate to be revoked
	 * @param revocationDate
	 *            Date of certificate revocation.
	 * @param invalidityDate
	 *            The date on which the private key for the certificate became
	 *            compromised or the certificate became invalid.
	 * @param revocationReason
	 *            the reason code, as indicated in X509RevokedCertificate, i.e
	 *            X509RevokedCertificateReason.KEY_COMPROMISE or 0 if not to be
	 *            used.
	 * @throws CryptoUtilsException
	 *             if the certificate is not a valid X509 certificate
	 */
	public X509CRLRevokedCertificateEntry(Certificate certificate,
			Date revocationDate, Date invalidityDate, Integer revocationReason)
			throws CryptoUtilsException {
		super();
		if (certificate instanceof X509Certificate) {
			this.certificateSerialNumber = ((X509Certificate) certificate)
					.getSerialNumber();
			this.revocationDate = revocationDate;
			this.invalidityDate = invalidityDate;
			this.revocationReason = revocationReason;
		} else {
			throw new CryptoUtilsException(
					"Create new X509CLRRevokedCertificateEntry object fail: certificate is not an X509 certificate");
		}
	}

	/**
	 * Constructor that receives the certificate to be revoked
	 * 
	 * @param certificate
	 *            Certificate to be revoked
	 * @param revocationDate
	 *            Date of certificate revocation.
	 * @param invalidityDate
	 *            The date on which the private key for the certificate became
	 *            compromised or the certificate became invalid.
	 * @throws CryptoUtilsException
	 *             if the certificate is not a valid X509 certificate
	 */
	public X509CRLRevokedCertificateEntry(Certificate certificate,
			Date revocationDate, Date invalidityDate)
			throws CryptoUtilsException {
		super();
		if (certificate instanceof X509Certificate) {
			this.certificateSerialNumber = ((X509Certificate) certificate)
					.getSerialNumber();
			this.revocationDate = revocationDate;
			this.invalidityDate = invalidityDate;
			this.revocationReason = X509RevokedCertificateReason.UNSPECIFIED;
		} else {
			throw new CryptoUtilsException(
					"Create new X509CLRRevokedCertificateEntry object fail: certificate is not an X509 certificate");
		}
	}

	/**
	 * Constructor that receives the certificate to be revoked
	 * 
	 * @param certificate
	 *            Certificate to be revoked
	 * @param revocationDate
	 *            Date of certificate revocation.
	 * @param revocationReason
	 *            the reason code, as indicated in X509RevokedCertificate, i.e
	 *            X509RevokedCertificateReason.KEY_COMPROMISE or 0 if not to be
	 *            used.
	 * @throws CryptoUtilsException
	 *             if the certificate is not a valid X509 certificate
	 */
	public X509CRLRevokedCertificateEntry(Certificate certificate,
			Date revocationDate, Integer revocationReason)
			throws CryptoUtilsException {
		super();
		if (certificate instanceof X509Certificate) {
			this.certificateSerialNumber = ((X509Certificate) certificate)
					.getSerialNumber();
			this.revocationDate = revocationDate;
			this.invalidityDate = revocationDate;
			this.revocationReason = revocationReason;
		} else {
			throw new CryptoUtilsException(
					"Create new X509CLRRevokedCertificateEntry object fail: certificate is not an X509 certificate");
		}
	}

	/**
	 * Constructor that receives the certificate to be revoked
	 * 
	 * @param certificate
	 *            Certificate to be revoked
	 * @param revocationDate
	 *            Date of certificate revocation.
	 * @throws CryptoUtilsException
	 *             if the certificate is not a valid X509 certificate
	 */
	public X509CRLRevokedCertificateEntry(Certificate certificate,
			Date revocationDate) throws CryptoUtilsException {
		super();
		if (certificate instanceof X509Certificate) {
			this.certificateSerialNumber = ((X509Certificate) certificate)
					.getSerialNumber();
			this.revocationDate = revocationDate;
			this.invalidityDate = revocationDate;
			this.revocationReason = X509RevokedCertificateReason.UNSPECIFIED;
		} else {
			throw new CryptoUtilsException(
					"Create new X509CLRRevokedCertificateEntry object fail: certificate is not an X509 certificate");
		}

	}

	/**
	 * Constructor with parameters
	 * 
	 * @param certificateSerialNumber
	 *            Serial number of the certificate to be revoked
	 * @param revocationDate
	 *            Date of certificate revocation.
	 * @param invalidityDate
	 *            The date on which the private key for the certificate became
	 *            compromised or the certificate became invalid.
	 * @param revocationReason
	 *            the reason code, as indicated in X509RevokedCertificate, i.e
	 *            X509RevokedCertificateReason.KEY_COMPROMISE or 0 if not to be
	 *            used.
	 */
	public X509CRLRevokedCertificateEntry(BigInteger certificateSerialNumber,
			Date revocationDate, Date invalidityDate, Integer revocationReason) {
		super();
		this.certificateSerialNumber = certificateSerialNumber;
		this.revocationDate = revocationDate;
		this.invalidityDate = invalidityDate;
		this.revocationReason = revocationReason;
	}

	/**
	 * Constructor with parameters
	 * 
	 * @param certificateSerialNumber
	 *            Serial number of the certificate to be revoked
	 * @param revocationDate
	 *            Date of certificate revocation.
	 * @param invalidityDate
	 *            The date on which the private key for the certificate became
	 *            compromised or the certificate became invalid.
	 */
	public X509CRLRevokedCertificateEntry(BigInteger certificateSerialNumber,
			Date revocationDate, Date invalidityDate) {
		super();
		this.certificateSerialNumber = certificateSerialNumber;
		this.revocationDate = revocationDate;
		this.invalidityDate = invalidityDate;
		this.revocationReason = X509RevokedCertificateReason.UNSPECIFIED;
	}

	/**
	 * Constructor with parameters
	 * 
	 * @param certificateSerialNumber
	 *            Serial number of the certificate to be revoked
	 * @param revocationDate
	 *            Date of certificate revocation.
	 * @param revocationReason
	 *            the reason code, as indicated in X509RevokedCertificate, i.e
	 *            X509RevokedCertificateReason.KEY_COMPROMISE or 0 if not to be
	 *            used.
	 */
	public X509CRLRevokedCertificateEntry(BigInteger certificateSerialNumber,
			Date revocationDate, Integer revocationReason) {
		super();
		this.certificateSerialNumber = certificateSerialNumber;
		this.revocationDate = revocationDate;
		this.invalidityDate = revocationDate;
		this.revocationReason = revocationReason;
	}

	/**
	 * Constructor with parameters
	 * 
	 * @param certificateSerialNumber
	 *            Serial number of the certificate to be revoked
	 * @param revocationDate
	 *            Date of certificate revocation.
	 */
	public X509CRLRevokedCertificateEntry(BigInteger certificateSerialNumber,
			Date revocationDate) {
		super();
		this.certificateSerialNumber = certificateSerialNumber;
		this.revocationDate = revocationDate;
		this.invalidityDate = revocationDate;
		this.revocationReason = X509RevokedCertificateReason.UNSPECIFIED;
		;
	}

	/**
	 * @return the certificateSerialNumber
	 */
	public BigInteger getCertificateSerialNumber() {
		return certificateSerialNumber;
	}

	/**
	 * @param certificateSerialNumber
	 *            the certificateSerialNumber to set
	 */
	public void setCertificateSerialNumber(BigInteger certificateSerialNumber) {
		this.certificateSerialNumber = certificateSerialNumber;
	}

	/**
	 * @return the revocationDate
	 */
	public Date getRevocationDate() {
		return revocationDate;
	}

	/**
	 * @param revocationDate
	 *            the revocationDate to set
	 */
	public void setRevocationDate(Date revocationDate) {
		this.revocationDate = revocationDate;
	}

	/**
	 * @return the invalidityDate
	 */
	public Date getInvalidityDate() {
		return invalidityDate;
	}

	/**
	 * @param invalidityDate
	 *            the invalidityDate to set
	 */
	public void setInvalidityDate(Date invalidityDate) {
		this.invalidityDate = invalidityDate;
	}

	/**
	 * @return the revocationReason
	 */
	public Integer getRevocationReason() {
		return revocationReason;
	}

	/**
	 * @param revocationReason
	 *            the revocationReason to set
	 */
	public void setRevocationReason(Integer revocationReason) {
		this.revocationReason = revocationReason;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "X509CLRRevokedCertificateEntry [certificateSerialNumber="
				+ certificateSerialNumber + ", revocationDate="
				+ revocationDate + ", invalidityDate=" + invalidityDate
				+ ", revocationReason=" + revocationReason + "]";
	}
}
