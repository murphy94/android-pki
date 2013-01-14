/**
 *  Created on  : 17/07/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Data Access Object (DAO) that represents the data base table Certificate
 */
package cinvestav.android.pki.db.dao;

import java.util.Date;

import cinvestav.android.pki.cryptography.utils.X509UtilsDictionary;

/**
 * Data Access Object (DAO) that represents the data base table Certificate
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 17/07/2012
 * @version 1.0
 */
public class CertificateDAO {

	/**
	 * Id of the certificate in the database
	 */
	private Integer id;
	/**
	 * Certificate serial number
	 */
	private Integer serialNumber;
	/**
	 * Base64 String which represents the X509 certificate it self
	 */
	private String certificateStr;

	/**
	 * Certificate used for sign this one
	 */
	private CertificateDAO caCertificate;

	/**
	 * Owner of this certificate
	 */
	private SubjectDAO owner;
	/**
	 * Status of the certificate in the DB, the possible values are at
	 * {@link X509UtilsDictionary} ej.
	 * X509UtilsDictionary.X509_CERTIFICATE_STATUS_VALID
	 */
	private Integer status;
	/**
	 * Date of the last Status update in the DB of this certificate
	 */
	private Date lastStatusUpdateDate;

	/**
	 * Id of the device in which this certificate was signed
	 */
	private String signDeviceId;

	/**
	 * Subject Key Id extension value saved in the certificate in base64
	 */
	private String subjectKeyId;

	/**
	 * Default constructor
	 */
	public CertificateDAO() {
		id = 0;
		serialNumber = 0;
		certificateStr = "";
		owner = new SubjectDAO();
		status = X509UtilsDictionary.X509_CERTIFICATE_STATUS_VALID;
		lastStatusUpdateDate = new Date();
		signDeviceId = "";
		subjectKeyId = "";
		// caCertificate = new CertificateDAO();
	}

	/**
	 * @return the Id of the certificate in the database
	 */
	public Integer getId() {
		return id;
	}

	/**
	 * @param id
	 *            Id of the certificate in the database
	 */
	public void setId(Integer id) {
		this.id = id;
	}

	/**
	 * @return the certificate serial number
	 */
	public Integer getSerialNumber() {
		return serialNumber;
	}

	/**
	 * @param serialNumber
	 *            Certificate serial number
	 */
	public void setSerialNumber(Integer serialNumber) {
		this.serialNumber = serialNumber;
	}

	/**
	 * @return the Base64 String which represents the X509 certificate it self
	 */
	public String getCertificateStr() {
		return certificateStr;
	}

	/**
	 * @param certificateStr
	 *            Base64 String which represents the X509 certificate it self
	 */
	public void setCertificateStr(String certificateStr) {
		this.certificateStr = certificateStr;
	}

	/**
	 * @return the certificate DAO used for sign this one
	 */
	public CertificateDAO getCaCertificate() {
		return caCertificate;
	}

	/**
	 * @param caCertificate
	 *            Certificate DAO used for sign this one
	 */
	public void setCaCertificate(CertificateDAO caCertificate) {
		this.caCertificate = caCertificate;
	}

	/**
	 * @return the owner
	 */
	public SubjectDAO getOwner() {
		return owner;
	}

	/**
	 * @param owner
	 *            the owner to set
	 */
	public void setOwner(SubjectDAO owner) {
		this.owner = owner;
	}

	/**
	 * @return the status of the certificate in the DB, the possible values are
	 *         at {@link X509UtilsDictionary} ej.
	 *         X509UtilsDictionary.X509_CERTIFICATE_STATUS_VALID
	 */
	public Integer getStatus() {
		return status;
	}

	/**
	 * @return the signDeviceId
	 */
	public String getSignDeviceId() {
		return signDeviceId;
	}

	/**
	 * @param signDeviceId
	 *            the signDeviceId to set
	 */
	public void setSignDeviceId(String signDeviceId) {
		this.signDeviceId = signDeviceId;
	}

	/**
	 * @return the subjectKeyId
	 */
	public String getSubjectKeyId() {
		return subjectKeyId;
	}

	/**
	 * @param subjectKeyId
	 *            the subjectKeyId to set
	 */
	public void setSubjectKeyId(String subjectKeyId) {
		this.subjectKeyId = subjectKeyId;
	}

	/**
	 * Get the string value for the certificate status
	 * 
	 * @param language
	 *            The language code for the locale
	 * @return A String that represents the certificate status in the specified
	 *         language
	 */
	public String getStatusStr(String language) {
		if (language.equalsIgnoreCase("ES")) {
			if (status
					.equals(X509UtilsDictionary.X509_CERTIFICATE_STATUS_VALID))
				return "válido";
			if (status
					.equals(X509UtilsDictionary.X509_CERTIFICATE_STATUS_INVALID))
				return "inválido";
			if (status
					.equals(X509UtilsDictionary.X509_CERTIFICATE_STATUS_EXPIRED))
				return "expirado";
			if (status
					.equals(X509UtilsDictionary.X509_CERTIFICATE_STATUS_REVOKED))
				return "revocado";
			if (status
					.equals(X509UtilsDictionary.X509_CERTIFICATE_STATUS_NOT_YET_VALID))
				return "no válido aun";
			return "";
		} else {
			if (status
					.equals(X509UtilsDictionary.X509_CERTIFICATE_STATUS_VALID))
				return "valid";
			if (status
					.equals(X509UtilsDictionary.X509_CERTIFICATE_STATUS_INVALID))
				return "invalid";
			if (status
					.equals(X509UtilsDictionary.X509_CERTIFICATE_STATUS_EXPIRED))
				return "expired";
			if (status
					.equals(X509UtilsDictionary.X509_CERTIFICATE_STATUS_REVOKED))
				return "revoked";
			if (status
					.equals(X509UtilsDictionary.X509_CERTIFICATE_STATUS_NOT_YET_VALID))
				return "not yet valid";
			return "";
		}
	}

	/**
	 * @param status
	 *            Status of the certificate in the DB, the possible values are
	 *            at {@link X509UtilsDictionary} ej.
	 *            X509UtilsDictionary.X509_CERTIFICATE_STATUS_VALID
	 */
	public void setStatus(Integer status) {
		this.status = status;
	}

	/**
	 * @return the date of the last Status update in the DB of this certificate
	 */
	public Date getLastStatusUpdateDate() {
		return lastStatusUpdateDate;
	}

	/**
	 * @param lastStatusUpdateDate
	 *            the date of the last Status update in the DB of this
	 *            certificate
	 */
	public void setLastStatusUpdateDate(Date lastStatusUpdateDate) {
		this.lastStatusUpdateDate = lastStatusUpdateDate;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "CertificateDAO [id=" + id + ", serialNumber=" + serialNumber
				+ ", certificateStr=" + certificateStr + ", caCertificate="
				+ caCertificate.getSerialNumber() + ", owner=" + owner
				+ ", status=" + status + ", lastStatusUpdateDate="
				+ lastStatusUpdateDate + ", signDevice=" + signDeviceId
				+ ", subjectKeyId=" + subjectKeyId + "]";
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof CertificateDAO) {
			CertificateDAO certificateDAO = (CertificateDAO) obj;
			if (this.id.equals(certificateDAO.id)
					&& this.serialNumber.equals(certificateDAO.serialNumber)
					&& this.status.equals(certificateDAO.status)
					&& this.signDeviceId.equals(certificateDAO.signDeviceId)
					&& this.subjectKeyId.equals(certificateDAO.subjectKeyId)
					&& this.lastStatusUpdateDate.getDate() == certificateDAO.lastStatusUpdateDate
							.getDate()
					&& this.lastStatusUpdateDate.getMonth() == certificateDAO.lastStatusUpdateDate
							.getMonth()
					&& this.lastStatusUpdateDate.getYear() == certificateDAO.lastStatusUpdateDate
							.getYear()
					&& this.certificateStr
							.equals(certificateDAO.certificateStr))
				return true;
		}
		return false;
	}

}
