/**
 *  Created on  : 17/07/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Data Access Object (DAO) that represents the CRLDAO table in the data base, contains all the required information 
 *  for this table
 *  	
 */
package cinvestav.android.pki.db.dao;

import java.util.Date;

/**
 * Data Access Object (DAO) that represents the CRLDAO table in the data base,
 * contains all the required information for this table
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 17/07/2012
 * @version 1.0
 */
public class CRLDAO {

	/**
	 * Data base CRL id
	 */
	private Integer id;
	/**
	 * CRL serial number
	 */
	private Integer serialNumber;
	/**
	 * Date of official publication of this CRL
	 */
	private Date publishDate;
	/**
	 * Brief description of the CRL
	 */
	private String description;
	/**
	 * Actual data of the CRL as a base64 String
	 */
	private String crlDataStr;
	/**
	 * Certificate DAO of the issuer of this CRL
	 */
	private CertificateDAO issuerCertificate;

	/**
	 * Default constructor
	 */
	public CRLDAO() {
		id = 0;
		serialNumber = 0;
		publishDate = new Date();
		description = "";
		crlDataStr = "";
		issuerCertificate = new CertificateDAO();

	}

	/**
	 * @return the data base CRL id
	 */
	public Integer getId() {
		return id;
	}

	/**
	 * @param id
	 *            Data base CRL id
	 */
	public void setId(Integer id) {
		this.id = id;
	}

	/**
	 * @return the CRL serial number
	 */
	public Integer getSerialNumber() {
		return serialNumber;
	}

	/**
	 * @param serialNumber
	 *            CRL serial number
	 */
	public void setSerialNumber(Integer serialNumber) {
		this.serialNumber = serialNumber;
	}

	/**
	 * @return the date of official publication of this CRL
	 */
	public Date getPublishDate() {
		return publishDate;
	}

	/**
	 * @param publishDate
	 *            Date of official publication of this CRL
	 */
	public void setPublishDate(Date publishDate) {
		this.publishDate = publishDate;
	}

	/**
	 * @return the brief description of the CRL
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * @param description
	 *            Brief description of the CRL
	 */
	public void setDescription(String description) {
		this.description = description;
	}

	/**
	 * @return the actual data of the CRL as a base64 String
	 */
	public String getCrlDataStr() {
		return crlDataStr;
	}

	/**
	 * @param crlDataStr
	 *            Actual data of the CRL as a base64 String
	 */
	public void setCrlDataStr(String crlDataStr) {
		this.crlDataStr = crlDataStr;
	}

	/**
	 * @return the certificate DAO of the issuer of this CRL
	 */
	public CertificateDAO getIssuerCertificate() {
		return issuerCertificate;
	}

	/**
	 * @param issuerCertificate
	 *            Certificate DAO of the issuer of this CRL
	 */
	public void setIssuerCertificate(CertificateDAO issuerCertificate) {
		this.issuerCertificate = issuerCertificate;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "CRLDAO [id=" + id + ", serialNumber=" + serialNumber
				+ ", publishDate=" + publishDate + ", description="
				+ description + ", crlDataStr=" + crlDataStr
				+ ", issuerCertificate=" + issuerCertificate + "]";
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof CRLDAO) {
			CRLDAO crlDAO = (CRLDAO) obj;
			if (this.id.equals(crlDAO.id)
					&& this.serialNumber.equals(crlDAO.serialNumber)
					&& this.publishDate.getDate() == crlDAO.publishDate
							.getDate()
					&& this.publishDate.getMonth() == crlDAO.publishDate
							.getMonth()
					&& this.publishDate.getYear() == crlDAO.publishDate
							.getYear()
					&& this.crlDataStr.equals(crlDAO.crlDataStr)
					&& this.description.equals(crlDAO.description))
				return true;
		}
		return false;
	}

}
