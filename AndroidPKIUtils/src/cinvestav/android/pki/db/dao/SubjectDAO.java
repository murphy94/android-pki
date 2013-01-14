/**
 *  Created on  : 17/07/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Data Access Object (DAO) that represents the data base table SubjectDAO, that is a certificate owner
 */
package cinvestav.android.pki.db.dao;

import java.util.LinkedList;
import java.util.List;

/**
 * Data Access Object (DAO) that represents the data base table SubjectDAO, that
 * is a certificate owner
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 17/07/2012
 * @version 1.0
 */
public class SubjectDAO {

	private Integer id;
	private String name;
	private Boolean active;
	private List<PersonalKeyDAO> keyList;
	private List<TrustedCertificateDAO> trustedCertificateList;
	private String deviceID;

	/**
	 * 
	 */
	public SubjectDAO() {
		id = 0;
		name = "";
		active = Boolean.TRUE;
		// certificateList = new LinkedList<CertificateDAO>();
		keyList = new LinkedList<PersonalKeyDAO>();
		trustedCertificateList = new LinkedList<TrustedCertificateDAO>();
		deviceID = "";
	}

	/**
	 * @return the id
	 */
	public Integer getId() {
		return id;
	}

	/**
	 * @param id
	 *            the id to set
	 */
	public void setId(Integer id) {
		this.id = id;
	}

	/**
	 * @return the deviceID
	 */
	public String getDeviceID() {
		return deviceID;
	}

	/**
	 * @param deviceID
	 *            the deviceID to set
	 */
	public void setDeviceID(String deviceID) {
		this.deviceID = deviceID;
	}

	/**
	 * @return the name
	 */
	public String getName() {
		return name;
	}

	/**
	 * @param name
	 *            the name to set
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * @return the certificateList
	 */
	/*
	 * public List<CertificateDAO> getCertificateList() { return
	 * certificateList; }
	 */

	/**
	 * @param certificateList
	 *            the certificateList to set
	 */
	/*
	 * public void setCertificateList(List<CertificateDAO> certificateList) {
	 * this.certificateList = certificateList; }
	 */

	/**
	 * @return the keyList
	 */
	public List<PersonalKeyDAO> getKeyList() {
		return keyList;
	}

	/**
	 * @param keyList
	 *            the keyList to set
	 */
	public void setKeyList(List<PersonalKeyDAO> keyList) {
		this.keyList = keyList;
	}

	/**
	 * @return the trustedCertificateList
	 */
	public List<TrustedCertificateDAO> getTrustedCertificateList() {
		return trustedCertificateList;
	}

	/**
	 * @param trustedCertificateList
	 *            the trustedCertificateList to set
	 */
	public void setTrustedCertificateList(
			List<TrustedCertificateDAO> trustedCertificateList) {
		this.trustedCertificateList = trustedCertificateList;
	}

	/**
	 * @return the active
	 */
	public Boolean getActive() {
		return active;
	}

	/**
	 * @param active
	 *            the active to set
	 */
	public void setActive(Boolean active) {
		this.active = active;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "SubjectDAO [id=" + id + ", name=" + name + ", active=" + active
				+ ", keyList=" + keyList + ", trustedCertificateList="
				+ trustedCertificateList + ", deviceID=" + deviceID + "]";
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof SubjectDAO) {
			SubjectDAO subject = (SubjectDAO) obj;
			if (this.id.equals(subject.id)
					&& this.active.equals(subject.active)
					&& this.deviceID.equals(subject.deviceID)
					&& this.name.equals(subject.name))
				return true;
		}
		return false;
	}

}
