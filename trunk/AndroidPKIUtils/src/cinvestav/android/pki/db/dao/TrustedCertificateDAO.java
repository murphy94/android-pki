/**
 *  Created on  : 19/07/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	
 */
package cinvestav.android.pki.db.dao;

import cinvestav.android.pki.db.exception.DBException;

/**
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 19/07/2012
 * @version 1.0
 */
public class TrustedCertificateDAO {

	/**
	 * Data base ID
	 */
	private Integer id;
	/**
	 * Trust level for the certificate, its based on PGP web of trust model,
	 * with some modifications for better performance, this value represents how
	 * much do the list owner trust in some other entity as introducer for new
	 * certificates, could take a value between [-100,100], in which -100 means
	 * that the introducer is totally untrusted and its totally known for
	 * creating false certificates, on the other hand, 100 is for introducer to
	 * which the list owner has fully trust and the certificates sign by this
	 * entity will be trusted completely. </ul>
	 */
	private Integer trustLevel;
	/**
	 * Details of the trusted certificate
	 */
	private CertificateDAO trustedCertificate;

	/**
	 * 
	 */
	public TrustedCertificateDAO() {
		id = 0;
		trustLevel = 0;
		trustedCertificate = new CertificateDAO();
	}

	/**
	 * Parameterized constructor
	 * 
	 * @param id
	 * @param trustLevel
	 * @param trustedCertificate
	 * @throws DBException
	 *             if the trust level is not valid, see valid values as static
	 *             values in this class, ej.
	 *             TrustedCertificateDAO.TRUST_LEVEL_COMPLETE
	 */
	public TrustedCertificateDAO(Integer id, Integer trustLevel,
			CertificateDAO trustedCertificate) throws DBException {
		super();
		if (trustLevel < -100 && trustLevel > 100) {
			throw new DBException("Invalid Trust Level value: " + trustLevel);
		}
		this.id = id;
		this.trustLevel = trustLevel;
		this.trustedCertificate = trustedCertificate;

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
	 * @return the trustLevel
	 */
	public Integer getTrustLevel() {
		return trustLevel;
	}

	/**
	 * @param trustLevel
	 *            the trustLevel to set
	 * @throws DBException
	 *             if the trust level is not valid, the value must be between
	 *             -100 and 100
	 */
	public void setTrustLevel(Integer trustLevel) throws DBException {
		if (trustLevel < -100 && trustLevel > 100) {
			throw new DBException("Invalid Trust Level value: " + trustLevel);
		}
		this.trustLevel = trustLevel;
	}

	/**
	 * @return the trustedCertificate
	 */
	public CertificateDAO getTrustedCertificate() {
		return trustedCertificate;
	}

	/**
	 * @param trustedCertificate
	 *            the trustedCertificate to set
	 */
	public void setTrustedCertificate(CertificateDAO trustedCertificate) {
		this.trustedCertificate = trustedCertificate;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "TrustedCertificateDAO [id=" + id + ", trustLevel=" + trustLevel
				+ ", trustedCertificate=" + trustedCertificate + "]";
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof TrustedCertificateDAO) {
			TrustedCertificateDAO trustedCertificate = (TrustedCertificateDAO) obj;
			if (this.id.equals(trustedCertificate.id)
					&& this.trustLevel.equals(trustedCertificate.trustLevel)
					&& this.trustedCertificate
							.equals(trustedCertificate.trustedCertificate))
				return true;
		}
		return false;
	}

}
