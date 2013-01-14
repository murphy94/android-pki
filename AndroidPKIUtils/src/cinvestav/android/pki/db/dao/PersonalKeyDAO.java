/**
 *  Created on  : 19/07/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Data Access Object (DAO) that represents the data base table Key, that represents
 *  the set of saved key that a subject has
 */
package cinvestav.android.pki.db.dao;

import java.io.Serializable;
import java.util.Date;

import cinvestav.android.pki.db.exception.DBException;

/**
 * Data Access Object (DAO) that represents the data base table Key, that
 * represents the set of saved key that a subject has
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 19/07/2012
 * @version 1.0
 */
public class PersonalKeyDAO implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = -974874307647503333L;
	/**
	 * Table id
	 */
	private Integer id;
	/**
	 * Actual data of the key stored in the database as a base64 string
	 */
	private String keyStr;
	/**
	 * Key ID, constructed from the key it self, could be the hash of the key ir
	 * self
	 */
	private String keyID;
	/**
	 * Key Type:
	 * <ul>
	 * <li>0: Private EC
	 * <li>1: Public EC
	 * <li>2: Private RSA
	 * <li>3: Public RSA
	 * <li>4: EC PKCS#12
	 * <li>5: RSA PKCS#12
	 * </ul>
	 */
	private Integer keyType;

	/**
	 * Key Owner subject Id
	 */
	private Integer subjectId;

	/**
	 * Key comment
	 */
	private String comment;

	/**
	 * Key creation date
	 */
	private Date creationDate;

	public static final Integer PRIVATE_EC = 0;
	public static final Integer PUBLIC_EC = 1;
	public static final Integer PRIVATE_RSA = 2;
	public static final Integer PUBLIC_RSA = 3;
	public static final Integer PKCS12_EC = 4;
	public static final Integer PKCS12_RSA = 5;

	/**
	 * 
	 */
	public PersonalKeyDAO() {
		id = 0;
		keyStr = "";
		keyID = "";
		keyType = -1;
		subjectId = 0;
		comment = "";
		creationDate = new Date();
	}

	/**
	 * Parameterized constructor
	 * 
	 * @param id
	 * @param keyStr
	 *            Actual data of the key stored in the database as a base64
	 *            string
	 * @param keyID
	 *            Key ID, constructed from the key it self
	 * @param keyType
	 *            Key Type:
	 *            <ul>
	 *            <li>0: Private EC
	 *            <li>1: Public EC
	 *            <li>2: Private RSA
	 *            <li>3: Public RSA
	 *            <li>4: EC PKCS#12
	 *            <li>5: RSA PKCS#12
	 *            </ul>
	 * @param subjectId
	 *            Subject owner id
	 * @param comment
	 *            Personal comment for this key
	 */
	public PersonalKeyDAO(Integer id, String keyStr, String keyID,
			Integer keyType, Integer subjectId, String comment,
			Date creationDate) {
		super();
		this.id = id;
		this.keyStr = keyStr;
		this.keyID = keyID;
		this.keyType = keyType;
		this.subjectId = subjectId;
		this.comment = comment;
		this.creationDate = creationDate;
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
	 * @return Actual data of the key stored in the database as a base64 string
	 */
	public String getKeyStr() {
		return keyStr;
	}

	/**
	 * @param keyStr
	 *            Actual data of the key stored in the database as a base64
	 *            string
	 */
	public void setKeyStr(String keyStr) {
		this.keyStr = keyStr;
	}

	/**
	 * @return Key ID, constructed from the key it self
	 */
	public String getKeyID() {
		return keyID;
	}

	/**
	 * @param keyID
	 *            Key ID, constructed from the key it self
	 */
	public void setKeyID(String keyID) {
		this.keyID = keyID;
	}

	/**
	 * @return Key Type:
	 *         <ul>
	 *         <li>0: Private EC
	 *         <li>1: Public EC
	 *         <li>2: Private RSA
	 *         <li>3: Public RSA
	 *         <li>4: EC PKCS#12
	 *         <li>5: RSA PKCS#12
	 *         </ul>
	 */
	public Integer getKeyType() {
		return keyType;
	}

	/**
	 * Return a multilanguage String equivalence of the key type
	 * 
	 * @param language
	 * 
	 * @return The string equivalence of the key type
	 */
	public String getKeyTypeStr(String language) {
		if (language.equalsIgnoreCase("ES")) {
			switch (keyType) {
			case 0:
				return "Privada EC";
			case 1:
				return "Pública EC";
			case 2:
				return "Privada RSA";
			case 3:
				return "Pública RSA";
			case 4:
				return "EC PKCS#12";
			case 5:
				return "RSA PKCS#12";
			default:
				return "Tipo de clave inválido";
			}

		} else {
			switch (keyType) {
			case 0:
				return "Private EC";
			case 1:
				return "Public EC";
			case 2:
				return "Private RSA";
			case 3:
				return "Public RSA";
			case 4:
				return "EC PKCS#12";
			case 5:
				return "RSA PKCS#12";
			default:
				return "Invalid Key Type";
			}
		}
	}

	/**
	 * @param keyType
	 *            Key Type:
	 *            <ul>
	 *            <li>0: Private EC
	 *            <li>1: Public EC
	 *            <li>2: Private RSA
	 *            <li>3: Public RSA
	 *            <li>4: EC PKCS#12
	 *            <li>5: RSA PKCS#12
	 *            </ul>
	 * @throws DBException
	 *             if the key type is not supported
	 */
	public void setKeyType(Integer keyType) throws DBException {
		if (keyType > 5 && keyType < 0) {
			throw new DBException("Unsupported Key Type");
		}
		this.keyType = keyType;
	}

	/**
	 * @return the creationDate
	 */
	public Date getCreationDate() {
		return creationDate;
	}

	/**
	 * @param creationDate
	 *            the creationDate to set
	 */
	public void setCreationDate(Date creationDate) {
		this.creationDate = creationDate;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "PersonalKeyDAO [id=" + id + ", keyStr=" + keyStr + ", keyID="
				+ keyID + ", keyType=" + keyType + ", subjectId=" + subjectId
				+ ", comment=" + comment + ", creationDate=" + creationDate
				+ "]";
	}

	/**
	 * @return the subjectId
	 */
	public Integer getSubjectId() {
		return subjectId;
	}

	/**
	 * @param subjectId
	 *            the subjectId to set
	 */
	public void setSubjectId(Integer subjectId) {
		this.subjectId = subjectId;
	}

	/**
	 * @return the comment
	 */
	public String getComment() {
		return comment;
	}

	/**
	 * @param comment
	 *            the comment to set
	 */
	public void setComment(String comment) {
		this.comment = comment;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof PersonalKeyDAO) {
			PersonalKeyDAO personalKeyDAO = (PersonalKeyDAO) obj;
			if (this.id.equals(personalKeyDAO.id)
					&& this.keyID.equals(personalKeyDAO.keyID)
					&& this.keyStr.equals(personalKeyDAO.keyStr)
					&& this.keyType.equals(personalKeyDAO.keyType)
					&& this.creationDate.getDate() == personalKeyDAO.creationDate
							.getDate()
					&& this.creationDate.getMonth() == personalKeyDAO.creationDate
							.getMonth()
					&& this.creationDate.getYear() == personalKeyDAO.creationDate
							.getYear())
				return true;
		}
		return false;
	}
}
