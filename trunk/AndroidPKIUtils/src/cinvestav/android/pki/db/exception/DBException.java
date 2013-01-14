/**
 *  Created on  : November 25, 2010
 *  Author      : Ing. Javier Silva Pérez
 *  Description :
 *  	Personalized exception for DB errors
 *
 */

package cinvestav.android.pki.db.exception;

import java.sql.SQLException;

/**
 *
 * @author Ing. Javier Silva Pérez
 */
public class DBException extends Exception{

    /**
	 * 
	 */
	private static final long serialVersionUID = -4551795654553662516L;
	SQLException dbError;
    /**
     * Constuctor that gets the message for the exception
     * @param message Exception message
     */
    public DBException(String message){
        super(message);
        this.dbError=null;
    }

    /**
     * Receives the exception message and the cause
     * @param message   Exception Message
     * @param cause     Exception Cause
     */
    public DBException(String message, Throwable cause){
        super(message,cause);
        this.dbError=null;
    }

    /**
     * Constructor that receives an other exception
     * @param ex Exception
     */
    public DBException (Exception ex){
        super(ex.getMessage(),ex.getCause());
        this.dbError=null;
    }

    /**
     * Constructor with a message and an SQLException
     * @param message   Exception message
     * @param sqlE      Generated SQLException
     */
    public DBException(String message,SQLException sqlE){
        super(message);
        this.dbError=sqlE;
    }

    /**
     * Gets the SQL error that generates the Exception
     * @return SQL error generated as a string
     */
    public SQLException getDBError() {
        return dbError;
    }

}
