/**
 *  Created on  : 29/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	A fragment representing a section of the app, this fragment will allow insert
 * all the information referent to the certificate custom extension, like
 * userid, user permissions and identification document values
 */
package cinvestav.pki.android.trustednetwork.add;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import cinvestav.pki.android.trustednetwork.R;

import com.actionbarsherlock.app.SherlockFragment;

/**
 * A fragment representing a section of the app, this fragment will allow insert
 * all the information referent to the certificate custom extension, like
 * userid, user permissions and identification document values
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 29/09/2012
 * @version 1.0
 */
public class AddNewCertificateCustomInformationFragment extends
		SherlockFragment {

	EditText txtCertificateUserId;
	EditText txtCertificateUserPermission;
	EditText txtCertificateIdentificationDocument;

	String initialUserId;
	String initialUserPermission;
	String initialIdentificationDocument;
	Boolean loadValues;

	public AddNewCertificateCustomInformationFragment() {
		super();
	}

	/**
	 * Create a new instance with empty values for the view
	 * 
	 * @return a new instance for this class filled out with empty values
	 */
	public static AddNewCertificateCustomInformationFragment newInstance() {
		AddNewCertificateCustomInformationFragment f = new AddNewCertificateCustomInformationFragment();
		f.setLoadValues(Boolean.FALSE);
		return f;
	}

	/**
	 * Create a new instance with initial values for the view
	 * 
	 * @param initialUserId
	 *            User Id initial value
	 * @param initialUserPermission
	 *            User permission initial value
	 * @param initialIdentificationDocument
	 *            Identification document initial values
	 * @return a new instance for this class filled out with initial values
	 */
	public static AddNewCertificateCustomInformationFragment newInstance(
			String initialUserId, String initialUserPermission,
			String initialIdentificationDocument) {
		AddNewCertificateCustomInformationFragment f = new AddNewCertificateCustomInformationFragment();
		f.setInitialIdentificationDocument(initialIdentificationDocument);
		f.setInitialUserId(initialUserId);
		f.setInitialUserPermission(initialUserPermission);
		f.setLoadValues(Boolean.TRUE);
		return f;
	}

	/**
	 * @param initialUserId
	 *            the initialUserId to set
	 */
	public void setInitialUserId(String initialUserId) {
		this.initialUserId = initialUserId;
	}

	/**
	 * @param initialUserPermission
	 *            the initialUserPermission to set
	 */
	public void setInitialUserPermission(String initialUserPermission) {
		this.initialUserPermission = initialUserPermission;
	}

	/**
	 * @param initialIdentificationDocument
	 *            the initialIdentificationDocument to set
	 */
	public void setInitialIdentificationDocument(
			String initialIdentificationDocument) {
		this.initialIdentificationDocument = initialIdentificationDocument;
	}

	/**
	 * @param loadValues
	 *            the loadValues to set
	 */
	public void setLoadValues(Boolean loadValues) {
		this.loadValues = loadValues;
	}

	/**
	 * @return the txtCertificateUserId
	 */
	public EditText getTxtCertificateUserId() {
		return txtCertificateUserId;
	}

	/**
	 * @return the txtCertificateUserPermission
	 */
	public EditText getTxtCertificateUserPermission() {
		return txtCertificateUserPermission;
	}

	/**
	 * @return the txtCertificateIdentificationDocument
	 */
	public EditText getTxtCertificateIdentificationDocument() {
		return txtCertificateIdentificationDocument;
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		setRetainInstance(true);
		View rootView = inflater.inflate(
				R.layout.add_certificate_custom_information_fragment,
				container, false);

		txtCertificateIdentificationDocument = (EditText) rootView
				.findViewById(R.id.txtCertificateIdentificationDocument);

		txtCertificateUserPermission = (EditText) rootView
				.findViewById(R.id.txtCertificateUserPermission);

		txtCertificateUserId = (EditText) rootView
				.findViewById(R.id.txtCertificateUserId);

		if (loadValues) {
			txtCertificateIdentificationDocument
					.setText(initialIdentificationDocument);
			txtCertificateUserId.setText(initialUserId);
			txtCertificateUserPermission.setText(initialUserPermission);
			// Change the value so this will only will be made the first time
			// the view is loaded
			loadValues = Boolean.FALSE;
		}

		return rootView;
	}

}
