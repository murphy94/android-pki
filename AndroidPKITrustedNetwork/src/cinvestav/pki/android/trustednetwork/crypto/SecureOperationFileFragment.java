/**
 *  Created on  : 22/10/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Class for secure operations with files, this fragment should include all the
 * necessary options for sign/verify and cipher/decipher a file
 */
package cinvestav.pki.android.trustednetwork.crypto;

import android.os.Bundle;
import android.support.v4.app.FragmentTransaction;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.common.SelectFileDialogFragment;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

import com.actionbarsherlock.app.SherlockFragment;

/**
 * Class for secure operations with files, this fragment should include all the
 * necessary options for sign/verify and cipher/decipher a file
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 22/10/2012
 * @version 1.0
 */
public class SecureOperationFileFragment extends SherlockFragment {

	SelectFileDialogFragment selectFileFragment;
	SelectFileDialogFragment selectOutputFileFragment;
	SecureOperationOptionsFragment secureOperationOptionsFragment;
	private LinearLayout mLinearLayout;
	private int currentOption;
	private String selectedPrivateKeySign;
	private String selectedPrivateKeyDecipher;
	private String selectedCertificateVerify;
	private String selectedCertificateCipher;
	private String existingInput;
	private String existingOutputFile;
	private int selectedOperation;

	public static final int REQUEST_OPEN_FILE_ID = 1;
	public static final int REQUEST_OPEN_OUTPUT_FILE_ID = 2;
	private static final String CURRENT_OPTION = "CURRENT_OPTION";
	private static final String SELECTED_OPERATION = "SELECTED_OPERATION";
	private static final String SELECTED_PRIVATE_KEY_DECIPHER = "SELECTED_PRIVATE_KEY_DECIPHER";
	private static final String SELECTED_PRIVATE_KEY_SIGN = "SELECTED_PRIVATE_KEY_SIGN";
	private static final String SELECTED_CERTIFICATE_VERIFY = "SELECTED_CERTIFICATE_VERIFY";
	private static final String SELECTED_CERTIFICATE_CIPHER = "SELECTED_CERTIFICATE_CIPHER";
	private static final String EXISTING_INPUT = "EXISTING_INPUT";
	private static final String EXISTING_OUTPUT_FILE = "EXISTING_OUTPUT_FILE";

	public SecureOperationFileFragment() {
		super();
	}

	/**
	 * Create a new instance with empty values for the view
	 * 
	 * @return a new instance for this class filled out with empty values
	 */
	public static SecureOperationFileFragment newInstance(int currentOption,
			String existingInput, String existingOutputFile,
			int selectedOperation, String selectedPrivateKeySign,
			String selectedPrivateKeyDecipher,
			String selectedCertificateCipher, String selectedCertificateVerify) {
		SecureOperationFileFragment f = new SecureOperationFileFragment();
		f.setCurrentOption(currentOption);
		f.setSelectedCertificateCipher(selectedCertificateCipher);
		f.setSelectedCertificateVerify(selectedCertificateVerify);
		f.setSelectedPrivateKeyDecipher(selectedPrivateKeyDecipher);
		f.setSelectedPrivateKeySign(selectedPrivateKeySign);
		f.setExistingInput(existingInput);
		f.setSelectedOperation(selectedOperation);
		f.setExistingOutputFile(existingOutputFile);
		return f;
	}

	/**
	 * @return the secureOperationOptionsFragment
	 */
	public SecureOperationOptionsFragment getSecureOperationOptionsFragment() {
		return secureOperationOptionsFragment;
	}

	/**
	 * @param secureOperationOptionsFragment
	 *            the secureOperationOptionsFragment to set
	 */
	public void setSecureOperationOptionsFragment(
			SecureOperationOptionsFragment secureOperationOptionsFragment) {
		this.secureOperationOptionsFragment = secureOperationOptionsFragment;
	}

	/**
	 * @return the existingOutputFile
	 */
	public String getExistingOutputFile() {
		return existingOutputFile;
	}

	/**
	 * @param existingOutputFile
	 *            the existingOutputFile to set
	 */
	public void setExistingOutputFile(String existingOutputFile) {
		this.existingOutputFile = existingOutputFile;
	}

	/**
	 * @return the selectedOperation
	 */
	public int getSelectedOperation() {
		return selectedOperation;
	}

	/**
	 * @param selectedOperation
	 *            the selectedOperation to set
	 */
	public void setSelectedOperation(int selectedOperation) {
		this.selectedOperation = selectedOperation;
	}

	/**
	 * @param existingInput
	 *            the existingInput to set
	 */
	public void setExistingInput(String existingInput) {
		this.existingInput = existingInput;
	}

	/**
	 * @return the selectedPrivateKeySign
	 */
	public String getSelectedPrivateKeySign() {
		return selectedPrivateKeySign;
	}

	/**
	 * @param selectedPrivateKeySign
	 *            the selectedPrivateKeySign to set
	 */
	public void setSelectedPrivateKeySign(String selectedPrivateKeySign) {
		this.selectedPrivateKeySign = selectedPrivateKeySign;
	}

	/**
	 * @return the selectedPrivateKeyDecipher
	 */
	public String getSelectedPrivateKeyDecipher() {
		return selectedPrivateKeyDecipher;
	}

	/**
	 * @param selectedPrivateKeyDecipher
	 *            the selectedPrivateKeyDecipher to set
	 */
	public void setSelectedPrivateKeyDecipher(String selectedPrivateKeyDecipher) {
		this.selectedPrivateKeyDecipher = selectedPrivateKeyDecipher;
	}

	/**
	 * @return the selectedCertificateVerify
	 */
	public String getSelectedCertificateVerify() {
		return selectedCertificateVerify;
	}

	/**
	 * @param selectedCertificateVerify
	 *            the selectedCertificateVerify to set
	 */
	public void setSelectedCertificateVerify(String selectedCertificateVerify) {
		this.selectedCertificateVerify = selectedCertificateVerify;
	}

	/**
	 * @return the selectedCertificateCipher
	 */
	public String getSelectedCertificateCipher() {
		return selectedCertificateCipher;
	}

	/**
	 * @param selectedCertificateCipher
	 *            the selectedCertificateCipher to set
	 */
	public void setSelectedCertificateCipher(String selectedCertificateCipher) {
		this.selectedCertificateCipher = selectedCertificateCipher;
	}

	/**
	 * @return the currentOption
	 */
	public int getCurrentOption() {
		return currentOption;
	}

	/**
	 * @param currentOption
	 *            the currentOption to set
	 */
	public void setCurrentOption(int currentOption) {
		this.currentOption = currentOption;
	}

	/**
	 * @return the selectFileFragment
	 */
	public SelectFileDialogFragment getSelectFileFragment() {
		return selectFileFragment;
	}

	/**
	 * @param selectFileFragment
	 *            the selectFileFragment to set
	 */
	public void setSelectFileFragment(
			SelectFileDialogFragment selectFileFragment) {
		this.selectFileFragment = selectFileFragment;
	}

	/**
	 * @return the selectOutputFileFragment
	 */
	public SelectFileDialogFragment getSelectOutputFileFragment() {
		return selectOutputFileFragment;
	}

	/**
	 * @param selectOutputFileFragment
	 *            the selectOutputFileFragment to set
	 */
	public void setSelectOutputFileFragment(
			SelectFileDialogFragment selectOutputFileFragment) {
		this.selectOutputFileFragment = selectOutputFileFragment;
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		setRetainInstance(true);

		View rootView = inflater.inflate(R.layout.secure_operation_file,
				container, false);

		Log.i(PKITrustNetworkActivity.TAG, "FileFragmentSavedInst: "
				+ savedInstanceState);
		if (savedInstanceState == null) {
			// First-time init; create fragment to embed in activity.
			addFragmentes();
		} else if (savedInstanceState != null
				&& selectedCertificateCipher == null) {

			if(selectFileFragment==null){
				addFragmentes();
			}
			
			currentOption = savedInstanceState.getInt(CURRENT_OPTION);
			existingInput = savedInstanceState.getString(EXISTING_INPUT);
			existingOutputFile = savedInstanceState
					.getString(EXISTING_OUTPUT_FILE);
			selectedOperation = savedInstanceState.getInt(SELECTED_OPERATION);
			selectedCertificateCipher = savedInstanceState
					.getString(SELECTED_CERTIFICATE_CIPHER);
			selectedCertificateVerify = savedInstanceState
					.getString(SELECTED_CERTIFICATE_VERIFY);
			selectedPrivateKeyDecipher = savedInstanceState
					.getString(SELECTED_PRIVATE_KEY_DECIPHER);
			selectedPrivateKeySign = savedInstanceState
					.getString(SELECTED_PRIVATE_KEY_SIGN);
		}

		mLinearLayout = (LinearLayout) rootView
				.findViewById(R.id.linearLayout_focus);

		return rootView;
	}
	
	/*
	 * (non-Javadoc)
	 * 
	 * @see android.support.v4.app.Fragment#onResume()
	 */
	@Override
	public void onResume() {

		super.onResume();
		// do not give the editbox focus automatically when activity starts
		// txtNewOwnerName.clearFocus();
		mLinearLayout.requestFocus();

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * android.support.v4.app.Fragment#onSaveInstanceState(android.os.Bundle)
	 */
	@Override
	public void onSaveInstanceState(Bundle outState) {
		super.onSaveInstanceState(outState);
		outState.putInt(CURRENT_OPTION, currentOption);
		outState.putString(SELECTED_CERTIFICATE_CIPHER,
				selectedCertificateCipher);
		outState.putString(SELECTED_CERTIFICATE_VERIFY,
				selectedCertificateVerify);
		outState.putString(SELECTED_PRIVATE_KEY_DECIPHER,
				selectedPrivateKeyDecipher);
		outState.putString(SELECTED_PRIVATE_KEY_SIGN, selectedPrivateKeySign);
		outState.putInt(SELECTED_OPERATION, selectedOperation);
		outState.putString(EXISTING_INPUT, existingInput);
		outState.putString(EXISTING_OUTPUT_FILE, existingOutputFile);

	}
	
	

	public void addFragmentes() {
		
		// First-time init; create fragment to embed in activity.
		FragmentTransaction ft = getActivity().getSupportFragmentManager()
				.beginTransaction();

		selectFileFragment = SelectFileDialogFragment.newInstance(
				R.string.dialog_select_file_title, R.string.lblMessageFile, "",
				existingInput, REQUEST_OPEN_FILE_ID);

		selectOutputFileFragment = SelectFileDialogFragment.newInstance(
				R.string.dialog_select_file_title,
				R.string.lblMessageOutputFile, "", existingOutputFile,
				REQUEST_OPEN_OUTPUT_FILE_ID);

		secureOperationOptionsFragment = SecureOperationOptionsFragment
				.newInstance(currentOption, selectedOperation,
						selectedPrivateKeySign, selectedPrivateKeyDecipher,
						selectedCertificateCipher, selectedCertificateVerify);
		ft.replace(R.id.embeddedSelectFile, selectFileFragment);
		ft.replace(R.id.embeddedSelectOutputFile, selectOutputFileFragment);
		ft.replace(R.id.embeddedSecureOptions, secureOperationOptionsFragment);
		ft.commit();
	}
}
