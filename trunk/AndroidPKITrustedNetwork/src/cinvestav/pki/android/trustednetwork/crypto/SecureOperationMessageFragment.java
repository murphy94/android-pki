/**
 *  Created on  : 22/10/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Class for secure operations with messages, this fragment should include all the
 * necessary options for sign/verify and cipher/decipher a message
 */
package cinvestav.pki.android.trustednetwork.crypto;

import android.content.Intent;
import android.os.Bundle;
import android.support.v4.app.FragmentTransaction;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import cinvestav.pki.android.trustednetwork.R;

import com.actionbarsherlock.app.SherlockFragment;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuInflater;
import com.actionbarsherlock.view.MenuItem;
import com.actionbarsherlock.widget.ShareActionProvider;

/**
 * Class for secure operations with messages, this fragment should include all
 * the necessary options for sign/verify and cipher/decipher a message
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 22/10/2012
 * @version 1.0
 */
public class SecureOperationMessageFragment extends SherlockFragment {

	SecureOperationOptionsFragment secureOperationOptionsFragment;
	int currentOption;
	private String selectedPrivateKeySign;
	private String selectedPrivateKeyDecipher;
	private String selectedCertificateVerify;
	private String selectedCertificateCipher;
	private String existingInput;
	TextView txtMessage;
	private int selectedOperation;

	private static final String CURRENT_OPTION = "CURRENT_OPTION";
	private static final String SELECTED_OPERATION = "SELECTED_OPERATION";
	static final String SELECTED_PRIVATE_KEY_DECIPHER = "SELECTED_PRIVATE_KEY_DECIPHER";
	private static final String SELECTED_PRIVATE_KEY_SIGN = "SELECTED_PRIVATE_KEY_SIGN";
	private static final String SELECTED_CERTIFICATE_VERIFY = "SELECTED_CERTIFICATE_VERIFY";
	private static final String SELECTED_CERTIFICATE_CIPHER = "SELECTED_CERTIFICATE_CIPHER";
	private static final String EXISTING_INPUT = "EXISTING_INPUT";

	private ShareActionProvider mShareActionProvider;

	public SecureOperationMessageFragment() {
		super();
	}

	/**
	 * Create a new instance with empty values for the view
	 * 
	 * @return a new instance for this class filled out with empty values
	 */
	public static SecureOperationMessageFragment newInstance(int currentOption,
			String existingInput, int selectedOperation,
			String selectedPrivateKeySign, String selectedPrivateKeyDecipher,
			String selectedCertificateCipher, String selectedCertificateVerify) {
		SecureOperationMessageFragment f = new SecureOperationMessageFragment();
		f.setCurrentOption(currentOption);
		f.setSelectedCertificateCipher(selectedCertificateCipher);
		f.setSelectedCertificateVerify(selectedCertificateVerify);
		f.setSelectedPrivateKeyDecipher(selectedPrivateKeyDecipher);
		f.setSelectedPrivateKeySign(selectedPrivateKeySign);
		f.setExistingInput(existingInput);
		f.setSelectedOperation(selectedOperation);
		return f;
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
	 * @return the currentOption
	 */
	public int getCurrentOption() {
		return currentOption;
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
	 * @param currentOption
	 *            the currentOption to set
	 */
	public void setCurrentOption(int currentOption) {
		this.currentOption = currentOption;
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		setRetainInstance(true);
		super.onCreateView(inflater, container, savedInstanceState);
		setHasOptionsMenu(true);
		View rootView = inflater.inflate(R.layout.secure_operation_message,
				container, false);

		if (savedInstanceState == null) {
			// First-time init; create fragment to embed in activity.
			FragmentTransaction ft = getActivity().getSupportFragmentManager()
					.beginTransaction();
			secureOperationOptionsFragment = SecureOperationOptionsFragment
					.newInstance(currentOption, selectedOperation,
							selectedPrivateKeySign, selectedPrivateKeyDecipher,
							selectedCertificateCipher,
							selectedCertificateVerify);

			ft.replace(R.id.embeddedSecureOptionsMsg,
					secureOperationOptionsFragment);
			ft.commit();
		} else if (savedInstanceState != null
				&& selectedCertificateCipher == null) {
			currentOption = savedInstanceState.getInt(CURRENT_OPTION);
			existingInput = savedInstanceState.getString(EXISTING_INPUT);
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

		txtMessage = (TextView) rootView.findViewById(R.id.txtMessage);

		if (existingInput != null && !existingInput.equals("")) {
			txtMessage.setText(existingInput);
		}

		return rootView;
	}

	@Override
	public void onCreateOptionsMenu(Menu menu, MenuInflater inflater) {
		// Place an action bar item for cipher and signing
		inflater.inflate(R.menu.secure_message_menu, menu);

		/**
		 * Getting the action provider associated with the menu item whose id is
		 * share
		 */
		// mShareActionProvider = (ShareActionProvider) menu.findItem(
		// R.id.menu_secure_send).getActionProvider();
	}

	/**
	 * Hook into the OptionsMenu and add an Edit, Delete and Share option.
	 */
	@Override
	public void onPrepareOptionsMenu(Menu menu) {

		MenuItem sendItem = menu.findItem(R.id.menu_secure_send);
		sendItem.setVisible(true);
		mShareActionProvider = (ShareActionProvider) sendItem
				.getActionProvider();

		super.onPrepareOptionsMenu(menu);
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		switch (item.getItemId()) {
		case R.id.menu_secure_send:
			/** Setting a share intent */
			mShareActionProvider.setShareIntent(getDefaultShareIntent());
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}

	/**
	 * Returns share intent
	 * 
	 * @return
	 */
	private Intent getDefaultShareIntent() {
		Intent shareIntent = new Intent();
		shareIntent.setAction(Intent.ACTION_SEND);
		shareIntent
				.putExtra(Intent.EXTRA_TEXT, txtMessage.getText().toString());
		shareIntent.setType("text/plain");
		return shareIntent;
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
		outState.putString(EXISTING_INPUT, existingInput);
		outState.putString(SELECTED_CERTIFICATE_CIPHER,
				selectedCertificateCipher);
		outState.putString(SELECTED_CERTIFICATE_VERIFY,
				selectedCertificateVerify);
		outState.putString(SELECTED_PRIVATE_KEY_DECIPHER,
				selectedPrivateKeyDecipher);
		outState.putString(SELECTED_PRIVATE_KEY_SIGN, selectedPrivateKeySign);
		outState.putInt(SELECTED_OPERATION, selectedOperation);
	}
}
