/**
 *  Created on  : 22/10/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Fragment for select the cryptographic operations options, like
 *  operation type, and what operations should do, sign and encrypt or only one of them
 */

package cinvestav.pki.android.trustednetwork.crypto;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AnimationUtils;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.ArrayAdapter;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.ViewFlipper;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.main.SecureSectionActivity;

import com.actionbarsherlock.app.SherlockFragment;

/**
 * Fragment for select the cryptographic operations options, like operation
 * type, and what operations should do, sign and encrypt or only one of them
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 22/10/2012
 * @version 1.0
 */
public class SecureOperationOptionsFragment extends SherlockFragment {

	Spinner spinnerOperationType;
	ViewFlipper vf;
	CheckBox chkCipher;
	CheckBox chkDeleteCipher;
	TextView imgSearchPublicCertCipher;
	CheckBox chkSign;
	TextView imgSearchPrivateKeySign;
	CheckBox chkDecipher;
	TextView imgSearchPrivateKeyDecipher;
	CheckBox chkDeleteDecipher;
	CheckBox chkVerify;
	TextView imgSearchPublicCertVerify;
	Integer currentOption;
	private String selectedPrivateKeySign;
	private String selectedPrivateKeyDecipher;
	private String selectedCertificateVerify;
	private String selectedCertificateCipher;
	private int selectedOperation;

	private static final String CURRENT_OPTION = "CURRENT_OPTION";
	private static final String SELECTED_OPERATION = "SELECTED_OPERATION";
	private static final String SELECTED_PRIVATE_KEY_DECIPHER = "SELECTED_PRIVATE_KEY_DECIPHER";
	private static final String SELECTED_PRIVATE_KEY_SIGN = "SELECTED_PRIVATE_KEY_SIGN";
	private static final String SELECTED_CERTIFICATE_VERIFY = "SELECTED_CERTIFICATE_VERIFY";
	private static final String SELECTED_CERTIFICATE_CIPHER = "SELECTED_CERTIFICATE_CIPHER";

	/**
	 * Create a new instance for this fragment
	 * 
	 * @return A new instance of SecureOperationOptionsFragment
	 */
	public static SecureOperationOptionsFragment newInstance(
			Integer currentOption, int selectedOperation,
			String selectedPrivateKeySign, String selectedPrivateKeyDecipher,
			String selectedCertificateCipher, String selectedCertificateVerify) {
		SecureOperationOptionsFragment frag = new SecureOperationOptionsFragment();
		frag.setCurrentOption(currentOption);
		frag.setSelectedCertificateCipher(selectedCertificateCipher);
		frag.setSelectedCertificateVerify(selectedCertificateVerify);
		frag.setSelectedPrivateKeyDecipher(selectedPrivateKeyDecipher);
		frag.setSelectedPrivateKeySign(selectedPrivateKeySign);
		frag.setSelectedOperation(selectedOperation);
		return frag;
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
	public Integer getCurrentOption() {
		return currentOption;
	}

	/**
	 * @param currentOption
	 *            the currentOption to set
	 */
	public void setCurrentOption(Integer currentOption) {
		this.currentOption = currentOption;
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		setRetainInstance(true);

		if (savedInstanceState != null && selectedCertificateCipher == null) {
			currentOption = savedInstanceState.getInt(CURRENT_OPTION);
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

		View rootView = inflater.inflate(R.layout.secure_operation_options,
				container, false);

		vf = (ViewFlipper) rootView.findViewById(R.id.flipperOperation);

		spinnerOperationType = (Spinner) rootView
				.findViewById(R.id.spinnerOperation);
		ArrayAdapter<CharSequence> adapter = ArrayAdapter.createFromResource(
				getActivity(), R.array.cryptoOperationType,
				android.R.layout.simple_spinner_item);
		adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		spinnerOperationType.setAdapter(adapter);
		spinnerOperationType
				.setOnItemSelectedListener(new OperationTypeSpinnerItemSelectedListener());

		spinnerOperationType.setSelection(selectedOperation);
		imgSearchPrivateKeySign = (TextView) rootView
				.findViewById(R.id.lblImgSearchSignPrivateKey);
		imgSearchPrivateKeySign.setOnClickListener(new View.OnClickListener() {

			@Override
			public void onClick(View v) {
				((OnClickSearchElementsListener) getActivity())
						.onPrivateKeySignClick();
			}
		});

		imgSearchPrivateKeyDecipher = (TextView) rootView
				.findViewById(R.id.lblImgSearchDecipherPrivateKey);
		imgSearchPrivateKeyDecipher
				.setOnClickListener(new View.OnClickListener() {

					@Override
					public void onClick(View v) {
						((OnClickSearchElementsListener) getActivity())
								.onPrivateKeyDecipherClick();
					}
				});

		imgSearchPublicCertCipher = (TextView) rootView
				.findViewById(R.id.lblImgSearchCipherPublicCert);
		imgSearchPublicCertCipher
				.setOnClickListener(new View.OnClickListener() {

					@Override
					public void onClick(View v) {
						((OnClickSearchElementsListener) getActivity())
								.onCertificateCipher();
					}
				});

		imgSearchPublicCertVerify = (TextView) rootView
				.findViewById(R.id.lblImgSearchVerifyPublicCert);
		imgSearchPublicCertVerify
				.setOnClickListener(new View.OnClickListener() {

					@Override
					public void onClick(View v) {
						((OnClickSearchElementsListener) getActivity())
								.onCertificateVerify();
					}
				});

		chkDeleteCipher = (CheckBox) rootView.findViewById(R.id.chkDeleteAfter);
		chkDeleteDecipher = (CheckBox) rootView
				.findViewById(R.id.chkDeleteAfterDecipher);
		if (currentOption == SecureSectionActivity.MESSAGE) {
			chkDeleteCipher.setVisibility(View.GONE);
			chkDeleteDecipher.setVisibility(View.GONE);
		}
		chkCipher = (CheckBox) rootView.findViewById(R.id.chkCipher);
		chkCipher
				.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {

					@Override
					public void onCheckedChanged(CompoundButton buttonView,
							boolean isChecked) {
						if (isChecked) {
							imgSearchPublicCertCipher
									.setVisibility(View.VISIBLE);
							if (currentOption != SecureSectionActivity.MESSAGE)
								chkDeleteCipher.setVisibility(View.VISIBLE);
						} else {
							imgSearchPublicCertCipher.setVisibility(View.GONE);
							chkDeleteCipher.setVisibility(View.GONE);
						}
					}
				});
		chkSign = (CheckBox) rootView.findViewById(R.id.chkSign);
		chkSign.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {

			@Override
			public void onCheckedChanged(CompoundButton buttonView,
					boolean isChecked) {
				if (isChecked) {
					imgSearchPrivateKeySign.setVisibility(View.VISIBLE);
				} else {
					imgSearchPrivateKeySign.setVisibility(View.GONE);
				}
			}
		});

		chkDecipher = (CheckBox) rootView.findViewById(R.id.chkDecipher);
		chkDecipher
				.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {

					@Override
					public void onCheckedChanged(CompoundButton buttonView,
							boolean isChecked) {
						if (isChecked) {
							imgSearchPrivateKeyDecipher
									.setVisibility(View.VISIBLE);
							if (currentOption != SecureSectionActivity.MESSAGE)
								chkDeleteDecipher.setVisibility(View.VISIBLE);
						} else {
							imgSearchPrivateKeyDecipher
									.setVisibility(View.GONE);
							chkDeleteDecipher.setVisibility(View.GONE);
						}
					}
				});
		chkVerify = (CheckBox) rootView.findViewById(R.id.chkVerify);
		chkVerify
				.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {

					@Override
					public void onCheckedChanged(CompoundButton buttonView,
							boolean isChecked) {
						if (isChecked) {
							imgSearchPublicCertVerify
									.setVisibility(View.VISIBLE);

						} else {
							imgSearchPublicCertVerify.setVisibility(View.GONE);
						}
					}
				});

		if (selectedPrivateKeySign != null
				&& !selectedPrivateKeySign.equals("")) {
			imgSearchPrivateKeySign.setText(selectedPrivateKeySign);
			chkSign.setChecked(true);
		}

		if (selectedPrivateKeyDecipher != null
				&& !selectedPrivateKeyDecipher.equals("")) {
			imgSearchPrivateKeyDecipher.setText(selectedPrivateKeyDecipher);
			chkDecipher.setChecked(true);
		}

		if (selectedCertificateCipher != null
				&& !selectedCertificateCipher.equals("")) {
			imgSearchPublicCertCipher.setText(selectedCertificateCipher);
			chkCipher.setChecked(true);
		}

		if (selectedCertificateVerify != null
				&& !selectedCertificateVerify.equals("")) {
			imgSearchPublicCertVerify.setText(selectedCertificateVerify);
			chkVerify.setChecked(true);
		}

		return rootView;
	}

	/**
	 * Interface that handles the click on the button for
	 * {@link SecureOperationOptionsFragment}, this interface should be
	 * implemented by the Activity that holds the fragment
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	public interface OnClickSearchElementsListener {
		/**
		 * Search the private key for sign
		 * 
		 */
		void onPrivateKeySignClick();

		/**
		 * Search private key for decipher
		 */
		void onPrivateKeyDecipherClick();

		/**
		 * Search certificate for verification
		 */
		void onCertificateVerify();

		/**
		 * Search certificate for cipher
		 */
		void onCertificateCipher();
	}

	/**
	 * Item Selection Listener for Operation Type spinner, should change the
	 * view flipper to set the fragment that contains the corresponding fields
	 * of the selected operation
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 10/09/2012
	 * @version 1.0
	 */
	public class OperationTypeSpinnerItemSelectedListener implements
			OnItemSelectedListener {

		public void onItemSelected(AdapterView<?> parent, View v, int pos,
				long id) {
			// Set the ViewFlipper Animation
			vf.setAnimation(AnimationUtils.loadAnimation(getActivity(),
					R.anim.fragment_slide_left_enter));
			// Change the view according the operation type (cipher or dechiper)
			vf.setDisplayedChild(pos);
		}

		public void onNothingSelected(AdapterView<?> arg0) {
			// TODO Auto-generated method stub

		}
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
	}
}
