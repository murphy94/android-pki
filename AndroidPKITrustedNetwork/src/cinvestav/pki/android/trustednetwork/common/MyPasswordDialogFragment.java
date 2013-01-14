/**
 *  Created on  : 14/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	DialogFragment for inserting a password, this class contains a
 * OnPositiveButtonClickListener object which must be instantiated in
 * order to set the listener for this action.
 */
package cinvestav.pki.android.trustednetwork.common;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import cinvestav.android.pki.db.dao.PersonalKeyDAO;
import cinvestav.pki.android.trustednetwork.R;

import com.actionbarsherlock.app.SherlockDialogFragment;

/**
 * DialogFragment for inserting a password, this class contains a
 * OnPositiveButtonClickListener object which must be instantiated in
 * order to set the listener for this action.
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 14/09/2012
 * @version 1.0
 */
public class MyPasswordDialogFragment extends SherlockDialogFragment {

	/**
	 * Listener for OnPositiveButtonClick on the dialog fragment, the
	 * implementation of this interface will determine what to do with the
	 * inserted password
	 */
	protected OnPositiveButtonClickListener onPositiveButtonClickListener;
	protected PersonalKeyDAO key;

	/**
	 * @return the key
	 */
	public PersonalKeyDAO getKey() {
		return key;
	}

	/**
	 * @param key
	 *            the key to set
	 */
	public void setKey(PersonalKeyDAO key) {
		this.key = key;
	}

	/**
	 * @return the onPositiveButtonClickListener
	 */
	public OnPositiveButtonClickListener getOnPositiveButtonClickListener() {
		return onPositiveButtonClickListener;
	}

	/**
	 * @param onPositiveButtonClickListener
	 *            the onPositiveButtonClickListener to set
	 */
	public void setOnPositiveButtonClickListener(
			OnPositiveButtonClickListener onPositiveButtonClickListener) {
		this.onPositiveButtonClickListener = onPositiveButtonClickListener;
	}

	/**
	 * Create a new instance for this dialog
	 * 
	 * @param title
	 *            Title for the dialog
	 * @param key
	 *            Key which will be send after the password is inserted
	 * @param onPositiveButtonClickListener
	 *            Listener for OnPositiveButtonClick, its implementation will
	 *            determine what to do with the password and the key
	 * @return A new instance of MyPasswordDialogFragment
	 */
	public static MyPasswordDialogFragment newInstance(int title,
			PersonalKeyDAO key,
			OnPositiveButtonClickListener onPositiveButtonClickListener) {
		MyPasswordDialogFragment frag = new MyPasswordDialogFragment();
		Bundle args = new Bundle();
		args.putInt("title", title);
		frag.setArguments(args);
		frag.setKey(key);
		frag.setOnPositiveButtonClickListener(onPositiveButtonClickListener);
		return frag;
	}

	@Override
	public Dialog onCreateDialog(Bundle savedInstanceState) {
		setRetainInstance(true);
		int title = getArguments().getInt("title");

		final AlertDialog.Builder passwordDialog = new AlertDialog.Builder(
				getActivity());
		// Set view
		View view = getActivity().getLayoutInflater().inflate(
				R.layout.dialog_key_password, null);
		passwordDialog.setView(view);

		// Get key edit text
		final EditText input = (EditText) view
				.findViewById(R.id.txtKeyPassword);

		passwordDialog.setIcon(R.drawable.ic_alert);
		passwordDialog.setTitle(title);
		passwordDialog.setPositiveButton(R.string.alert_dialog_ok,
				new DialogInterface.OnClickListener() {
					public void onClick(DialogInterface dialog, int whichButton) {
						onPositiveButtonClickListener.onPositiveButtonClick(
								key, input.getText().toString());
						// onPositiveButtonClick();
					}
				});
		passwordDialog.setNegativeButton(R.string.alert_dialog_cancel,
				new DialogInterface.OnClickListener() {
					public void onClick(DialogInterface dialog, int whichButton) {

					}
				});

		return passwordDialog.create();
	}

	/**
	 * Interface to determine what to do with the password, declares two
	 * functions, one for key passwords and the other for PKCS passwords
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 14/09/2012
	 * @version 1.0
	 */
	public interface OnPositiveButtonClickListener {
		/**
		 * To be called from {@link MyPasswordDialogFragment} after the password
		 * is inserted and the PositiveButton is clicked
		 * 
		 * @param key
		 *            Key to be manipulated with the password
		 * @param passwordKey
		 *            Inserted password
		 */
		public void onPositiveButtonClick(PersonalKeyDAO key, String passwordKey);

		/**
		 * To be called from {@link MyPasswordPKCSDialogFragment} after the
		 * passwords (Key and PKCS file) are inserted and the PositiveButton is
		 * clicked
		 * 
		 * @param key
		 *            Key to be manipulated with the password
		 * @param passwordKey
		 *            Inserted key password
		 * @param passwordPKCS
		 *            Inserted PKCS12 File password
		 */
		public void onPositiveButtonClick(PersonalKeyDAO key,
				String passwordKey, String passwordPKCS);
	}
}
