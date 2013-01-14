/**
 *  Created on  : 14/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	
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

/**
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 14/09/2012
 * @version 1.0
 */
public class MyPasswordPKCSDialogFragment extends MyPasswordDialogFragment {

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
	 * @return A new instance of {@link MyPasswordPKCSDialogFragment}
	 */
	public static MyPasswordPKCSDialogFragment newInstance(int title,
			PersonalKeyDAO key,
			OnPositiveButtonClickListener onPositiveButtonClickListener) {
		MyPasswordPKCSDialogFragment frag = new MyPasswordPKCSDialogFragment();
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

		View view = getActivity().getLayoutInflater().inflate(
				R.layout.dialog_pkcs_password, null);
		passwordDialog.setView(view);

		final EditText inputKey = (EditText) view
				.findViewById(R.id.txtKeyPassword);
		final EditText inputPKCS = (EditText) view
				.findViewById(R.id.txtPKCS12Password);

		passwordDialog.setIcon(R.drawable.ic_alert);
		passwordDialog.setTitle(title);
		passwordDialog.setPositiveButton(R.string.alert_dialog_ok,
				new DialogInterface.OnClickListener() {
					public void onClick(DialogInterface dialog, int whichButton) {
						onPositiveButtonClickListener.onPositiveButtonClick(
								key, inputKey.getText().toString(), inputPKCS
										.getText().toString());
					}
				});
		passwordDialog.setNegativeButton(R.string.alert_dialog_cancel,
				new DialogInterface.OnClickListener() {
					public void onClick(DialogInterface dialog, int whichButton) {

					}
				});

		return passwordDialog.create();
	}

}
