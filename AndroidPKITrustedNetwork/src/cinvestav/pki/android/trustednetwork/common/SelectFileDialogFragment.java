/**
 *  Created on  : 14/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	DialogFragment for select a file from the device using a installed file manager installed, 
 *  this class contains a OnClickListener interface which must be instantiated in
 *  order to set the listener for manage the click options on this dialog.
 */

package cinvestav.pki.android.trustednetwork.common;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.ActivityNotFoundException;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;
import cinvestav.pki.android.trustednetwork.R;

import com.actionbarsherlock.app.SherlockDialogFragment;

/**
 * DialogFragment for select a file from the device using a installed file
 * manager, this class contains a OnClickListener interface which must be
 * instantiated in calling activity in order to set the listener for manage the
 * click event on this dialog.
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 14/09/2012
 * @version 1.0
 */
public class SelectFileDialogFragment extends SherlockDialogFragment {

	// public static final int MENU_ACCEPT = 0;
	// public static final int MENU_CANCEL = 1;
	// public static final int OPEN_FILE_REQUEST_ID = 1;
	private String fileName;
	private String warning;
	private int requestId;

	private EditText txtFileName;
	private ImageView btnBrowse;

	/**
	 * Listener for OnClickListener on the dialog fragment, the implementation
	 * of this interface will determine what to do with the selected file
	 */
	protected OnClickListener onClickListener;

	/**
	 * @return the onClickListener
	 */
	public OnClickListener getOnClickListener() {
		return onClickListener;
	}

	/**
	 * @param onClickListener
	 *            the onClickListener to set
	 */
	public void setOnClickListener(OnClickListener onClickListener) {
		this.onClickListener = onClickListener;
	}

	/**
	 * @return the fileName
	 */
	public String getFileName() {
		return fileName;
	}

	/**
	 * @param fileName
	 *            the fileName to set
	 */
	public void setFileName(String fileName) {
		this.fileName = fileName;
	}

	/**
	 * @return the warning
	 */
	public String getWarning() {
		return warning;
	}

	/**
	 * @param warning
	 *            the warning to set
	 */
	public void setWarning(String warning) {
		this.warning = warning;
	}

	/**
	 * @return the requestId
	 */
	public int getRequestId() {
		return requestId;
	}

	/**
	 * @param requestId
	 *            the requestId to set
	 */
	public void setRequestId(int requestId) {
		this.requestId = requestId;
	}

	/**
	 * Create a new instance for this dialog, use this when the dialog fragment
	 * will be shown
	 * 
	 * @param title
	 *            Title for the dialog
	 * @param message
	 *            Message to be shown in the dialog
	 * @param defaultFile
	 *            Default file to be selected
	 * @param onClickListener
	 *            Listener for OnClickListener, its implementation will
	 *            determine what to do with the selected file
	 * @return A new instance of FileDialogFragment
	 */
	public static SelectFileDialogFragment newInstance(int title, int message,
			String warning, String defaultFile,
			OnClickListener onClickListener, int requestId) {
		SelectFileDialogFragment frag = new SelectFileDialogFragment();
		Bundle args = new Bundle();
		args.putInt("title", title);
		args.putInt("message", message);
		frag.setWarning(warning);
		frag.setArguments(args);
		frag.setFileName(defaultFile);
		frag.setOnClickListener(onClickListener);
		frag.setRequestId(requestId);
		return frag;
	}

	/**
	 * Create a new instance for this dialog, use this when the dialog fragment
	 * will be embedded into an other activity
	 * 
	 * @param title
	 *            Title for the dialog
	 * @param message
	 *            Message to be shown in the dialog
	 * @param defaultFile
	 *            Default file to be selected
	 * @return A new instance of FileDialogFragment
	 */
	public static SelectFileDialogFragment newInstance(int title, int message,
			String warning, String defaultFile, int requestId) {
		SelectFileDialogFragment frag = new SelectFileDialogFragment();
		Bundle args = new Bundle();
		args.putInt("title", title);
		args.putInt("message", message);
		frag.setWarning(warning);
		frag.setArguments(args);
		frag.setFileName(defaultFile);
		frag.setRequestId(requestId);
		return frag;
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		setRetainInstance(true);
		int message = getArguments().getInt("message");
		View view = inflater.inflate(R.layout.open_file, container, false);

		((TextView) view.findViewById(R.id.lblMessage)).setText(message);

		TextView lblWarning = ((TextView) view
				.findViewById(R.id.lblWarningExport));
		if (warning == null || warning.isEmpty()) {
			lblWarning.setVisibility(View.GONE);
		} else {
			lblWarning.setText(warning);
		}
		txtFileName = (EditText) view.findViewById(R.id.txtFileName);
		txtFileName.setText(fileName);

		btnBrowse = (ImageView) view.findViewById(R.id.imgBrowse);
		btnBrowse.setClickable(true);
		btnBrowse.setOnClickListener(new View.OnClickListener() {
			public void onClick(View v) {
				openFile();
			}
		});

		return view;
	}

	@Override
	public Dialog onCreateDialog(Bundle savedInstanceState) {
		int title = getArguments().getInt("title");

		final AlertDialog.Builder selectFileDialog = new AlertDialog.Builder(
				getActivity());

		selectFileDialog.setTitle(title);
		selectFileDialog.setPositiveButton(R.string.alert_dialog_ok,
				new DialogInterface.OnClickListener() {
					public void onClick(DialogInterface dialog, int whichButton) {
						onClickListener.onOkClick(txtFileName.getText()
								.toString());
					}
				});
		selectFileDialog.setNegativeButton(R.string.alert_dialog_cancel,
				new DialogInterface.OnClickListener() {
					public void onClick(DialogInterface dialog, int whichButton) {
						onClickListener.onCancelClick();
					}
				});

		return selectFileDialog.create();
	}

	/**
	 * Opens the file manager to select a file to open.
	 */
	private void openFile() {
		String filename = txtFileName.getText().toString();

		Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
		intent.addCategory(Intent.CATEGORY_OPENABLE);

		intent.setData(Uri.parse("file://" + filename));
		intent.setType("*/*");

		try {
			getActivity().startActivityForResult(intent, requestId);
		} catch (ActivityNotFoundException e) {
			// No compatible file manager was found.
			Toast.makeText(getActivity(), R.string.noFilemanagerInstalled,
					Toast.LENGTH_SHORT).show();
		}
	}

	/**
	 * Interface to determine what to do with the selected file, declares two
	 * functions, one for cancel button and the other for OK button
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 14/09/2012
	 * @version 1.0
	 */
	public static interface OnClickListener {
		/**
		 * To be called when the user selects the cancel button in the dialog
		 */
		public void onCancelClick();

		/**
		 * To be called when the user selects the OK button in the dialog
		 * 
		 * @param filename
		 *            Selected fileName
		 */
		public void onOkClick(String filename);
	}
}
