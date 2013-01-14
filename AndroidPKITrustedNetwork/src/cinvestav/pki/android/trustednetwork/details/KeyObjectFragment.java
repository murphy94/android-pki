/**
 *  Created on  : 31/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	A fragment representing a section of the app, simply displays the basic key
 * information.
 */
package cinvestav.pki.android.trustednetwork.details;

import java.util.Date;

import android.os.Bundle;
import android.text.format.DateFormat;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import cinvestav.android.pki.db.controller.PersonalKeyController;
import cinvestav.android.pki.db.controller.SubjectController;
import cinvestav.android.pki.db.dao.PersonalKeyDAO;
import cinvestav.android.pki.db.dao.SubjectDAO;
import cinvestav.android.pki.db.exception.DBException;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

import com.actionbarsherlock.app.SherlockFragment;

/**
 * A fragment representing a section of the app, simply displays the basic key
 * information.
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 31/08/2012
 * @version 1.0
 */
public class KeyObjectFragment extends SherlockFragment {

	PersonalKeyDAO key;
	Integer keyId;
	Boolean moreDetails;
	PersonalKeyController personalKeyController;
	SubjectController subjectController;
	private static final String KEY_ID = "KEY_ID";
	private static java.text.DateFormat df;

	// static PersonalKeyController certificateController;
	// static SubjectController certificateController;

	public KeyObjectFragment() {
		super();
		Log.i(PKITrustNetworkActivity.TAG, "CONSTRUCTOR");
		keyId = 0;
		moreDetails = Boolean.FALSE;
	}

	public static KeyObjectFragment newInstance(Integer keyId) {
		KeyObjectFragment f = new KeyObjectFragment();
		f.setKeyId(keyId);
		f.setMoreDetails(Boolean.FALSE);
		// KeyObjectFragment.setPersonalKeyController(certificateController);
		// KeyObjectFragment.setSubjectController(certificateController);
		return f;
	}

	/**
	 * @return the key
	 */
	public PersonalKeyDAO getKey() {
		return key;
	}

	/**
	 * @return the privateKeyId
	 */
	public Integer getKeyId() {
		return keyId;
	}

	/**
	 * @param privateKeyId
	 *            the privateKeyId to set
	 */
	public void setKeyId(Integer keyId) {
		this.keyId = keyId;
	}

	/**
	 * @param key
	 *            the key to set
	 */
	public void setKey(PersonalKeyDAO key) {
		this.key = key;
	}

	/**
	 * @return the moreDetails
	 */
	public Boolean getMoreDetails() {
		return moreDetails;
	}

	/**
	 * @param moreDetails
	 *            the moreDetails to set
	 */
	public void setMoreDetails(Boolean moreDetails) {
		this.moreDetails = moreDetails;
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		df = DateFormat.getDateFormat(getActivity().getApplicationContext());
		View rootView = inflater.inflate(R.layout.detail_key_fragment,
				container, false);

		setRetainInstance(true);
		if (savedInstanceState != null && keyId == 0) {
			keyId = savedInstanceState.getInt(KEY_ID);
		}

		Log.i(PKITrustNetworkActivity.TAG, "KEY DETAILS: " + keyId);
		Log.i(PKITrustNetworkActivity.TAG, "SavedInstance: "
				+ savedInstanceState);

		if (personalKeyController == null) {
			personalKeyController = new PersonalKeyController(getActivity());

		}
		if (subjectController == null) {
			subjectController = new SubjectController(getActivity());
		}
		try {

			key = personalKeyController.getById(keyId);

			SubjectDAO sub;
			try {
				sub = subjectController.getById(key.getSubjectId());

				((TextView) rootView.findViewById(R.id.txtDetailsKeyOwnerName))
						.setText(sub.getName());
			} catch (DBException e) {
				((TextView) rootView.findViewById(R.id.txtDetailsKeyOwnerName))
						.setText((""));
			}
			((TextView) rootView.findViewById(R.id.txtDetailsKeyId))
					.setText(Integer.toString(key.getId()));

			((TextView) rootView.findViewById(R.id.txtDetailsKeyComment))
					.setText(key.getComment());

			((TextView) rootView.findViewById(R.id.txtDetailsKeyType))
					.setText(key.getKeyTypeStr(PKITrustNetworkActivity.LAN));

			((TextView) rootView.findViewById(R.id.txtDetailsKeyUniqueID))
					.setText(key.getKeyID());

			Date creationDate = key.getCreationDate();
			if (creationDate.equals(new Date(0))) {
				((TextView) rootView
						.findViewById(R.id.txtDetailsKeyCreationDate))
						.setText(R.string.lblNotAvailable);
			} else {
				((TextView) rootView
						.findViewById(R.id.txtDetailsKeyCreationDate))
						.setText(df.format(key.getCreationDate()));
			}

			((TextView) rootView.findViewById(R.id.lblImgSeeMoreDetails))
					.setOnClickListener(new View.OnClickListener() {

						@Override
						public void onClick(View v) {
							if (!key.getId().equals(0)) {
								moreDetails = Boolean.TRUE;
								((OnClickDetailsListener) getActivity())
										.onMoreDetails(key);
							}
						}
					});

		} catch (DBException e) {
			e.printStackTrace();
		}

		return rootView;
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
		outState.putInt(KEY_ID, keyId);
	}

	/**
	 * Interface that handles the click on SeeDetails for
	 * {@link KeyObjectFragment}, button this should be implemented by the
	 * Activity that holds the fragment
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 02/09/2012
	 * @version 1.0
	 */
	public interface OnClickDetailsListener {
		/**
		 * See more detail action
		 * 
		 * @param key
		 *            The key that must be used for load the details
		 */
		void onMoreDetails(PersonalKeyDAO key);
	}
}
