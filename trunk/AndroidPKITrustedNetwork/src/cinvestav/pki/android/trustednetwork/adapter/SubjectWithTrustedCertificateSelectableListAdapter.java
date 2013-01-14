/**
 *  Created on  : 23/10/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Creates a custom selectable list adapter for certificate List Fragment, for
 * subjects with trusted certificate list, so more details could be shown in the
 * list
 */
package cinvestav.pki.android.trustednetwork.adapter;

import java.util.List;

import android.app.Activity;
import android.content.Context;
import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.TextView;
import cinvestav.android.pki.db.dao.SubjectDAO;
import cinvestav.pki.android.trustednetwork.R;

/**
 * Creates a custom selectable list adapter for certificate List Fragment, for
 * subjects with trusted certificate list, so more details could be shown in the
 * list
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 23/10/2012
 * @version 1.0
 */
public class SubjectWithTrustedCertificateSelectableListAdapter extends
		BaseAdapter {

	private Context context;
	private List<SubjectDAO> data;
	SparseArray<Integer> certificateCount;
	private int selected_id;

	/**
	 * Default constructor, for construct a certificate list adapter
	 * 
	 * @param context
	 *            Application context
	 * @param data
	 *            List of subject to be shown in the list adapter
	 * @param certificateCount
	 *            Array with the total count of certificates on each list
	 * @param certificateController
	 *            Certificate controller object
	 */
	public SubjectWithTrustedCertificateSelectableListAdapter(Context context,
			List<SubjectDAO> data, SparseArray<Integer> certificateCount) {
		this.context = context;
		this.data = data;
		this.certificateCount = certificateCount;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.widget.Adapter#getCount()
	 */
	@Override
	public int getCount() {
		return data.size();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.widget.Adapter#getItem(int)
	 */
	@Override
	public Object getItem(int position) {
		return data.get(position);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.widget.Adapter#getItemId(int)
	 */
	@Override
	public long getItemId(int position) {
		return data.get(position).getId();
	}

	public void setSelectedId(int selected_id) {
		this.selected_id = selected_id;
	}

	public int getSelectedId() {
		return selected_id;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.widget.Adapter#getView(int, android.view.View,
	 * android.view.ViewGroup)
	 */
	@Override
	public View getView(final int position, View convertView, ViewGroup parent) {
		final ViewSubjectWithTrustedCertificates holder;
		View vi = convertView;
		LayoutInflater inflater = ((Activity) context).getLayoutInflater();
		if (convertView == null) {
			vi = inflater.inflate(R.layout.list_row_subject_with_trusted_certs,
					null);
			holder = new ViewSubjectWithTrustedCertificates();

			// ownerName
			holder.certHolderName = (TextView) vi
					.findViewById(R.id.txtOwnerName);

			// Owner device ID
			holder.certHolderDevice = (TextView) vi
					.findViewById(R.id.lblOwnerDeviceId);

			// Certificate Count
			holder.lblCertCount = (TextView) vi.findViewById(R.id.txtCount);

			holder.seeDetailsImg = (ImageView) vi
					.findViewById(R.id.imgSeeDetails);

			vi.setTag(holder);
		} else {
			holder = (ViewSubjectWithTrustedCertificates) vi.getTag();
		}

		SubjectDAO subject = new SubjectDAO();
		subject = data.get(position);

		// Setting all values in listview
		holder.certHolderName.setText(subject.getName());
		holder.certHolderDevice.setText(context.getString(R.string.lblDeviceId)
				+ ": "
				+ (subject.getDeviceID() != null ? subject.getDeviceID()
						: context.getString(R.string.lblNotAvailable)));

		Integer lblCertCountValue = 0;
		lblCertCountValue = certificateCount.get(subject.getId());

		holder.lblCertCount.setText(lblCertCountValue + " "
				+ context.getString(R.string.lblTrustedCertCount));

		// Hide details button
		holder.seeDetailsImg.setVisibility(View.GONE);

		if (subject.getId().equals(selected_id)) {
			vi.setBackgroundResource(R.color.android_green);
		} else {
			vi.setBackgroundResource(0);
		}

		return vi;

	}

	static class ViewSubjectWithTrustedCertificates {
		TextView certHolderName;
		TextView certHolderDevice;
		TextView lblCertCount;
		ImageView seeDetailsImg;
	}

}
