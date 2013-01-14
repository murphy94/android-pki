/**
 *  Created on  : 30/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Creates a custom list adapter for certificate List Fragment, so more details could be shown in the list
 */
package cinvestav.pki.android.trustednetwork.adapter;

import java.util.List;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.TextView;
import cinvestav.android.pki.db.dao.SubjectDAO;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.details.CertificateDetailsActivity;

/**
 * Creates a custom list adapter for certificate List Fragment, so more details
 * could be shown in the list
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 30/08/2012
 * @version 1.0
 */
public class SubjectWithCertificatesListAdapter extends BaseAdapter {

	private Context context;
	private List<SubjectDAO> data;
	SparseArray<Integer> certificateCount;

	/**
	 * Default constructor, for construct a certificate list adapter
	 * 
	 * @param context
	 *            Application context
	 * @param data
	 *            List of subject to be shown in the list adapter
	 * @param certificateCount
	 *            Array that contains the owned certificate count for each
	 *            subject in the list
	 */
	public SubjectWithCertificatesListAdapter(Context context,
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

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.widget.Adapter#getView(int, android.view.View,
	 * android.view.ViewGroup)
	 */
	@Override
	public View getView(final int position, View convertView, ViewGroup parent) {
		View vi = convertView;
		LayoutInflater inflater = ((Activity) context).getLayoutInflater();
		if (convertView == null)
			vi = inflater.inflate(R.layout.list_row_subject, null);

		// ownerName
		TextView certOwnerName = (TextView) vi.findViewById(R.id.txtOwnerName);

		// Owner device ID
		TextView certOwnerDevice = (TextView) vi
				.findViewById(R.id.lblOwnerDeviceId);

		// Certificate Count
		TextView lblCertCount = (TextView) vi.findViewById(R.id.txtCount);

		ImageView seeDetailsImg = (ImageView) vi
				.findViewById(R.id.imgSeeDetails);

		SubjectDAO subject = new SubjectDAO();
		subject = data.get(position);

		// Setting all values in listview
		certOwnerName.setText(subject.getName());
		certOwnerDevice.setText(context.getString(R.string.lblDeviceId)
				+ ": "
				+ (subject.getDeviceID() != null ? subject.getDeviceID()
						: context.getString(R.string.lblNotAvailable)));

		Integer lblCertCountValue = 0;
		lblCertCountValue = certificateCount.get(subject.getId());
		lblCertCount.setText(lblCertCountValue + " "
				+ context.getString(R.string.lblCertCount));
		seeDetailsImg.setClickable(true);
		seeDetailsImg.setOnClickListener(new View.OnClickListener() {

			@Override
			public void onClick(View v) {
				onClickSeeDetails(position);
			}
		});
		return vi;

	}

	protected void onClickSeeDetails(int position) {
		Intent intent = new Intent(context, CertificateDetailsActivity.class);
		int ownerId = data.get(position).getId();
		intent.putExtra(CertificateDetailsActivity.EXTRA_OWNER_ID, ownerId);
		intent.putExtra(CertificateDetailsActivity.EXTRA_CURRENT_ITEM, 0);
		context.startActivity(intent);

	}

}
