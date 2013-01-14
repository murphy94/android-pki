/**
 *  Created on  : 30/08/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Creates a custom list adapter for key List Fragment, so more details could be shown in the list
 */
package cinvestav.pki.android.trustednetwork.adapter;

import java.util.List;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.TextView;
import cinvestav.android.pki.db.dao.PersonalKeyDAO;
import cinvestav.android.pki.db.dao.SubjectDAO;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.details.KeyDetailsActivity;

/**
 * Creates a custom list adapter for key List Fragment, so more details could be
 * shown in the list
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 30/08/2012
 * @version 1.0
 */
public class SubjectListAdapter extends BaseAdapter {

	private Context context;
	private List<SubjectDAO> data;

	/**
	 * 
	 */
	public SubjectListAdapter(Context context, List<SubjectDAO> data) {
		this.context = context;
		this.data = data;
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

		TextView keyOwnerName = (TextView) vi.findViewById(R.id.txtOwnerName); // ownerName

		// Owner device ID
		TextView keyOwnerDevice = (TextView) vi
				.findViewById(R.id.lblOwnerDeviceId);
		TextView lblKeyCount = (TextView) vi.findViewById(R.id.txtCount); // key
																			// count

		ImageView seeDetailsImg = (ImageView) vi
				.findViewById(R.id.imgSeeDetails);

		SubjectDAO subject = new SubjectDAO();
		subject = data.get(position);
		keyOwnerName.setText(subject.getName());
		keyOwnerDevice.setText(context.getString(R.string.lblDeviceId)
				+ ": "
				+ (subject.getDeviceID() != null ? subject.getDeviceID()
						: context.getString(R.string.lblNotAvailable)));
		lblKeyCount.setText(subject.getKeyList().size() + " "
				+ context.getString(R.string.lblKeyCount));
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
		Intent intent = new Intent(context, KeyDetailsActivity.class);
		List<PersonalKeyDAO> keyList = data.get(position).getKeyList();
		int[] idArray = new int[keyList.size()];
		for (int i = 0; i < keyList.size(); i++) {
			idArray[i] = keyList.get(i).getId();
		}
		intent.putExtra(KeyDetailsActivity.EXTRA_ID_ARRAY, idArray);
		intent.putExtra(KeyDetailsActivity.EXTRA_CURRENT_ITEM, 0);
		context.startActivity(intent);
	}

}
