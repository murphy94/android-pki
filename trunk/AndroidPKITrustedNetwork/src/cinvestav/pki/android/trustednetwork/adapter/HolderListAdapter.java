/**
 *  Created on  : 29/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Creates a custom list adapter for holder List Fragment, so more details could be shown in the list
 */
package cinvestav.pki.android.trustednetwork.adapter;

import java.util.List;

import android.app.Activity;
import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;
import cinvestav.android.pki.db.dao.SubjectDAO;
import cinvestav.pki.android.trustednetwork.R;

/**
 * Creates a custom list adapter for holder List Fragment, so more details could
 * be shown in the list
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 29/09/2012
 * @version 1.0
 */
public class HolderListAdapter extends BaseAdapter {

	private Context context;
	private List<SubjectDAO> data;
	private int selected_id;

	/**
	 * 
	 */
	public HolderListAdapter(Context context, List<SubjectDAO> data) {
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

		final ViewHolder holder;

		View vi = convertView;

		LayoutInflater inflater = ((Activity) context).getLayoutInflater();
		if (convertView == null) {
			vi = inflater.inflate(R.layout.list_row_holder, null);

			holder = new ViewHolder();
			// ownerName
			holder.keyHolderName = (TextView) vi
					.findViewById(R.id.txtHolderName);

			// Key Count
			holder.keyHolderTotal = (TextView) vi.findViewById(R.id.txtCount);
			// ownerDeviceID
			holder.keyHolderDevice = (TextView) vi
					.findViewById(R.id.lblHolderDeviceId);

			vi.setTag(holder);
		} else {
			holder = (ViewHolder) vi.getTag();
		}

		SubjectDAO subject = data.get(position);
		holder.keyHolderName.setText(subject.getName());
		holder.keyHolderTotal.setText(subject.getKeyList().size() + " "
				+ context.getString(R.string.lblKeyCount));
		holder.keyHolderDevice.setText(context
				.getString(R.string.lblDeviceId)
				+ ": "
				+ (subject.getDeviceID() != null ? subject.getDeviceID()
						: context.getString(R.string.lblNotAvailable)));

		if (subject.getId().equals(selected_id)) {
			vi.setBackgroundResource(R.color.android_green);
		} else {
			vi.setBackgroundResource(0);
		}
		return vi;
	}

	static class ViewHolder {
		TextView keyHolderName;
		TextView keyHolderDevice;
		TextView keyHolderTotal;
	}

}
