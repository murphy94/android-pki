/**
 *  Created on  : 27/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Creates a custom list adapter for key List Fragment, so more details could be shown in the list
 */
package cinvestav.pki.android.trustednetwork.adapter;

import java.util.Date;
import java.util.List;

import android.app.Activity;
import android.content.Context;
import android.text.format.DateFormat;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;
import cinvestav.android.pki.db.dao.PersonalKeyDAO;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

/**
 * Creates a custom list adapter for key List Fragment, so more details could be
 * shown in the list
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 27/09/2012
 * @version 1.0
 */
public class KeyListAdapter extends BaseAdapter {

	private Context context;
	private List<PersonalKeyDAO> data;
	private int selectedId;
	private int selectedPosition;
	private static java.text.DateFormat df;

	/**
	 * 
	 */
	public KeyListAdapter(Context context, List<PersonalKeyDAO> data) {
		this.context = context;
		this.data = data;
		selectedPosition = -1;
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
		this.selectedId = selected_id;
	}

	public int getSelectedId() {
		return selectedId;
	}

	/**
	 * @return the selectedPosition
	 */
	public int getSelectedPosition() {
		return selectedPosition;
	}

	/**
	 * @param selectedPosition
	 *            the selectedPosition to set
	 */
	public void setSelectedPosition(int selectedPosition) {
		this.selectedPosition = selectedPosition;
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

		if (df == null) {
			df = DateFormat.getDateFormat(context);
		}
		LayoutInflater inflater = ((Activity) context).getLayoutInflater();
		if (convertView == null) {
			vi = inflater.inflate(R.layout.list_row_key, null);

			holder = new ViewHolder();
			// Key Type
			holder.keyType = (TextView) vi.findViewById(R.id.txtKeyType);
			// Key Comment
			holder.keyComment = (TextView) vi.findViewById(R.id.txtKeyComment);
			// Key Creation Date
			holder.keyCreationDate = (TextView) vi
					.findViewById(R.id.txtKeyCreation);

			// Key Unique Id
			holder.keyUniqueId = (TextView) vi
					.findViewById(R.id.txtKeyUniqueId);

			vi.setTag(holder);
		} else {
			holder = (ViewHolder) vi.getTag();
		}

		PersonalKeyDAO key = data.get(position);
		holder.keyType.setText(key.getKeyTypeStr(PKITrustNetworkActivity.LAN));

		holder.keyComment.setText(context.getString(R.string.lblKeyComment)
				+ ": "
				+ (key.getComment() != null ? key.getComment() : context
						.getString(R.string.lblNotAvailable)));
		holder.keyUniqueId.setText(context.getString(R.string.lblKeyID) + " : "
				+ key.getKeyID());

		Date creationDate = key.getCreationDate();
		if (creationDate.equals(new Date(0))) {
			holder.keyCreationDate.setText(context
					.getString(R.string.lblKeyCreationDate)
					+ ": "
					+ context.getString(R.string.lblNotAvailable));
		} else {
			holder.keyCreationDate.setText(context
					.getString(R.string.lblKeyCreationDate)
					+ ": "
					+ df.format(key.getCreationDate()));
		}

		if (key.getId().equals(selectedId)) {
			selectedPosition = position;
			vi.setBackgroundResource(R.color.android_green);
		} else {
			vi.setBackgroundResource(0);
		}
		return vi;
	}

	static class ViewHolder {
		TextView keyType;
		TextView keyComment;
		TextView keyUniqueId;
		TextView keyCreationDate;
	}

}
