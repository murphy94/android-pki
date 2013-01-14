/**
 *  Created on  : 23/10/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Creates a custom selectable list adapter for CRL List Fragment, so more 
 *  details could be shown in the list
 */
package cinvestav.pki.android.trustednetwork.adapter;

import java.util.List;

import android.app.Activity;
import android.content.Context;
import android.text.format.DateFormat;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.TextView;
import cinvestav.android.pki.db.dao.CRLDAO;
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.pki.android.trustednetwork.R;

/**
 * Creates a custom selectable list adapter for CRL List Fragment, so more
 * details could be shown in the list
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 23/10/2012
 * @version 1.0
 */
public class CRLSelectableListAdapter extends BaseAdapter {

	private Context context;
	private List<CRLDAO> data;
	private static java.text.DateFormat df;
	private int selected_id;

	/**
	 * 
	 */
	public CRLSelectableListAdapter(Context context, List<CRLDAO> data) {
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
		if (df == null) {
			df = DateFormat.getDateFormat(context);
		}

		final ViewHolder holder;
		View vi = convertView;
		LayoutInflater inflater = ((Activity) context).getLayoutInflater();
		if (convertView == null) {
			vi = inflater.inflate(R.layout.list_row_crl, null);

			holder = new ViewHolder();
			// Issuer Name
			holder.txtIssuerName = (TextView) vi
					.findViewById(R.id.txtIssuerName);

			// Serial Number
			holder.txtSerialNumber = (TextView) vi
					.findViewById(R.id.txtSerialNumber);
			// Publish Date
			holder.txtPublishDate = (TextView) vi
					.findViewById(R.id.txtPublishDate);

			// See Details
			holder.seeDetailsImg = (ImageView) vi
					.findViewById(R.id.imgSeeDetails);

			vi.setTag(holder);
		} else {
			holder = (ViewHolder) vi.getTag();
		}

		CRLDAO crl = new CRLDAO();
		crl = data.get(position);
		CertificateDAO issuerCert = crl.getIssuerCertificate();
		if (issuerCert != null) {
			holder.txtIssuerName.setText(issuerCert.getOwner()
					.getName());
		} else {
			holder.txtIssuerName.setText(R.string.lblUnkwnown);
		}

		holder.txtSerialNumber.setText(crl.getSerialNumber().toString());
		holder.txtPublishDate.setText(df.format(crl.getPublishDate()));
		holder.seeDetailsImg.setVisibility(View.GONE);
		
		if (crl.getId().equals(selected_id)) {
			vi.setBackgroundResource(R.color.android_green);
		} else {
			vi.setBackgroundResource(0);
		}
		
		return vi;
	}

	static class ViewHolder {
		TextView txtIssuerName;
		TextView txtSerialNumber;
		TextView txtPublishDate;
		ImageView seeDetailsImg;
	}

}
