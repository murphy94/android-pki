/**
 *  Created on  : 22/10/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Creates a custom list adapter for CRL List Fragment, so more details could be shown in the list
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
 * Creates a custom list adapter for CRL List Fragment, so more details could be
 * shown in the list
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 22/10/2012
 * @version 1.0
 */
public class CRLListAdapter extends BaseAdapter {

	private Context context;
	private List<CRLDAO> data;
	private static java.text.DateFormat df;

	/**
	 * 
	 */
	public CRLListAdapter(Context context, List<CRLDAO> data) {
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
		if (df == null) {
			df = DateFormat.getDateFormat(context);
		}
		
		View vi = convertView;
		LayoutInflater inflater = ((Activity) context).getLayoutInflater();
		if (convertView == null)
			vi = inflater.inflate(R.layout.list_row_crl, null);

		// Issuer Name
		TextView txtCRLIssuerName = (TextView) vi
				.findViewById(R.id.txtIssuerName);
		// Serial Number
		TextView txtCRLSerialNumber = (TextView) vi
				.findViewById(R.id.txtSerialNumber);

		// Publish Date
		TextView txtCRLPublishDate = (TextView) vi
				.findViewById(R.id.txtPublishDate);

		ImageView seeDetailsImg = (ImageView) vi
				.findViewById(R.id.imgSeeDetails);

		CRLDAO crl = new CRLDAO();
		crl = data.get(position);
		CertificateDAO issuerCert = crl.getIssuerCertificate();
		if (issuerCert != null) {
			txtCRLIssuerName.setText(crl.getIssuerCertificate().getOwner()
					.getName());
		} else {
			txtCRLIssuerName.setText(R.string.lblUnkwnown);
		}

		txtCRLSerialNumber.setText(crl.getSerialNumber().toString());
		txtCRLPublishDate.setText(df.format(crl.getPublishDate()));
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
		/*Intent intent = new Intent(context, KeyDetailsActivity.class);
		List<PersonalKeyDAO> keyList = data.get(position).getKeyList();
		int[] idArray = new int[keyList.size()];
		for (int i = 0; i < keyList.size(); i++) {
			idArray[i] = keyList.get(i).getId();
		}
		intent.putExtra(KeyDetailsActivity.EXTRA_ID_ARRAY, idArray);
		intent.putExtra(KeyDetailsActivity.EXTRA_CURRENT_ITEM, 0);
		context.startActivity(intent);*/
	}

}
