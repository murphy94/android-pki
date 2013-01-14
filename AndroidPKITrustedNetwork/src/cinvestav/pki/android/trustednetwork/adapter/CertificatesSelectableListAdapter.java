/**
 *  Created on  : 03/10/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	Creates a custom list adapter for certificate List Fragment, so more details could be shown in the list
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
import android.widget.TextView;
import cinvestav.android.pki.db.controller.CertificateController;
import cinvestav.android.pki.db.dao.CertificateDAO;
import cinvestav.pki.android.trustednetwork.R;
import cinvestav.pki.android.trustednetwork.main.PKITrustNetworkActivity;

/**
 * Creates a custom list adapter for certificate List Fragment, so more details
 * could be shown in the list.
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 03/10/2012
 * @version 1.0
 */
public class CertificatesSelectableListAdapter extends BaseAdapter {

	private Context context;
	private List<CertificateDAO> data;
	private static java.text.DateFormat df;
	CertificateController certificateController;
	private int selectedId;
	private int selectedPosition;

	/**
	 * Default constructor, for construct a certificate list adapter
	 * 
	 * @param context
	 *            Application context
	 * @param data
	 *            List of Certificate to be shown in the list adapter
	 * @param certificateController
	 *            Certificate controller object
	 */
	public CertificatesSelectableListAdapter(Context context, List<CertificateDAO> data,
			CertificateController certificateController) {
		this.context = context;
		this.data = data;
		this.certificateController = certificateController;
		selectedId = -1;
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

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.widget.Adapter#getView(int, android.view.View,
	 * android.view.ViewGroup)
	 */
	@Override
	public View getView(final int position, View convertView, ViewGroup parent) {
		View vi = convertView;
		final ViewCertificate holder;
		LayoutInflater inflater = ((Activity) context).getLayoutInflater();

		// If convertView is null, the view is been created, so we need to get
		// its elements and saved the into a holder so they can be preserved and
		// loaded more efficiently, because the method findbyid is called only
		// the first time
		if (convertView == null) {
			vi = inflater.inflate(R.layout.list_row_cert, null);

			holder = new ViewCertificate();

			// Holder Alias
			holder.holderAlias = (TextView) vi
					.findViewById(R.id.txtCertificateHolderAlias);

			// Certificate Serial Number
			holder.serialNumber = (TextView) vi
					.findViewById(R.id.txtCertificateSerialNumber);

			// Certificate Status (DB)
			holder.status = (TextView) vi
					.findViewById(R.id.txtCertificateStatus);

			// Certificate Status Last Update(DB)
			holder.statusUpdate = (TextView) vi
					.findViewById(R.id.txtCertificateStatusUpdate);
			// Certificate Issuer Alias
			holder.issuerAlias = (TextView) vi
					.findViewById(R.id.txtCertificateIssuerAlias);

			vi.setTag(holder);

			if (df == null) {
				df = DateFormat.getDateFormat(context);
			}
		} else {
			holder = (ViewCertificate) vi.getTag();
		}

		CertificateDAO certificate = new CertificateDAO();
		certificate = data.get(position);
		certificateController.getCertificateDetails(certificate);

		String holderName;
		String serialNumber;
		String status;
		String statusUpdate;
		String issuerAlias;
		// Check if the certificate has id = 0 - means that the certificate is
		// unknown
		if (certificate.getId().equals(0)) {
			// Fill with unknown or not available information values
			holderName = context.getString(R.string.lblUnkwnown);
			serialNumber = context.getString(R.string.lblNotAvailable);
			status = context.getString(R.string.lblNotAvailable);
			statusUpdate = context.getString(R.string.lblNotAvailable);
			issuerAlias = context.getString(R.string.lblUnkwnown);
		} else {
			// Fill with certificate information
			holderName = certificate.getOwner().getName();
			serialNumber = certificate.getSerialNumber() + "";
			status = certificate.getStatusStr(PKITrustNetworkActivity.LAN);
			statusUpdate = df.format(certificate.getLastStatusUpdateDate());
			CertificateDAO caCert = certificate.getCaCertificate();
			if (caCert != null && !caCert.getId().equals(0)) {
				issuerAlias = certificate.getCaCertificate().getOwner()
						.getName();
			} else {
				issuerAlias = context.getString(R.string.lblUnkwnown);
			}
		}

		// Setting all values in listview

		holder.holderAlias.setText(holderName);
		holder.serialNumber.setText(context
				.getString(R.string.lblCertificateSerialNumber)
				+ ": "
				+ serialNumber);
		holder.status.setText(status);
		holder.statusUpdate.setText("(" + statusUpdate + ")");
		holder.issuerAlias.setText(context
				.getString(R.string.lblCertificateCASubjectName)
				+ ": "
				+ issuerAlias);

		if (certificate.getId().equals(selectedId)) {
			selectedPosition = position;
			vi.setBackgroundResource(R.color.android_green);
		} else {
			vi.setBackgroundResource(0);
		}
		return vi;

	}

	static class ViewCertificate {
		TextView holderAlias;
		TextView serialNumber;
		TextView status;
		TextView statusUpdate;
		TextView issuerAlias;
	}

}
