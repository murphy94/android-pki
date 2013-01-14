/**
 *  Created on  : 29/09/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	
 */
package cinvestav.pki.android.trustednetwork.common;

import java.util.Calendar;
import java.util.Date;

import android.app.DatePickerDialog;
import android.app.Dialog;
import android.os.Bundle;
import android.support.v4.app.DialogFragment;
import android.widget.DatePicker;

/**
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 29/09/2012
 * @version 1.0
 */
public class DatePickerFragment extends DialogFragment implements
		DatePickerDialog.OnDateSetListener {

	/**
	 * Listener for OnDataSetListener on the dialog fragment, the implementation
	 * of this interface will determine what to do when the date is setted
	 */
	protected OnDataSetListener onDataSetListener;
	protected Date initialDate;

	/**
	 * @return the onDataSetListener
	 */
	public OnDataSetListener getOnDataSetListener() {
		return onDataSetListener;
	}

	/**
	 * @param onDataSetListener
	 *            the onDataSetListener to set
	 */
	public void setOnDataSetListener(OnDataSetListener onDataSetListener) {
		this.onDataSetListener = onDataSetListener;
	}

	/**
	 * @return the initialDate
	 */
	public Date getInitialDate() {
		return initialDate;
	}

	/**
	 * @param initialDate
	 *            the initialDate to set
	 */
	public void setInitialDate(Date initialDate) {
		this.initialDate = initialDate;
	}

	/**
	 * creates a new instance of this dialog using a dateSet Listener and a
	 * initial date
	 * 
	 * @param initialDate
	 *            date that should be shown in the DatePicker
	 * @param onDataSetListener
	 *            Listener to be called when the date is selected
	 * @return a new instance of DatePickerFragment
	 */
	public static DatePickerFragment newInstance(Date initialDate,
			OnDataSetListener onDataSetListener) {
		DatePickerFragment f = new DatePickerFragment();
		f.setInitialDate(initialDate);
		f.setOnDataSetListener(onDataSetListener);
		return f;
	}

	@Override
	public Dialog onCreateDialog(Bundle savedInstanceState) {
		// Use the current date as the default date in the picker
		final Calendar c = Calendar.getInstance();
		c.setTime(initialDate);
		int year = c.get(Calendar.YEAR);
		int month = c.get(Calendar.MONTH);
		int day = c.get(Calendar.DAY_OF_MONTH);

		// Create a new instance of DatePickerDialog and return it
		return new DatePickerDialog(getActivity(), this, year, month, day);
	}

	public void onDateSet(DatePicker view, int year, int month, int day) {
		// Do something with the date chosen by the user
		final Calendar c = Calendar.getInstance();
		c.set(year, month, day);
		onDataSetListener.onDataSet(c.getTime());
	}

	/**
	 * Interface to determine what to do when the date is chosen by the user
	 * 
	 * @author Ing. Javier Silva Pérez - [javier]
	 * @since 29/09/2012
	 * @version 1.0
	 */
	public interface OnDataSetListener {
		/**
		 * To be called from {@link DatePickerFragment} after the user chose the
		 * date
		 * 
		 * @param date
		 *            Selected date
		 */
		public void onDataSet(Date date);
	}
}
