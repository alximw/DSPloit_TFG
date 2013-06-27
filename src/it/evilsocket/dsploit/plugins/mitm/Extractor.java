package it.evilsocket.dsploit.plugins.mitm;

import it.evilsocket.dsploit.MainActivity;
import it.evilsocket.dsploit.R;
import it.evilsocket.dsploit.core.ManagedReceiver;
import it.evilsocket.dsploit.core.System;
import it.evilsocket.dsploit.net.Endpoint;
import it.evilsocket.dsploit.net.NetworkDiscovery;

import java.net.InetAddress;
import java.util.ArrayList;

import android.app.AlertDialog;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.Toast;
import android.widget.ToggleButton;

import com.actionbarsherlock.app.SherlockActivity;
import com.actionbarsherlock.view.MenuItem;

public class Extractor extends SherlockActivity {

	String DEBUG_TAG="EXTRACTORUC3M";
	
	private NetworkDiscovery		discover					=null;
	private ToggleButton			startStopListing			=null;
	private ListView 				targetList					=null;
	private boolean					runningScan					=false;
	
	
	

	
	/*
	 * This will be the object which contained on each
	 * listview item
	 */
	public class EndPointTarget extends Endpoint 
	{

		public EndPointTarget(InetAddress address, byte[] hardware) {
			super(address, hardware);
		}
		
		
		public EndPointTarget(String address, String hardware) {
			super(address, hardware);
		}

	}
	
	
	/*
	 * ListAdapter for the new listItem
	 */
	public class EndPointTargetAdapter extends ArrayAdapter<EndPointTarget>
	{

		private int 					  layoutId = 0;
		private ArrayList <EndPointTarget > targets = null;
		
		public EndPointTargetAdapter(int layout){
			super(Extractor.this,layout);
			 layout=layout;
			 targets= new ArrayList<EndPointTarget>();
			
			
		}
		
		 
	}
	
	
	
	
	
	
	
	@Override
	protected void onCreate(Bundle savedInstanceState)
	{
		// TODO Auto-generated method stub
		super.onCreate(savedInstanceState);
        setTitle( System.getCurrentTarget() + " > MITM > Xtractor" );
        setContentView(R.layout.plugin_mitm_extractor);
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        
        startStopListing =(ToggleButton)findViewById(R.id.startTargetListingButton);
        targetList =(ListView)findViewById(R.id.targetList);

        startStopListing.setOnClickListener(new OnClickListener() {
			
        	@Override
        	public void onClick(View v) {
        		
        	}
        });
        
        AlertDialog howTo =new AlertDialog.Builder(this).create();
        howTo.setTitle("How To:");
        howTo.setMessage("When you press the button, the list of connected targets will appear. Pick one from the list.");
        howTo.setButton(DialogInterface.BUTTON_NEUTRAL, "Understood!", new DialogInterface.OnClickListener() {
			
			@Override
			public void onClick(DialogInterface dialog, int which) {
				dialog.cancel();
			}
		});
        howTo.show();

	}


	

	/*
	 * 
	 * this two methods do the same:
	 * 
	 * ->onOptionsItemSelected takes you to the parent activity when actionBar arrow is pressed
	 * 
	 * ->onbackPressed does the same but when  the back button on the device is pressed
	 * 
	 * @see com.actionbarsherlock.app.SherlockActivity#onOptionsItemSelected(android.view.MenuItem)
	 */
	
	public boolean onOptionsItemSelected( MenuItem item ) 
	{    
		switch( item.getItemId() ) 
		{        
			case android.R.id.home:            
	         
				onBackPressed();
				
				return true;
	    	  
			default:            
				return super.onOptionsItemSelected(item);    
	   }
	}
	
	public void onBackPressed() {
	    super.onBackPressed();
	    overridePendingTransition(R.anim.slide_in_left, R.anim.slide_out_left);	    	    
	}
}
