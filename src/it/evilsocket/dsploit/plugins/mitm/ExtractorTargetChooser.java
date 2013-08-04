package it.evilsocket.dsploit.plugins.mitm;

import it.evilsocket.dsploit.R;

import it.evilsocket.dsploit.core.System;
import it.evilsocket.dsploit.core.Shell.OutputReceiver;
import it.evilsocket.dsploit.net.Endpoint;
import it.evilsocket.dsploit.plugins.mitm.SpoofSession.OnSessionReadyListener;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.Base64;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.ToggleButton;

import com.actionbarsherlock.app.SherlockActivity;
import com.actionbarsherlock.view.MenuItem;

public class ExtractorTargetChooser extends  SherlockActivity {

	static String DEBUG_TAG="TFG_UC3M";
	static boolean DEBUG_ENABLED=false;
	
	 //views used on this activity
	private ToggleButton			startStopListing			=null;
	private ListView 				targetList					=null;
	
	//spoofSession object->create an ARP spoof sesion
	private SpoofSession			spoofSession				=null;

	
	//save the state of the target search
	private boolean lookingForTargets							=false;
	
	
	/*
	 * This pcap filter will show only packets which dest and src ip are not localhost and
	 * the current protocol it's not ARP, will show the packet's ethernet header too. 
	 */
	private static final String  PCAP_FILTER = " -e not '(src host localhost or dst host localhost or arp)'";
	
	//This pcap filter will show only http traffic including its ethernet header  
	private static final String PCAP_FILTER_HTTP= "-eA '(dst port 80 or src port 80)' ";
	
	//static String regexb="^.+length\\s+(\\d+)\\)\\s+([\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3})\\.[^\\s]+\\s+>\\s+([\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3})\\.[^\\:]+:.+";
	//static String regexd="^.+(([0-9a-fA-F]{2}[\\:-]){5}([0-9A-Fa-f]{2}))\\s\\(.+\\s.+\\)\\s\\>\\s(([0-9a-fA-F]{2}[\\:-]){5}([0-9A-Fa-f]{2})).+";

	/*
	 * Regex that accepts standard packet including SRC and DST ip/MAC and payload 
	 */
	static String regexc="^.+(([0-9a-fA-F]{2}[\\:-]){5}([0-9A-Fa-f]{2}))\\s\\(.+\\s.+\\)\\s\\>\\s(([0-9a-fA-F]{2}[\\:-]){5}([0-9A-Fa-f]{2})).+length\\s+(\\d+)\\)\\s+([\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3})\\.[^\\s]+\\s+>\\s+([\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3})\\.[^\\:]+:.+";
	
	//pattern used to compile regexc
	private static Pattern 			PARSER 	 					=null; 

	private static EndPointTargetAdapter adapter				=null;
	

	
	/*
	 * This object will contain the information about the
	 * endpoints showed on the target list.
	 */
	public  class EndPointTarget extends Endpoint
	{

		public EndPointTarget(InetAddress address, byte[] hardware) {
			super(address, hardware);
		}
		
		
		public EndPointTarget(String address, String hardware) {
			super(address, hardware);
		}


		

	}
	

	
	public static class EndPointTargetAdapter extends ArrayAdapter<EndPointTarget>
	{
		int rowLayout;
		Context adapterContext	=	null;
		ArrayList<EndPointTarget> targetList;
		static class ElementHolder{
			TextView macAddres;
			TextView IPAddres;
			TextView macVendor;
			
		}
		
		public EndPointTargetAdapter(Context context,int layout) {
			super(context, layout);
			this.adapterContext=context;
			this.rowLayout=layout;
			targetList	=	new ArrayList<EndPointTarget>();
		}
		
		public synchronized EndPointTarget getListElement(int index){
			EndPointTarget target=targetList.get(index);
			return target;
		}

		public int getCount(){
			return targetList.size();
		}
		public  View getView(int position, View convertView, ViewGroup parent) {
			
				//holder for the list element views
			ElementHolder holder;
				//convertView saves the view of the current element if it has benn inflated before
			View listElement=convertView;
			
				/*
				 * If this is the first time the element is inflated (convertiview==NULL)
				 * inflate it and create a new holder on which you can save the view references
				 * instead of search them in the layout tree.
				 */
			if(listElement==null)
			{
			
				LayoutInflater inflater=(LayoutInflater) adapterContext.getSystemService(LAYOUT_INFLATER_SERVICE);
				listElement=inflater.inflate(rowLayout, null,false );
			
				holder=new ElementHolder();
				holder.IPAddres=(TextView)listElement.findViewById(R.id.IPAddresField);
				holder.macAddres=(TextView)listElement.findViewById(R.id.MacAddresField);
				holder.macVendor=(TextView)listElement.findViewById(R.id.MacVendorField);
				
				listElement.setTag(holder);
			}else{
				
				// if the layout has been inflated before, we just retrieve the holder...
				 
				holder=(ElementHolder)listElement.getTag();
				
			}
				
			
				//..and fill the views with our data.
			
			holder.IPAddres.setText(getListElement(position).getAddress().toString().replace("/", ""));
			holder.macAddres.setText(targetList.get(position).getHardwareAsString());
			if(System.getMacVendor(targetList.get(position).getHardware())==null)
			{
				holder.macVendor.setText("Unknown MAC vendor");	
			}else{
			holder.macVendor.setText(System.getMacVendor(targetList.get(position).getHardware()));
			}
			showDebug(getListElement(position).getAddress().toString()+" "+targetList.get(position).getHardwareAsString()+" "+System.getMacVendor(targetList.get(position).getHardware()));
			
			
			return listElement;
		}
		
		
		
		public synchronized void addTarget(EndPointTarget newtarget){
			boolean targetAdded=false;
			
			for(EndPointTarget target:targetList){
				
				if( target.getAddress().equals(newtarget.getAddress()) ){
					targetAdded=true;
					break;
				}
				
			}
			
			if(!targetAdded){ 
				showDebug("Added Target!");
				targetList.add(newtarget);
				showDebug(String.valueOf(getCount()));
			
			}
		}
		 
		
		
	}		
		
	
	
	
	
	
	
	
	
	
	@Override
	protected void onCreate(Bundle savedInstanceState)
	{
		// TODO Auto-generated method stub
		super.onCreate(savedInstanceState);
        setTitle( System.getCurrentTarget() + " > MITM > Target Chooser" );
        setContentView(R.layout.plugin_mitm_extractor);
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        
        //initialize the activity views
        startStopListing =(ToggleButton)findViewById(R.id.startTargetListingButton);
        targetList =(ListView)findViewById(R.id.targetList);

        //set new OnclickListener for the button
        startStopListing.setOnClickListener(new OnClickListener() {
			
        	@Override
        	public void onClick(View v) {
        		
        		if(lookingForTargets){
        			setStoppedState();
        		}else{
        			setStartedState();	
        		}
        		
        	}
        });
        //compile the regular expression
        PARSER=Pattern.compile(regexc);
        
        //initialize the spoofSession object, not using proxy nor server
        spoofSession	   = new SpoofSession( false, false, null, null );

        //create a new target list adapter
        adapter=new EndPointTargetAdapter(getApplicationContext(), R.layout.end_point_target_list_item);

        //set the adapter for the list
        targetList.setAdapter(adapter);

        //set new onItemselected for the listview
        targetList.setOnItemClickListener(new OnItemClickListener() {

			@Override
			public void onItemClick(AdapterView<?> arg0, View element, int position,long id) {
				//in case of active search, stop it
					setStoppedState();
					
					Intent intent=new Intent(getApplicationContext(), Extractor.class);
					intent.putExtra("target_IP", adapter.getListElement(position).getAddress().toString().replace("/", ""));
					intent.putExtra("target_MAC", adapter.getListElement(position).getHardwareAsString());
					startActivity(intent);
			}
		
        
        });

	}


	

	private void setStartedState( ) {		
		//if the re is a tcpdump session alive, we first kill it
		System.getTcpDump().kill();
		lookingForTargets=true;
		spoofSession.start( new OnSessionReadyListener() {			
			@Override
			public void onError( String error ) {

			}
			
			@Override
			public void onSessionReady() {
				
				System.getTcpDump().sniff( PCAP_FILTER_HTTP, null, new OutputReceiver(){
					@Override
					public void onStart(String command) { }

					@Override
					public void onNewLine( String line ) {

						try
						{
							Matcher matcher = PARSER.matcher( line.trim() );

								if(matcher!=null && matcher.find()){
									EndPointTarget source= new EndPointTarget(matcher.group(8), matcher.group(1));
									EndPointTarget destiny= new EndPointTarget(matcher.group(9), matcher.group(4));
									
									if(System.getNetwork().isInternal(matcher.group(8))){
									//	showDebug("internal node (SRC)");
										//save it to the list
										final EndPointTarget target=source;
										
										//optimize this! use AsyncTask instead of runOnUiThread
										ExtractorTargetChooser.this.runOnUiThread(new Runnable() {
											
											@Override
											public void run() {
												adapter.addTarget(target);
												adapter.notifyDataSetChanged();
												
											}
										});
									
									}
									
									if(System.getNetwork().isInternal(matcher.group(9))){
										
										showDebug("internal node (DST)");
										//save it to the list
										final EndPointTarget target=destiny;
											
										ExtractorTargetChooser.this.runOnUiThread(new Runnable() {

											@Override
											public void run() {
												adapter.addTarget(target);
												adapter.notifyDataSetChanged();

											}
										});

									}
									
									
									
								}
							
						}
						catch( Exception e )
						{
							System.errorLogging( "Error during packet capturing", e );
						}
					}

					@Override
					public void onEnd(int exitCode) { }
				}).start();				
			}
		});
	

	}
	
	private void setStoppedState( ) {		
		//stop the current spoof session
		spoofSession.stop();
		//kill the current tcpdump session
		System.getTcpDump().kill();
		//update the search state
		lookingForTargets= false;
		//uncheck the start/stop button
		this.startStopListing.setChecked( false );                			
	}
	

	public static void showDebug(String message){
		if(DEBUG_ENABLED){
			Log.d(DEBUG_TAG, message);
		}
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
