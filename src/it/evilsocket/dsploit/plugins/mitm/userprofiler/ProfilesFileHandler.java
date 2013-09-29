/*
 * This file is part of the dSploit.
 *
 * Copyleft of Simone Margaritelli aka evilsocket <evilsocket@gmail.com>
 *
 * dSploit is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * dSploit is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with dSploit.  If not, see <http://www.gnu.org/licenses/>.
 */

package it.evilsocket.dsploit.plugins.mitm.userprofiler;



import java.util.ArrayList;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import android.content.Context;
import android.widget.Toast;


public class ProfilesFileHandler extends DefaultHandler {
	 private static boolean name = false;		//profile name
	private static boolean host = false;		//rule host
	private static boolean number = false;		//rule number
	private static boolean allowOr=false;		//profile allowor option
	private Context context;					//context used to display toast	
			
	private ArrayList<Profile> profiles;		//set of profiles parsed
	
	private Profile profile;					//temporal profile object
	private Rule rule;							//temporal rule object
	
 
	public ProfilesFileHandler(Context context ){
		super();
		this.context=context;
	}

	@Override
	public void endDocument() throws SAXException {
		super.endDocument();
		Toast.makeText(context, profiles.size()+ " profiles parsed", Toast.LENGTH_SHORT).show();
		
	}

	@Override
	public void startDocument() throws SAXException {
				super.startDocument();
				
				profiles=new ArrayList<Profile>();
	}

	public void startElement(String uri, String localName,String qName, 
                Attributes attributes) throws SAXException {
 
		////Log.i("DEBUG","Start Element :" + qName);
		if(localName.equalsIgnoreCase("PROFILE")){
			//<profile> tag found
			profile=new Profile();		//create profile object
			profile.rules=new ArrayList<Rule>();	//and list of rules
			
		}
		
		if(localName.equalsIgnoreCase("RULE")){
			rule=new Rule();
			
		}
		
		if (localName.equalsIgnoreCase("NAME")) {
			name = true;
			
		}
 
		if (localName.equalsIgnoreCase("HOST")) {
			host = true;
		}
 
		if (localName.equalsIgnoreCase("NUMBER")) {
			number = true;
		}if (localName.equalsIgnoreCase("ALLOW-OR")) {
			allowOr = true;
		}
 
		
 
	}
 
	public void endElement(String uri, String localName,
		String qName) throws SAXException {
		
		if(localName.equalsIgnoreCase("RULE")){
			////Log.i("DEBUG","END tag : "+qName);

			profile.rules.add(rule);
		}
		if(localName.equalsIgnoreCase("PROFILE")){
			
			if(allowOr){
				profile.allowOr=true;
				allowOr=false;
			}
			profiles.add(profile);
		}
			
 
	}
 
	public void characters(char ch[], int start, int length) throws SAXException {
 
		
		if (name) {
			super.characters(ch, start, length);
			//Log.i("DEBUGSAX","Profile name : " + new String(ch, start, length));
		
			profile.name=new String(ch, start, length);
			
			name = false;
		}
 
		if (host) {
			//Log.i("DEBUG","Host : " + new String(ch, start, length));
			host = false;
			rule.host=new String(ch, start, length);
		}
 
		if (number) {
			//Log.i("DEBUG","Number : " + new String(ch, start, length));
			number = false;
			rule.number=Integer.parseInt(new String(ch, start, length).trim());
		}
		
		////Log.i("DEBUG","characters : " + new String(ch, start, length));
		
	}
 
	public ArrayList<Profile> getProfileList(){
		return this.profiles;
	}
	
	
}
