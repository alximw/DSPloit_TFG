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

import it.evilsocket.dsploit.plugins.mitm.Extractor.BrowserRequest;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.SAXException;

import android.content.Context;
import android.widget.Toast;



public class UserProfiler {

	private File profilesFile;		//path to profiles.xml
	private Context context;		//app context, used to show some toasts

	public UserProfiler(Context context,String path){
		this.profilesFile=new File(path);		
		this.context=context;
	}


	/*
	 * This method search the looks on the BrowSerRequests list
	 * in order to validate the parsed profiles from profiles.xml
	 * 
	 */
	public ArrayList<Profile> applyProfiler(ArrayList<BrowserRequest> requests,ArrayList<Profile> profiles){
		ArrayList<Profile> validatedProfiles = new ArrayList<Profile>();

		for (Profile profile : profiles) {	//profiles for

			for (Rule rule : profile.rules) {	//for each profile rule

				for(BrowserRequest request:requests){		//for each rule on profile, look if the rule could be validated
					if(!request.goOverSSL()){
						if((rule.host).contains(request.getRequestHeader("Host")) && (request.getRequestCount()>=rule.number)){
							rule.validated=true;
						}				
					}


				}	
			}
			if(profile.allRulesValidated()){ //all the rules in the profile have been validated
				profile.validated=true;
				validatedProfiles.add(profile);	  //add the profile to the validated profiles list
			}	
		}
		return validatedProfiles;
	}




	public ArrayList<Profile> parse()
	{
		SAXParserFactory factory = SAXParserFactory.newInstance();
		ArrayList<Profile> result=null;

		SAXParser parser;
		try {
			//open file and create SAX parser Instances
			parser = factory.newSAXParser();
			ProfilesFileHandler handler = new ProfilesFileHandler( context);
			parser.parse(this.profilesFile, handler);
			result=handler.getProfileList();
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		} catch (SAXException e) {
			e.printStackTrace();
		} catch (IOException e) {
			Toast.makeText(context, "Error While Reading profile file", Toast.LENGTH_SHORT).show();
		}

		return result;
	}


}
