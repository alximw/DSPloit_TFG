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

import android.util.Log;

public class Profile {
	String name;		//profile name
	ArrayList<Rule> rules;		//set of rules
	boolean validated=false;	//the profile is validated?
	boolean allowOr=false;		//allow logic OR between rules?
	public Profile(){
		
	}
	public String toString(){
		
		String a="PROFILE NAME: "+name+"";
		String webs="";
		int count=0;
		
		for (Rule rule: rules){
			
			webs+=rule.host+", ";
			
		}
		
	return a+" webs visited: "+webs;
	}
	
	//checks if all rules have been validated
	public boolean allRulesValidated(){

		boolean allRulesValidated=false;
		boolean foundNotValidated=false;
		
		//the profiles allows OR between rules, only need one rule validated
		if(this.allowOr){
			Log.i("profiles","allowor");
			for(Rule rule:rules){
				if(rule.validated){
					Log.i("profiles",rule.host);
					allRulesValidated=true;
					break;
				}
			}
			
		}else{
			//all rules need to be validated
			for(Rule rule:rules){
				if(!rule.validated){
					foundNotValidated=true;
					break;
				}
			}
			if(!foundNotValidated){
				allRulesValidated=true;
			}
		}
		
		return allRulesValidated;
	}
	
	public static String toString(ArrayList<Profile> profiles){
		String string="";
		for(Profile profile:profiles ){
			string+="\n"+profile.toString();
		}
		return string;
	}
	
}
