/**
 * This file is part of JSF/Facelets Tag Library for Spring Security TagLibs.
 *
 * JSF/Facelets Tag Library for Spring Security TagLibs is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * JSF/Facelets Tag Library for Spring Security TagLibs is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with JSF/Facelets Tag Library for Spring Security TagLibs.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.malaguna.springsec.taglibs;

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;

import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.servlet.ServletContext;

import org.malaguna.cmdit.model.usrmgt.RoleHelper;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

/**
 * Taglib to combine the Spring-Security Project with Facelets <br />
 *
 * This is the class responsible holding the logic for making the tags work. <br />
 * The specified <code>public static</code> methods are also defined in the spring-security.taglib.xml
 * to enable them for usage as expression-language element. <br />
 * <br />
 * e.g.<code><br />
 * &lt;ui:component rendered='#{sec:ifAllGranted(&quot;ROLE_USER&quot;)'> blablabal &lt;/ui:component&gt;
 *
 * @author Dominik Dorn - http://www.dominikdorn.com/
 * @version %I%, %G%
 * @since 0.5
 * 
 * Modification for including cmdit actions as GrantedAuthorities
 * @author Miguel Angel Laguna - http://malaguna.github.io
 */
public class SpringSecurityELLibrary {
	private static SpringSecurityELLibrary instance = null;
	private RoleHelper roleHelper = null;
	
	/**
	 * Implements private singleton 
	 * 
	 * @return
	 */
	private static SpringSecurityELLibrary getInstance(){
		if(instance == null){
			instance = new SpringSecurityELLibrary();
		}
		
		return instance;
	}
	
	/**
	 * Private constructor. It is called on first use on xhtml
	 */
	private SpringSecurityELLibrary(){
		FacesContext fctx = FacesContext.getCurrentInstance();
		if(fctx != null){
			ExternalContext ectx = fctx.getExternalContext();
			if(ectx != null){
				ServletContext sc = (ServletContext) ectx.getContext();
				if(sc != null){
					String roleHelperBeanName = sc.getInitParameter("RoleHelperBeanName");
					if(roleHelperBeanName != null && !"".equals(roleHelperBeanName)){
						WebApplicationContext wac = WebApplicationContextUtils.getRequiredWebApplicationContext(sc);
						
						roleHelper = (RoleHelper) wac.getBean(roleHelperBeanName);
					}
				}
			}
		}
	}

	private static Set<String> parseAuthorities(String grantedRoles) {
		Set<String> parsedAuthorities = new TreeSet<String>();
		if (grantedRoles == null || "".equals(grantedRoles.trim())) {
			return parsedAuthorities;
		}

		String[] parsedAuthoritiesArr;
		if(grantedRoles.contains(",")){
			parsedAuthoritiesArr = grantedRoles.split(",");
		} else {
			 parsedAuthoritiesArr = new String[]{grantedRoles};
		}

		// adding authorities to set (could pssible be done better!)
		for (String auth : parsedAuthoritiesArr)
			parsedAuthorities.add(auth.trim());
		return parsedAuthorities;
	}

	private static GrantedAuthority[] getUserAuthorities()
	{
		if(SecurityContextHolder.getContext() == null)
		{
			System.out.println("security context is empty, this seems to be a bug/misconfiguration!");
			return new GrantedAuthority[0];
		}
		Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();
		if(currentUser == null)
			return new GrantedAuthority[0];


		Collection<? extends GrantedAuthority> authorities = currentUser.getAuthorities();
		if(authorities == null)
			return new GrantedAuthority[0];

		return authorities.toArray(new GrantedAuthority[]{});
	}


	/**
	 * Method that checks if the user holds <b>any</b> of the given roles.
	 * Returns <code>true, when the first match is found, <code>false</code> if no match is found and
	 * also <code>false</code> if no roles are given
	 *
	 * @param grantedRoles a comma seperated list of roles
	 * @return true if any of the given roles are granted to the current user, false otherwise
	 */
	public static boolean ifAnyGranted(final String grantedRoles) {
		boolean result = false;
		
		Set<String> parsedAuthorities = parseAuthorities(grantedRoles);
		if (!parsedAuthorities.isEmpty()){
			GrantedAuthority[] authorities = getUserAuthorities();
	
			//Check if any rol is granted
			for (GrantedAuthority authority : authorities) {
				result |= parsedAuthorities.contains(authority.getAuthority());
			}
			
			//Check if any actions is granted
			if(!result){
				Set<String> actionSet = new HashSet<String>();
				
				for (GrantedAuthority authority : authorities) {
					actionSet.addAll(getInstance().roleHelper.getActionSet(authority.getAuthority()));
				}
				
				Iterator<String> pait = parsedAuthorities.iterator();
				while(!result && pait.hasNext()){
					result |= actionSet.contains(pait.next());
				}
			}
		}
		
		return result;
	}



	/**
	 * Method that checks if the user holds <b>all</b> of the given roles.
	 * Returns <code>true</code>, iff the user holds all roles, <code>false</code> if no roles are given or
	 * the first non-matching role is found
	 *
	 * @param requiredRoles a comma seperated list of roles
	 * @return true if all of the given roles are granted to the current user, false otherwise or if no
	 * roles are specified at all.
	 */
	public static boolean ifAllGranted(final String requiredRoles) {
		// parse required roles into list
		Set<String> requiredAuthorities = parseAuthorities(requiredRoles);
		if (requiredAuthorities.isEmpty())
			return false;

		// get granted roles
		GrantedAuthority[] authoritiesArray = getUserAuthorities();

		Set<String> grantedAuthorities = new TreeSet<String>();
		for (GrantedAuthority authority : authoritiesArray) {
		    grantedAuthorities.add(authority.getAuthority());
		}


		// iterate over required roles,
		for(String requiredAuthority : requiredAuthorities)
		{
			// check if required role is inside granted roles
			// if not, return false
			if(!grantedAuthorities.contains(requiredAuthority)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Method that checks if <b>none</b> of the given roles is hold by the user.
	 * Returns <code>true</code> if no roles are given, or none of the given roles match the users roles.
	 * Returns <code>false</code> on the first matching role.
	 *
	 * @param notGrantedRoles a comma seperated list of roles
	 * @return true if none of the given roles is granted to the current user, false otherwise
	 */
	public static boolean ifNotGranted(final String notGrantedRoles) {
		Set<String> parsedAuthorities = parseAuthorities(notGrantedRoles);
		if (parsedAuthorities.isEmpty())
			return true;

		GrantedAuthority[] authorities = getUserAuthorities();

		for (GrantedAuthority authority : authorities) {
			if (parsedAuthorities.contains(authority.getAuthority()))
				return false;
		}
		return true;
	}
	
  /**
   * Method checks if the user is authenticated.
   * Returns <code>true</code> if the user is <b>not</b> anonymous.
   * Returns <code>false</code> if the user <b>is</b> anonymous.
   * @return
   */
  public static boolean isAuthenticated() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null || authentication instanceof AnonymousAuthenticationToken) {
      return false;
    }
    return authentication.isAuthenticated();
  }

  /**
   * Method checks if the user is anonymous.
   * Returns <code>true</code> if the user <b>is</b> anonymous.
   * Returns <code>false</code> if the user is <b>not</b> anonymous.
   * @return
   */
  public static boolean isAnonymous() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null || authentication instanceof AnonymousAuthenticationToken) {
      return true;
    }
    return !authentication.isAuthenticated();
  }
}
