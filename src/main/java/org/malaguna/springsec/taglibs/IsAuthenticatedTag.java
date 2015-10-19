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

import java.io.IOException;

import javax.el.ELException;
import javax.faces.FacesException;
import javax.faces.component.UIComponent;
import javax.faces.view.facelets.ComponentConfig;
import javax.faces.view.facelets.FaceletContext;
import javax.faces.view.facelets.FaceletException;
import javax.faces.view.facelets.TagHandler;

/**
 * Taglib to combine the Spring-Security Project with Facelets <br />
 *
 * This is the Class responsible for making the <br />
 * <code><br />
 *     &lt;sec:isAuthenticated;&gt;<br />
 *         The components you want to show only when the user is authenticated<br />
 *     lt;/sec:isAuthenticated&gt;<br />
 * </code>
 * work.
 *
 * @author Grzegorz Blaszczyk - http://www.blaszczyk-consulting.com/
 * @version %I%, %G%
 * @since 0.5
 */
public class IsAuthenticatedTag extends TagHandler
{

	public void apply(FaceletContext faceletContext, UIComponent uiComponent)
			throws IOException, FacesException, FaceletException, ELException {

		if(SpringSecurityELLibrary.isAuthenticated()) {
			this.nextHandler.apply(faceletContext, uiComponent);
		}
	}

	public IsAuthenticatedTag(ComponentConfig componentConfig) {
		super(componentConfig);	
	}

}