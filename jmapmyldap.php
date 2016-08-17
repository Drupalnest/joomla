<?php
/**
 * @author      Ken Patolia <kenpatolia@live.com> 
 * @author      Shaun Maunder <shaun@shmanic.com>
 * @package     Shmanic.Plugin
 * @subpackage  User.JMapMyLDAP
 * 
 * @copyright	Copyright (C) 2011 Shaun Maunder. All rights reserved.
 * @license		GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('_JEXEC') or die;

jimport('joomla.plugin.plugin');
jimport('shmanic.jldap2');

/**
 * LDAP User Plugin
 *
 * @package     Shmanic.Plugin
 * @subpackage  User.JMapMyLDAP
 * @since       1.0
 */
class plgUserJMapMyLDAP extends JPlugin 

{	
  /**

       * Destroys the session if the login failed

       * and performs the redirect if a URL was specified

       * 

       * @param unknown_type $response

       */

/**     
	 public function onUserLoginFailure( $response=array() )

      {

            // destroy the session to prevent future use of the $session->user value that any other user plugins may have created

            $session = JFactory::getSession();

            $session->destroy();

           

            $redirect_url = $this->params->get( 'ms_no_access_redirect_url' );

            if ($redirect_url)

            {

                  // do redirect, but only if login attempt was on the front-end

                  $app = JFactory::getApplication();

                  if ($app->isSite())

                  {

                        $app->redirect( $redirect_url );

                  }

            }

            return;

      }

     */

      /**

       * Gets the map of multisites to ldap groups

       *

       * @return  Array  Multidimensional Array where the multisite id is the key, each value is a group

       */

      protected function getMSLDAPMap()

      {

            $list = array();

            $tmp = explode("\n", $this->params->get(multisite_2_ldap_map_list));

            foreach($tmp as $entry) {

                  if($entry != "" && strrpos($entry, ':') > 0) {

                        $parts = explode(":", $entry, 2);

                        $key = strtolower( trim( $parts[0] ) );

                        $value = strtolower( trim( $parts[1] ) );

                        if (empty($list[$key]))

                        {

                              $list[$key] = array();

                        }

                        $list[$key][] = $value;

                  }

            }

            return $list;

      }

     

      /**

       * Using the array of the user's ldap_groups, the current multisite id, and the map of multisites2ldap_groups,

       * determine if the user has access to the multisite 

       *

       * @param unknown_type $user_ldap_groups

       * @param unknown_type $ms_id

       * @param unknown_type $map

       */

      protected function hasAccess($user_ldap_groups, $ms_id, $map)

      {

            $this->output_error = '';

           

            if (empty($user_ldap_groups))

            {

                  $this->setError( 'no_user_ldap_groups' );

                  return false;

            }

           

            if (empty($map[$ms_id]))

            {

                  $this->setError( 'no_valid_ldap_groups_for_this_multisite' );

                  return false;

            }

           

            foreach($user_ldap_groups as $user_ldap_group)

            {

                  $user_ldap_group = trim( $user_ldap_group );

                 

                  if (in_array($user_ldap_group, $map[$ms_id]))

                  {

                        return true;

                  }

                 

                  foreach ($map[$ms_id] as $key=>$value)

                  {

                        if (trim($value) == $user_ldap_group)

                        {

                              return true;

                        }

                  }

            }

           

            $this->setError( 'user_not_in_ldap_groups_with_access' );

            return false;

      }
	/**
	 * This method fires off the onlogin method for setting
	 * the user session and user groups.
	 *
	 * @param  array  $user     Holds the user data, and the ldapUser entry by auth plugin
	 * @param  array  $options  Array holding options (remember, autoregister, group)
	 *
	 * @return  boolean  True on success
	 * @since   1.0
	 */
	public function onUserLogin($user, $options = array()) 
	{
		//load up the front end lanuages (used for errors)
		$this->loadLanguage();
		
		if($user['type'] != 'LDAP') {
			return true; //the authentication protocol is not comptable
		}
		
		jimport('shmanic.jmapmyldap');
		if(!class_exists('JMapMyLDAP')) { //checks for the required library
			return JERROR::raiseWarning('SOME_ERROR_CODE', JText::_('PLG_JMAPMYLDAP_ERROR_LIB_JMAPMYLDAP_MISSING'));
		}

		$maper = new JMapMyLDAP($this->params);
		
		// Autoregistration with optional override
		$autoRegister = $this->params->get('autoregister', 1);
		if($autoRegister == '0' || $autoRegister == '1') {
			
			// inherited registration
			$options['autoregister'] = isset($options['autoregister']) ? $options['autoregister'] : $autoRegister;
			
		} else {

			// override registration
			$options['autoregister'] = ($autoRegister == 'override1') ? 1 : 0;

		}
		
		jimport('joomla.user.helper');
		$instance = JMapMyLDAP::getUser($user, $options); //get authenticating user...
		if(!$instance || $instance->get('error')) {
			return false;
		}
		
		/* this may have been set in the authentication plugin
		 * and therefore would contain all the attributes we
		 * need to map this authenticating user. as a result
		 * we wouldn't require any ldap connections.
		 */
		if(isset($user['jmapmyentry'])) {
			$ldapUser =& $user['jmapmyentry']; //some other plug-in has already set everything
			
		} else {
			$ldap = $maper->getActiveLdap(); 
			if(JError::isError($ldap))
				return $this->_reportError($ldap); 
			
			$ldapUser = $maper->getLdapUser($ldap, $instance->get('username'));
			$ldap->close();
			
		}

		if(JError::isError($ldapUser)) { //cannot get ldap attributes for user
			return $this->_reportError($ldapUser); 
		} 

		if($this->params->get('group_map_enabled')) {
			$result = $maper->doMap($instance, $ldapUser); //lets do the mapping and report back on any errors
			if(JError::isError($result)) {
				return $this->_reportError($result); 
			}
		}

		$maper->doSync($instance, $ldapUser); //lets do the userfield sync
		
		if(!JMapMyLDAP::saveUser($instance)) { //our own method to bypass the super user security checks
			return $this->_reportError(new JException(JText::_('PLG_JMAPMYLDAP_ERROR_JUSER_SAVE')));
		}

		//check the user can login.
		$authorised	= $instance->authorise($options['action']);
		if(!$authorised) {
			return JError::raiseWarning(401, JText::_('JERROR_LOGIN_DENIED'));
		}

		// check the user's LDAP groups to see if they have access to this site
		// if the site id is not null and is not in the ldap groups array, don't login the user
		if (defined( 'MULTISITES_ID'))
		{
			// get the user's ldap groups
			$ldap_groups = $ldapUser->getGroups();
			
			// get the site id from the multisite component
			$site_id = MULTISITES_ID;
			
			// get the map of multisites to LDAP Groups
			$ms_ldap_map = $this->getMSLDAPMap();
			
			// does the user have access?
			$has_access = $this->hasAccess($ldap_groups, $site_id, $ms_ldap_map);
			
			if ($this->params->get('multisite_mapping_debug', 0))
			{
				JError::raiseWarning('SOME_ERROR_CODE', "<br/>plgUserJMapMyLDAP.site_id: " . $site_id );
			
				JError::raiseWarning('SOME_ERROR_CODE', "<br/>plgUserJMapMyLDAP.ldapUser->getgroups: <pre>" . print_r ($ldap_groups, true) ) . "</pre>";
			
				JError::raiseWarning('SOME_ERROR_CODE', "<br/>plgUserJMapMyLDAP.multisites_2_ldapgroups_map: <pre>" . print_r ($ms_ldap_map, true) ) . "</pre>";
			
				if ($has_access) { $may_enter = 'YES'; } else { $may_enter = 'NO because: ' . $this->getError(); }
				JError::raiseWarning('SOME_ERROR_CODE', "<br/>plgUserJMapMyLDAP.has_access: " . $may_enter );
			}
			
			if(!$has_access) {
				// delete the user from the db -- it was created by jmapmyldap above
				if (!$instance->delete())
				{
					// delete failed
					if ($this->params->get('multisite_mapping_debug', 0)) {
						JError::raiseWarning('SOME_ERROR_CODE', "<br/>plgUserJMapMyLDAP.delete_user: " . $instance->getError() );
					}
				}
				
				// failsafe
				$session = JFactory::getSession();
				$session->destroy();
				return false;
			}
		}
		
		//Ken's code
		// check the user's LDAP groups to see if they have access to this site

            // if the site id is not null and is not in the ldap groups array, don't login the user

            if (defined( 'MULTISITES_ID'))

            {

                  // get the user's ldap groups

                  $ldap_groups = $ldapUser->getGroups();

                 

                  // get the site id from the multisite component

                  $site_id = MULTISITES_ID;

                 

                  // get the map of multisites to LDAP Groups

                  $ms_ldap_map = $this->getMSLDAPMap();

                 

                  // does the user have access?

                  $has_access = $this->hasAccess($ldap_groups, $site_id, $ms_ldap_map);

                 

                  if ($this->params->get('multisite_mapping_debug', 0))

                  {

                        JError::raiseWarning('SOME_ERROR_CODE', "<br/>plgUserJMapMyLDAP.site_id: " . $site_id );

                 

                        JError::raiseWarning('SOME_ERROR_CODE', "<br/>plgUserJMapMyLDAP.ldapUser->getgroups: <pre>" . print_r ($ldap_groups, true) ) . "</pre>";

                 

                        JError::raiseWarning('SOME_ERROR_CODE', "<br/>plgUserJMapMyLDAP.multisites_2_ldapgroups_map: <pre>" . print_r ($ms_ldap_map, true) ) . "</pre>";

                 

                        if ($has_access) { $may_enter = 'YES'; } else { $may_enter = 'NO because: ' . $this->getError(); }

                        JError::raiseWarning('SOME_ERROR_CODE', "<br/>plgUserJMapMyLDAP.has_access: " . $may_enter );

                  }

                 

                  if(!$has_access) {

                        // delete the user from the db -- it was created by jmapmyldap above

                        if (!$instance->delete())

                        {

                              // delete failed

                              if ($this->params->get('multisite_mapping_debug', 0)) {

                                    JError::raiseWarning('SOME_ERROR_CODE', "<br/>plgUserJMapMyLDAP.delete_user: " . $instance->getError() );

                              }

                        }

                       

                        // failsafe

                        $session = JFactory::getSession();

                        $session->destroy();

                        return false;

                  }

            }
		
		// Mark the user as logged in
		$instance->set('guest', 0);
	
		// Register the needed session variables
		$session = JFactory::getSession();
		$session->set('user', $instance);

		return true;
	}
	
	/**
	 * Destroys the session if the login failed
	 * and performs the redirect if a URL was specified
	 *  
	 * @param unknown_type $response
	 */
	public function onUserLoginFailure( $response=array() )
	{
		// destroy the session to prevent future use of the $session->user value that any other user plugins may have created
		$session = JFactory::getSession();
		$session->destroy();
		
		$redirect_url = $this->params->get( 'ms_no_access_redirect_url' );
		if ($redirect_url)
		{
			// do redirect, but only if login attempt was on the front-end
			$app = JFactory::getApplication();
			if ($app->isSite())
			{
				$app->redirect( $redirect_url );
			}
		}
		return;
	}
	
	/**
	 * Gets the map of multisites to ldap groups
	 * 
	 * @return  Array  Multidimensional Array where the multisite id is the key, each value is a group 
	 */
	protected function getMSLDAPMap()
	{
		$list = array();
		$tmp = explode("\n", $this->params->get(multisite_2_ldap_map_list));
		foreach($tmp as $entry) {
			if($entry != "" && strrpos($entry, ':') > 0) {
				$parts = explode(":", $entry, 2);
				$key = strtolower( trim( $parts[0] ) );
				$value = strtolower( trim( $parts[1] ) );
				if (empty($list[$key]))
				{
					$list[$key] = array();
				}
				$list[$key][] = $value;
			}
		}
		return $list;
	}
	
	/**
	 * Using the array of the user's ldap_groups, the current multisite id, and the map of multisites2ldap_groups,
	 * determine if the user has access to the multisite  
	 * 
	 * @param unknown_type $user_ldap_groups
	 * @param unknown_type $ms_id
	 * @param unknown_type $map
	 */
	protected function hasAccess($user_ldap_groups, $ms_id, $map)
	{
		$this->output_error = '';
		
		if (empty($user_ldap_groups))
		{
			$this->setError( 'no_user_ldap_groups' );
			return false;
		}
		
		if (empty($map[$ms_id]))
		{
			$this->setError( 'no_valid_ldap_groups_for_this_multisite' );
			return false;
		}
		
		foreach($user_ldap_groups as $user_ldap_group)
		{
			$user_ldap_group = trim( $user_ldap_group );
			
			if (in_array($user_ldap_group, $map[$ms_id]))
			{
				return true;
			}
			
			foreach ($map[$ms_id] as $key=>$value)
			{
				if (trim($value) == $user_ldap_group)
				{
					return true;
				}
			}
		}
		
		$this->setError( 'user_not_in_ldap_groups_with_access' );
		return false;
	}
	
	/**
	 * Reports an error to the screen and log. If debug mode is on 
	 * then it displays the specific error on screen, if debug mode 
	 * is off then it displays a generic error.
	 *
	 * @param  JException  $exception  The authentication error
	 * 
	 * @return  JError  Error based on comment from exception
	 * @since   1.0
	 */
	protected function _reportError($exception = null) 
	{
		/*
		* The mapping was not successful therefore
		* we should report what happened to the logger
		* for admin inspection and user should be informed
		* all is not well.
		*/
		$comment = is_null($exception) ? JText::_('PLG_JMAPMYLDAP_ERROR_UNKNOWN') : $exception;
		
		$errorlog = array('status'=>'JMapMyLDAP Fail: ', 'comment'=>$comment);
		
		jimport('joomla.error.log');
		$log = JLog::getInstance();
		$log->addEntry($errorlog);
		
		if(JDEBUG) {
			return JERROR::raiseWarning('SOME_ERROR_CODE', $comment);
		}
		
		return JERROR::raiseWarning('SOME_ERROR_CODE', JText::_('PLG_JMAPMYLDAP_ERROR_GENERAL'));
		
	}

}
