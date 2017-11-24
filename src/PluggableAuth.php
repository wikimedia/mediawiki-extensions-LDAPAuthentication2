<?php

namespace MediaWiki\Extension\LDAPAuthentication;

use PluggableAuth as PluggableAuthBase;
use PluggableAuthLogin;
use MediaWiki\Extension\LDAPAuthentication\ExtraLoginFields;
use MediaWiki\Extension\LDAPProvider\ClientFactory;
use MediaWiki\Auth\AuthManager;

class PluggableAuth extends PluggableAuthBase {

	/**
	 * Authenticates against LDAP
	 * @param int $id
	 * @param string $username
	 * @param string $realname
	 * @param string $email
	 * @param string $errorMessage
	 */
	public function authenticate( &$id, &$username, &$realname, &$email, &$errorMessage ) {
		$authManager = AuthManager::singleton();
		$extraLoginFields = $authManager->getAuthenticationSessionData(
			PluggableAuthLogin::EXTRALOGINFIELDS_SESSION_KEY
		);

		$domain = $extraLoginFields[ExtraLoginFields::DOMAIN];
		$username = $extraLoginFields[ExtraLoginFields::USERNAME];
		$password = $extraLoginFields[ExtraLoginFields::PASSWORD];

		if( $domain === ExtraLoginFields::DOMAIN_VALUE_LOCAL ) {
			return true;
		}

		$ldapClient = ClientFactory::getInstance()->getForDomain( $domain );
		if( !$ldapClient->canBindAs( $username, $password ) ) {
			$errorMessage =
				wfMessage(
					'ldapauthentication-error-authentication-failed',
					$domain
				)->text();
			return;
		}
		try {
			$result = $ldapClient->getUserInfo( $username );
			$username = $result[Config::USERINFO_USERNAME_ATTR];
			$realname = $result[Config::USERINFO_REALNAME_ATTR];
			$email = $result[Config::USERINFO_EMAIL_ATTR];
		} catch( \Exception $ex ) {
			$errorMessage =
				wfMessage(
					'ldapauthentication-error-authentication-failed-userinfo',
					$domain
				)->text();
		}
	}

	/**
	 *
	 * @param \User $user
	 */
	public function deauthenticate( \User &$user ) {
		//Nothing to do
	}

	/**
	 *
	 * @param int $id
	 */
	public function saveExtraAttributes( $id ) {
		//Nothing to do
	}
}