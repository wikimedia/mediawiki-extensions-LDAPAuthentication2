<?php

namespace MediaWiki\Extension\LDAPAuthentication;

use PluggableAuth as PluggableAuthBase;
use MediaWiki\Extension\LDAPAuthentication\ExtraLoginFields;
use MediaWiki\Extension\LDAPProvider\ClientFactory;

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

		$ldapClient = ClientFactory::getInstance()->getForDomain( $domain );
		if( !$ldapClient->canBindAs( $username, $password ) ) {
			$errorMessage =
				wfMessage(
					'ldapauthentication-error-authentication-failed',
					$domain
				)->text();
			return;
		}

		$basicUserInfoRequest = new BasicUserInfoRequest( $ldapClient, $username );
		$result = $basicUserInfoRequest->execute();

		$username = $result[BasicUserInfoRequest::USERNAME];
		$realname = $result[BasicUserInfoRequest::REALNAME];
		$email = $result[BasicUserInfoRequest::EMAIL];
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