<?php

namespace MediaWiki\Extension\LDAPAuthentication\Auth;

use MediaWiki\Auth\AbstractPasswordPrimaryAuthenticationProvider;
use MediaWiki\Auth\LocalPasswordPrimaryAuthenticationProvider;
use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Extension\LDAPProvider\ClientFactory;

class PrimaryAuthenticationProvider extends LocalPasswordPrimaryAuthenticationProvider {
	/**
	 *
	 * @param string $action
	 * @param array $options
	 * @return AuthenticationRequest[]
	 */
	public function getAuthenticationRequests( $action, array $options ) {
		$req = new DomainAndPasswordAuthenticationRequest();
		return [ $req ];
	}

	/**
	 *
	 * @param AuthenticationRequest[] $reqs
	 * @return AuthenticationResponse
	 */
	public function beginPrimaryAuthentication( array $reqs ) {
		$req = AuthenticationRequest::getRequestByClass(
			$reqs,
			DomainAndPasswordAuthenticationRequest::class
		);
		if ( $req instanceof DomainAndPasswordAuthenticationRequest === false ) {
			return AuthenticationResponse::newAbstain();
		}

		$selectedDomain = $req->domain;
		if( $selectedDomain === 'local' ) {
			return AuthenticationResponse::newAbstain();
		}

		$client = ClientFactory::getInstance()->getForDomain( $selectedDomain );
		$isAuthenticated = $client->canBindAs( $req->username, $req->password );

		if( !$isAuthenticated ) {
			return AuthenticationResponse::newFail(
				wfMessage( 'ldapauthentication-error-authentication-failed' )
			);
		}

		return AuthenticationResponse::newPass();
	}
}