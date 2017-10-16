<?php

namespace MediaWiki\Extension\LDAPAuthentication\Auth;

use MediaWiki\Auth\PasswordAuthenticationRequest;
use MediaWiki\Extension\LDAPProvider\ClientFactory;

class DomainAndPasswordAuthenticationRequest extends PasswordAuthenticationRequest {

	public $domain = '';

	public function getFieldInfo(): array {
		$ret = parent::getFieldInfo();

		$ret ['domain'] = [
			'type' => 'select',
			'options' => $this->makeDomainOptions(),
			'label' => wfMessage( 'ldapauthentication-label-domain' ),
			'help' => wfMessage( 'ldapauthentication-help-domain' ),
			'weight' => -50
		];

		return $ret;
	}

	protected function makeDomainOptions() {
		$domainOpts = [
			'local' => wfMessage( 'ldapauthentication-domain-local' ),
		];

		$clientFactory = ClientFactory::getInstance();
		$configuredDomains = $clientFactory->getConfiguredDomains();
		foreach( $configuredDomains as $configuredDomain ) {
			$domainOpts[ $configuredDomain ] =
				wfMessage( 'ldapauthentication-domain-'.$configuredDomain );
		}

		return $domainOpts;
	}

}