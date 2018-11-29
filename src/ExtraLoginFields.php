<?php

namespace MediaWiki\Extension\LDAPAuthentication2;

class ExtraLoginFields extends \ArrayObject {

	const DOMAIN = 'domain';
	const USERNAME = 'username';
	const PASSWORD = 'password';

	const DOMAIN_VALUE_LOCAL = 'local';

	/**
	 * @param array $configuredDomains to set up
	 * @param Config $config Config for this extension
	 */
	public function __construct( array $configuredDomains, $config ) {
		parent::__construct( [
			static::DOMAIN => $this->makeDomainFieldDescriptor( $configuredDomains, $config ),
			static::USERNAME => [
				'type' => 'string',
				'label' => wfMessage( 'userlogin-yourname' ),
				'help' => wfMessage( 'authmanager-username-help' ),
			],
			static::PASSWORD => [
				'type' => 'password',
				'label' => wfMessage( 'userlogin-yourpassword' ),
				'help' => wfMessage( 'authmanager-password-help' ),
				'sensitive' => true,
			]
		] );
	}

	private function makeDomainFieldDescriptor( $configuredDomains, $config ) {
		if ( $config->get( 'AllowLocalLogin' ) ) {
			$configuredDomains[] = static::DOMAIN_VALUE_LOCAL;
		}

		if ( count( $configuredDomains ) === 1 ) {
			return [
				'type' => 'hidden',
				'value' => $configuredDomains[0]
			];
		}

		$domainOptions = [];
		foreach ( $configuredDomains as $domain ) {
			$domainOptions[$domain] = new \RawMessage( $domain );
		}

		return [
			'type' => 'select',
			'label' => new \Message( 'yourdomainname' ),
			'help' => new \Message( 'authmanager-domain-help' ),
			'options' => $domainOptions
		];
	}

}
