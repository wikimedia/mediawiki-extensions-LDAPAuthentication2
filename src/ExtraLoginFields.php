<?php

namespace MediaWiki\Extensions\LDAPAuthentication;

class ExtraLoginFields extends \ArrayObject {
	const DOMAIN = 'domain';
	const USERNAME = 'username';
	const PASSWORD = 'password';
	const DOMAIN_VALUE_LOCAL = 'local';

	/**
	 * @param array $domains to set up
	 */
	public function __construct( array $domains ) {
		$domainOptions = [];
		foreach ( $domains as $domain ) {
			$domainOptions[$domain] = new \RawMessage( $domain );
		}
		$domainOptions[static::DOMAIN_VALUE_LOCAL] = new \RawMessage( 'local' );
		parent::__construct( [
			static::DOMAIN => [
				'type' => 'select',
				'label' => wfMessage( 'yourdomainname' ),
				'help' => wfMessage( 'authmanager-domain-help' ),
				'options' => $domainOptions
			],
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
}
