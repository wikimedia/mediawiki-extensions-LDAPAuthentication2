<?php

namespace MediaWiki\Extension\LDAPAuthentication;

class ExtraLoginFields extends \ArrayObject {
	const DOMAIN = 'domain';
	const USERNAME = 'username';
	const PASSWORD = 'password';

	public function __construct( $domains ) {
		$domainOptions = [];
		foreach( $domains as $domain ) {
			$domainOptions[$domain] = new \RawMessage( $domain );
		}
		$domainOptions['local'] = new \RawMessage( 'local' );
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