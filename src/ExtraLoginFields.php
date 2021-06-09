<?php

namespace MediaWiki\Extension\LDAPAuthentication2;

class ExtraLoginFields extends \ArrayObject {

	const DOMAIN = 'domain';
	const USERNAME = 'username';
	const PASSWORD = 'password';
	const SSLUSER = 'ssluser';

	const DOMAIN_VALUE_LOCAL = 'local';

	/**
	 * @param array $configuredDomains to set up
	 * @param Config $config Config for this extension
	 */
	public function __construct( array $configuredDomains, $config ) {
		$sslconfig = $config->getSSLConfig();
		$default_login = false;

		if ($sslconfig->enabled)
		{
			if ($config::getSSLUsername())
			{
				if ($sslconfig->requirePassword)
					parent::__construct( [
						static::DOMAIN => $this->makeDomainFieldDescriptor( $configuredDomains, $config ),
						static::SSLUSER => $this->makeSSLUserFieldDescriptor( $config ),
						static::PASSWORD => $this->makePasswordFieldDescriptor()
					] );
				else
					parent::__construct( [
						static::DOMAIN => $this->makeDomainFieldDescriptor( $configuredDomains, $config ),
						static::SSLUSER => $this->makeSSLUserFieldDescriptor( $config )
					] );
			}
			else
			{
				$default_login = true;
			}
		}
		else
		{
			$default_login = true;
		}
		
		if ($default_login)
		{
			parent::__construct( [
				static::DOMAIN => $this->makeDomainFieldDescriptor( $configuredDomains, $config ),
				static::USERNAME => $this->makeUsernameFieldDescriptor(),
				static::PASSWORD => $this->makePasswordFieldDescriptor()
				
			] );
		}
	}
	
	private function makeSSLUserFieldDescriptor($config)
	{
		return [
			'type' => 'hidden',
			'value' => $config::getSSLUsername()
		];
	}
	
	private function makeUsernameFieldDescriptor() 
	{		
		return [
			'type' => 'string',
			'label' => wfMessage( 'userlogin-yourname' ),
			'help' => wfMessage( 'authmanager-username-help' ),
		];
	}
	
	private function makePasswordFieldDescriptor() 
	{		
		return [
			'type' => 'password',
			'label' => wfMessage( 'userlogin-yourpassword' ),
			'help' => wfMessage( 'authmanager-password-help' ),
			'sensitive' => true,
		];
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
