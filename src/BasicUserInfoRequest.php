<?php

namespace MediaWiki\Extension\LDAPAuthentication;

class BasicUserInfoRequest {
	const USERNAME = 'username';
	const REALNAME = 'realname';
	const EMAIL = 'email';

	/**
	 *
	 * @var \MediaWiki\Extension\LDAPProvider\Client
	 */
	protected $ldapClient = null;

	/**
	 *
	 * @var string
	 */
	protected $username = '';

	/**
	 *
	 * @var string
	 */
	protected $resultUsername = '';

	/**
	 *
	 * @var string
	 */
	protected $resultRealname = '';

	/**
	 *
	 * @var string
	 */
	protected $resultEmail = '';

	public function __construct( $ldapClient, $username ) {
		$this->ldapClient = $ldapClient;
		$this->username = $username;
	}

	/**
	 * @return array
	 */
	public function execute() {
		

		return [
			static::USERNAME => $this->resultUsername,
			static::REALNAME => $this->resultRealname,
			static::EMAIL => $this->resultEmail
		];
	}
}