<?php

namespace MediaWiki\Extension\LDAPAuthentication2\Tests;

use MediaWiki\Auth\AuthManager;
use MediaWiki\Extension\LDAPAuthentication2\HookHandler\ReorderLoginFields;
use PHPUnit\Framework\TestCase;

class ReorderLoginFieldsTest extends TestCase {

	/**
	 * @covers \MediaWiki\Extension\LDAPAuthentication2\HookHandler\ReorderLoginFields::onAuthChangeFormFields
	 * @dataProvider provideLoginFields
	 */
	public function testOnAuthChangeFormFields( array $inputLoginFields, array $expected ) {
		$reorderLoginFields = new ReorderLoginFields();

		$reorderLoginFields->onAuthChangeFormFields( [], [], $inputLoginFields, AuthManager::ACTION_LOGIN );

		$this->assertEquals( $expected, $inputLoginFields );
	}

	public function provideLoginFields() {
		return [
			[
				[
					'username' => [],
					'password' => [],
					'rememberMe' => [],
					'loginattempt' => [],
					'linkcontainer' => [],
					'passwordReset' => [],
					'pluggableauthlogin1' => [],
					'pluggableauthlogin2' => [],
					'pluggableauthlogin3' => [],
					'pluggableauthlogin4' => [],
					'pluggableauthlogin5' => [],
				],
				[
					'username' => [ 'weight' => 10 ],
					'password' => [ 'weight' => 20 ],
					'rememberMe' => [ 'weight' => 30 ],
					'loginattempt' => [ 'weight' => 40 ],
					'linkcontainer' => [ 'weight' => 60 ],
					'passwordReset' => [ 'weight' => 70 ],
					'pluggableauthlogin1' => [ 'weight' => 50 ],
					'pluggableauthlogin2' => [ 'weight' => 51 ],
					'pluggableauthlogin3' => [ 'weight' => 52 ],
					'pluggableauthlogin4' => [ 'weight' => 53 ],
					'pluggableauthlogin5' => [ 'weight' => 54 ],
				]
			]
		];
	}
}
