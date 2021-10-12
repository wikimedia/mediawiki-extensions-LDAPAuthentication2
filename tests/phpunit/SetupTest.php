<?php

namespace MediaWiki\Extension\LDAPAuthentication2\Tests;

use MediaWiki\Extension\LDAPAuthentication2\Setup;
use MediaWiki\Extension\LDAPProvider\DomainConfigProvider\InlinePHPArray;
use MediaWikiIntegrationTestCase;

/**
 * @coversDefaultClass MediaWiki\Extension\LDAPAuthentication2\Setup
 */
class SetupTest extends MediaWikiIntegrationTestCase {

	/**
	 * @covers MediaWiki\Extension\LDAPAuthentication2\Setup::init
	 */
	public function testInit() {
		$this->setMwGlobals( [
			'wgPluggableAuth_ExtraLoginFields' => [],
			'LDAPProviderDomainConfigProvider' => static function () {
				$config = [ 'hw.local' => [] ];
				return new InlinePHPArray( $config );
			}
		] );

		Setup::init();

		$this->assertArrayHasKey( 'domain', $GLOBALS['wgPluggableAuth_ExtraLoginFields'] );
		$this->assertArrayHasKey( 'username', $GLOBALS['wgPluggableAuth_ExtraLoginFields'] );
		$this->assertArrayHasKey( 'password', $GLOBALS['wgPluggableAuth_ExtraLoginFields'] );
	}
}
