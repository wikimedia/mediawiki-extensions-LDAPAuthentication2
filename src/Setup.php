<?php

namespace MediaWiki\Extension\LDAPAuthentication;

use MediaWiki\Extension\LDAPProvider\ClientFactory;

class Setup {
	public static function onRegistration() {
		$configuredDomains = ClientFactory::getInstance()->getConfiguredDomains();
		$GLOBALS['wgPluggableAuth_ExtraLoginFields'] =
			(array) new ExtraLoginFields( $configuredDomains );
	}
}