<?php

namespace MediaWiki\Extension\LDAPAuthentication;

use MediaWiki\Extension\LDAPProvider\DomainConfigFactory;

class Setup {
	public static function setup() {
		$configuredDomains = DomainConfigFactory::getInstance()->getConfiguredDomains();
		$GLOBALS['wgPluggableAuth_ExtraLoginFields'] =
			(array) new ExtraLoginFields( $configuredDomains );
	}
}