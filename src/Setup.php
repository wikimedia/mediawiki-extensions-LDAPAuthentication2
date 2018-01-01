<?php

namespace MediaWiki\Extensions\LDAPAuthentication;

use MediaWiki\Extensions\LDAPProvider\DomainConfigFactory;

class Setup {
	public static function setup() {
		$configuredDomains = DomainConfigFactory::getInstance()->getConfiguredDomains();
		$GLOBALS['wgPluggableAuth_ExtraLoginFields'] =
			(array) new ExtraLoginFields( $configuredDomains );
	}
}