<?php

namespace MediaWiki\Extension\LDAPAuthentication2;

use MediaWiki\Extension\LDAPProvider\DomainConfigFactory;

class Setup {
	/**
	 * @SuppressWarnings( SuperGlobals )
	 */
	public static function init() {
		$configuredDomains = DomainConfigFactory::getInstance()->getConfiguredDomains();
		$config = Config::newInstance();
		$GLOBALS['wgPluggableAuth_ExtraLoginFields']
			= (array)( new ExtraLoginFields( $configuredDomains, $config ) );
	}
}
