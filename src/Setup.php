<?php

namespace MediaWiki\Extensions\LDAPAuthentication;

use MediaWiki\Extensions\LDAPProvider\DomainConfigFactory;

class Setup {
	/**
	 * @SuppressWarnings( SuperGlobals )
	 */
	public static function init() {
		$configuredDomains = DomainConfigFactory::getInstance()->getConfiguredDomains();
		$GLOBALS['wgPluggableAuth_ExtraLoginFields']
			= (array)( new ExtraLoginFields( $configuredDomains ) );
	}
}
