<?php

namespace MediaWiki\Extension\LDAPAuthentication2;

use MediaWiki\Extension\LDAPProvider\DomainConfigFactory;
use MediaWiki\MediaWikiServices;
use OutputPage;
use Skin;

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

	/**
	 *
	 * @param OutputPage $out
	 * @param Skin $skin
	 */
	public static function onBeforePageDisplay( $out, $skin ) {
		/**
		 * If `$LDAPAuthentication2AllowLocalLogin` is enabled we will end up with two "Login"
		 * buttons, as `PluggableAuth` will leave the regular
		 * `LocalPasswordPrimaryAuthenticationProvider` enabled. As there is unfortunately no
		 * other way to remove it - besides implementing subclass of
		 * `LocalPasswordPrimaryAuthenticationProvider`, we just hide it
		 */
		$config = new Config();
		if ( $out->getTitle()->isSpecial( 'Userlogin' ) && $config->get( 'AllowLocalLogin' ) ) {
			$authManager = MediaWikiServices::getInstance()->getAuthManager();
			$domainSessionKey = $authManager->getAuthenticationSessionData( PluggableAuth::DOMAIN_SESSION_KEY );

			// We don't know the domain only on the first step
			if ( $domainSessionKey === null ) {
				// Hide that button only for the first login step
				$out->addInlineStyle( '#wpLoginAttempt { display: none; }' );
			}
		}
	}
}
