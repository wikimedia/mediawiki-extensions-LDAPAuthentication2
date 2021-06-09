<?php

namespace MediaWiki\Extension\LDAPAuthentication2;

use MediaWiki\Extension\LDAPProvider\DomainConfigFactory;
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
			$out->addInlineStyle( '#wpLoginAttempt { display: none; }' );
		}
		
		$sslconfig = Config::newInstance()->getSSLConfig();

		if (($sslconfig->enabled) && (!$sslconfig->requirePassword) && ($sslconfig->autoLogin))
			$out->addScript( '<script type="text/javascript">
			function minuteCookie(cname, cvalue) {
				var d = new Date();
				d.setTime(d.getTime() + (3*60*1000));
				var expires = "expires="+ d.toUTCString();
 				document.cookie = cname + "=" + cvalue + ";" + expires + ";path=/";
			}
			function getCookie(cname) {
				var name = cname + "=";
				var decodedCookie = decodeURIComponent(document.cookie);
				var ca = decodedCookie.split(";");
				for(var i = 0; i <ca.length; i++) {
				  var c = ca[i];
				  while (c.charAt(0) == " ") {
				    c = c.substring(1);
				  }
				  if (c.indexOf(name) == 0) {
				    return c.substring(name.length, c.length);
				  }
				}
				return "";
			}
			function autoClick()
			{
				minuteCookie("logintry", 1);
				document.getElementById("mw-input-pluggableauthlogin").click();			
			}
			var tryCookie = getCookie("logintry");
			if (tryCookie == "")
			{
				if (document.getElementsByClassName("errorbox").length == 0)
				{
					if (!!document.getElementById("mw-input-captchaWord") === false)
					{
						if (!!document.getElementsByClassName("mw-userlogin-rememberme") === true)
							document.getElementsByClassName("mw-userlogin-rememberme")[0].style.display = "none";
					
						document.getElementById("mw-input-pluggableauthlogin").style.display = "none";

						setTimeout("autoClick()", 1100);
					}
				}
			}
			</script>' );
	}
}
