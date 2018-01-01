<?php

if ( PHP_SAPI !== 'cli' && PHP_SAPI !== 'phpdbg' ) {
	die( 'Not an entry point' );
}

error_reporting( E_ALL | E_STRICT );
date_default_timezone_set( 'UTC' );
ini_set( 'display_errors', 1 );

if (
	!class_exists( 'MediaWiki\\Extensions\\LDAPAuthentication\\Config' )
	|| ( $version = MediaWiki\Extensions\LDAPAuthentication\Config::getVersion() ) === null
) {
	die( "\nLDAPAuthentication is not available, please check your Composer or LocalSettings.\n" );
}

print sprintf( "\n%-20s%s\n", "LDAPAuthentication: ", $version );
