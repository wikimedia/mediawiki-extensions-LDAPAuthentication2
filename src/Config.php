<?php

namespace MediaWiki\Extension\LDAPAuthentication2;

use GlobalVarConfig;

class Config extends GlobalVarConfig {
	const VERSION = "1.0.2";

	public function __construct() {
		parent::__construct( 'LDAPAuthentication2' );
	}

	/**
	 * Factory method for MediaWikiServices
	 * @return Config
	 */
	public static function newInstance() {
		return new self();
	}

	/**
	 * Convenience function to show the tests we can actually load.
	 *
	 * @return string
	 */
	public static function getVersion() {
		return self::VERSION;
	}

	/**
	 * Helper function to retrieve SSL config as object
	 *
	 * @return stdClass
	 */
        public static function getSSLConfig()
        {
                $sslconfig = new \stdClass;

                $sslconfig->enabled = $GLOBALS["LDAPAuthentication2SSLClientCertEnabled"];
                $sslconfig->prefix = $GLOBALS["LDAPAuthentication2SSLClientCertPrefix"];
                $sslconfig->field = $GLOBALS["LDAPAuthentication2SSLClientCertField"];
                $sslconfig->fieldParse = $GLOBALS["LDAPAuthentication2SSLClientCertFieldParse"];
                $sslconfig->fieldSeparator = $GLOBALS["LDAPAuthentication2SSLClientCertFieldSeparator"];
                $sslconfig->keyValueSeparator = $GLOBALS["LDAPAuthentication2SSLClientCertKeyValueSeparator"];
                $sslconfig->keySelector = $GLOBALS["LDAPAuthentication2SSLClientCertKeySelector"];
                $sslconfig->valueSeparators = $GLOBALS["LDAPAuthentication2SSLClientCertValueSeparators"];
                $sslconfig->requirePassword = $GLOBALS["LDAPAuthentication2SSLClientCertRequirePassword"];
                $sslconfig->autoLogin = $GLOBALS["LDAPAuthentication2SSLClientCertAutoLogin"];

                return $sslconfig;
        }
        
	/**
	 * Helper function to retrieve SSL client cert username
	 *
	 * @return string
	 */
        public static function getSSLUsername()
        {
                $sslconfig = self::getSSLConfig();
                
                if (!$sslconfig->prefix)
                        $sslconfig->prefix = "SSL_CLIENT_S_";

                if (!$sslconfig->field)
                        return null;

                if (!$sslconfig->fieldParse)
                {
                        if (isset($_SERVER[$sslconfig->prefix.$sslconfig->field]))
                                return $_SERVER[$sslconfig->prefix.$sslconfig->field];
                        else
                                return null;
                }

                if (!$sslconfig->keySelector)
                        return null;

                $fields = explode($sslconfig->fieldSeparator, $_SERVER[$sslconfig->prefix.$sslconfig->field]);

                if (!count($fields))
                        return null;

                $username = null;

                foreach ($fields as $keyvalue)
                {
                        if ($sslconfig->keyValueSeparator)
                        {
                                $keyval = explode($sslconfig->keyValueSeparator, $keyvalue);

                                $key = $keyval[0];
                                $val = ((isset($keyval[1])) ? $keyval[1] : null);

                                if ($key == $sslconfig->keySelector)
                                {
                                        if ($sslconfig->valueSeparators)
                                        {
                                                if (is_array($sslconfig->valueSeparators))
                                                {
                                                        foreach ($sslconfig->valueSeparators as $sepkey => $sepvalue)
                                                        {
                                                                $sepval = explode($sepkey, $val);
                                                                $val = ((isset($sepval[$sepvalue])) ? $sepval[$sepvalue] : $val);
                                                        }
                                                }
                                                else
                                                {
                                                        $sepval = explode($sslconfig->valueSeparators, $val);
                                                        $val = $sepval[0];
                                                }
                                        }

                                        $username = $val;
                                        break;
                                }
                        }
                        else
                        {
                                if ($keyvalue == $sslconfig->keySelector)
                                {
                                        $username = $keyvalue;
                                        break;
                                }
                        }
                }

                if ($username)
                        return $username;

                return null;
        }
}
