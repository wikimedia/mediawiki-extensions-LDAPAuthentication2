<?php

namespace MediaWiki\Extension\LDAPAuthentication2\HookHandler;

use MediaWiki\SpecialPage\Hook\AuthChangeFormFieldsHook;

class ReorderLoginFields implements AuthChangeFormFieldsHook {

	private const FIELD_ORDER = [
		'username' => 10,
		'password' => 20,
		'rememberMe' => 30,
		'loginattempt' => 40,
		'linkcontainer' => 60,
		'passwordReset' => 70,
	];

	private const PLUGGABLE_AUTH_BASE_WEIGHT = 50;
	private const PLUGGABLE_AUTH_INCREMENT = 1;

	/**
	 * @inheritDoc
	 */
	public function onAuthChangeFormFields( $requests, $fieldInfo, &$formDescriptor, $action ) {
		// Assign weights to predefined fields
		foreach ( self::FIELD_ORDER as $field => $weight ) {
			if ( isset( $formDescriptor[$field] ) ) {
				$formDescriptor[$field]['weight'] = $weight;
			}
		}

		// Handle multiple `pluggableauthloginX` fields dynamically
		$pluggableAuthWeight = self::PLUGGABLE_AUTH_BASE_WEIGHT;
		foreach ( array_keys( $formDescriptor ) as $fieldName ) {
			if ( preg_match( '/^pluggableauthlogin\d$/', $fieldName ) ) {
				$formDescriptor[$fieldName]['weight'] = $pluggableAuthWeight;
				$pluggableAuthWeight += self::PLUGGABLE_AUTH_INCREMENT;
			}
		}
	}
}
