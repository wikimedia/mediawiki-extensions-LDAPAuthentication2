<?php

namespace MediaWiki\Extension\LDAPAuthentication2;

use Exception;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Extension\LDAPProvider\ClientConfig;
use MediaWiki\Extension\LDAPProvider\ClientFactory;
use MediaWiki\Extension\LDAPProvider\LDAPNoDomainConfigException as NoDomain;
use MediaWiki\Extension\LDAPProvider\UserDomainStore;
use MediaWiki\Extension\PluggableAuth\PluggableAuthLogin;
use MediaWiki\Logger\LoggerFactory;
use MediaWiki\User\UserFactory;
use MediaWiki\User\UserIdentity;
use MWException;
use PasswordFactory;
use User;
use Wikimedia\Rdbms\ILoadBalancer;

class PluggableAuth extends \MediaWiki\Extension\PluggableAuth\PluggableAuth {

	const DOMAIN_SESSION_KEY = 'ldap-authentication-selected-domain';

	/**
	 * Domain value in case of local domain
	 */
	const DOMAIN_VALUE_LOCAL = 'local';

	/**
	 * Data key name, where domain name is stored
	 */
	const DOMAIN = 'domain';

	/**
	 * Name of username extra login field
	 */
	const USERNAME = 'username';

	/**
	 * Name of password extra login field
	 */
	const PASSWORD = 'password';

	/**
	 * AuthManager instance to manage authentication session data
	 *
	 * @var AuthManager
	 */
	private $authManager;

	/**
	 * @var UserFactory
	 */
	private $userFactory;

	/**
	 * @var ILoadBalancer
	 */
	private $loadBalancer;

	/**
	 * @var PasswordFactory
	 */
	private $passwordFactory;

	/**
	 * @param UserFactory $userFactory
	 * @param AuthManager $authManager
	 * @param ILoadBalancer $loadBalancer
	 * @param PasswordFactory $passwordFactory
	 */
	public function __construct(
		UserFactory $userFactory,
		AuthManager $authManager,
		ILoadBalancer $loadBalancer,
		PasswordFactory $passwordFactory
	) {
		$this->userFactory = $userFactory;
		$this->authManager = $authManager;
		$this->loadBalancer = $loadBalancer;
		$this->passwordFactory = $passwordFactory;

		$this->setLogger( LoggerFactory::getInstance( 'LDAPAuthentication2' ) );
	}

	/**
	 * Authenticates against LDAP
	 * @param int|null &$id not used
	 * @param string|null &$username set to username
	 * @param string|null &$realname set to real name
	 * @param string|null &$email set to email
	 * @param string|null &$errorMessage any errors
	 * @return bool false on failure
	 * @SuppressWarnings( UnusedFormalParameter )
	 * @SuppressWarnings( ShortVariable )
	 */
	public function authenticate(
		?int &$id,
		?string &$username,
		?string &$realname,
		?string &$email,
		?string &$errorMessage
	): bool {
		$extraLoginFields = $this->authManager->getAuthenticationSessionData(
			PluggableAuthLogin::EXTRALOGINFIELDS_SESSION_KEY
		);

		$data = $this->getData();
		$domain = $data->get( static::DOMAIN );
		$username = $extraLoginFields[static::USERNAME] ?? '';
		$password = $extraLoginFields[static::PASSWORD] ?? '';

		$this->getLogger()->info( 'Try to authenticate user: ' . $username );

		$isLocal = $this->maybeLocalLogin( $domain, $username, $password, $id, $errorMessage );
		if ( $isLocal !== null ) {
			return $isLocal;
		}

		$this->getLogger()->info( 'Not local login. Checking LDAP...' );

		if ( !$this->checkLDAPLogin(
			$domain, $username, $password, $realname, $email, $errorMessage
		) ) {
			return false;
		}

		$username = $this->normalizeUsername( $username );
		$user = $this->userFactory->newFromName( $username );
		if ( $user !== false && $user->getId() !== 0 ) {
			$id = $user->getId();

			// Make sure that the user-domain-relation is updated for existing users.
			// PluggableAuth will only call this when a user get's newly created.
			$this->saveExtraAttributes( $id );
		}

		return true;
	}

	/**
	 * Normalize usernames as desired.
	 *
	 * @param string $username to normalize
	 * @return string username with any normalization
	 */
	protected function normalizeUsername( $username ) {
		/**
		 * this is a feature after updating wikis which used strtolower on usernames.
		 * to use it, set this in LocalSettings.php:
		 * $LDAPAuthentication2UsernameNormalizer = 'strtolower';
		 */
		$config = Config::newInstance();
		$normalizer = $config->get( "UsernameNormalizer" );
		if ( !empty( $normalizer ) ) {
			if ( !is_callable( $normalizer ) ) {
				throw new MWException(
					"The UsernameNormalizer for LDAPAuthentiation2 should be callable"
				);
			}
			$username = call_user_func( $normalizer, $username );
		}
		return $username;
	}

	/**
	 * If a local login is attempted, see if they're allowed, try it if they
	 * are, and return success or faillure.  Otherwise, if no local login is
	 * attempted, return null.
	 *
	 * @param string $domain we are logging into
	 * @param string &$username for the user
	 * @param string $password for the user
	 * @param int &$id value of id
	 * @param string &$errorMessage any error message for the user
	 *
	 * @return ?bool
	 */
	protected function maybeLocalLogin(
		$domain,
		&$username,
		$password,
		&$id,
		&$errorMessage
	) {
		if ( $domain === static::DOMAIN_VALUE_LOCAL ) {
			$config = Config::newInstance();
			if ( !$config->get( "AllowLocalLogin" ) ) {
				$this->getLogger()->error( 'Local logins are not allowed.' .
					'Check "$LDAPAuthentication2AllowLocalLogin" for more details' );
				$errorMessage = wfMessage( 'ldapauthentication2-no-local-login' )->plain();
				return false;
			}
			// Validate local user the mediawiki way
			$user = $this->checkLocalPassword( $username, $password );
			if ( $user ) {
				$id = $user->getId();
				$username = $user->getName();

				$this->authManager->setAuthenticationSessionData(
					static::DOMAIN_SESSION_KEY,
					$domain
				);

				$this->getLogger()->info( 'Local login succeeded.' );
				return true;
			}

			$errorMessage = wfMessage(
				'ldapauthentication2-error-local-authentication-failed'
			)->plain();
			$this->getLogger()->error( 'Local authentication failed. Username: ' . $username );

			return false;
		}

		return null;
	}

	/**
	 * Attempt a login and get info (realname, username) from LDAP
	 *
	 * @param string $domain
	 * @param string &$username username used for binding is passed in, but
	 *     chosen attribute is returned here
	 * @param string $password
	 * @param string &$realname Real name from LDAP
	 * @param string &$email for the user from LDAP
	 * @param string &$errorMessage any error message for the user
	 *
	 * @return ?bool
	 */
	protected function checkLDAPLogin(
		$domain,
		&$username,
		$password,
		&$realname,
		&$email,
		&$errorMessage
	) {
		/* This is a workaround: As "PluggableAuthUserAuthorization" hook is
		 * being called before PluggableAuth::saveExtraAttributes (see below)
		 * we can not rely on LdapProvider\UserDomainStore here. Further
		 * complicating things, we can not persist the domain here, as the
		 * user id may be null (first login)
		 */
		$this->authManager->setAuthenticationSessionData(
			static::DOMAIN_SESSION_KEY,
			$domain
		);

		$ldapClient = null;
		try {
			$ldapClient = ClientFactory::getInstance()->getForDomain( $domain );
		} catch ( NoDomain $e ) {
			$errorMessage = wfMessage( 'ldapauthentication2-no-domain-chosen' )->plain();
			return false;
		}

		$this->getLogger()->info( 'LDAP domain: ' . $domain );

		if ( !$ldapClient->canBindAs( $username, $password ) ) {
			$errorMessage = wfMessage(
				'ldapauthentication2-error-authentication-failed', $domain
			)->text();

			$this->getLogger()->error( 'Could not bind to LDAP domain with given user: ' . $username );
			return false;
		}
		try {
			$result = $ldapClient->getUserInfo( $username );

			if ( $result ) {
				if ( !isset( $result[$ldapClient->getConfig( ClientConfig::USERINFO_USERNAME_ATTR )] ) ) {
					$this->getLogger()->error( 'Username not found in user info provided by LDAP!' .
						'Please check LDAP domain configuration. Specifically ' .
						ClientConfig::USERINFO_USERNAME_ATTR );
					$this->getLogger()->debug( "LDAP user info results for user $username: " . print_r( $result, true ) );

					// We anyway cannot proceed if we don't have correct username from LDAP
					return false;
				}

				$username = $result[$ldapClient->getConfig( ClientConfig::USERINFO_USERNAME_ATTR )];
				$realname = $result[$ldapClient->getConfig( ClientConfig::USERINFO_REALNAME_ATTR )];
				// maybe there are no emails stored in LDAP, this prevents php notices:
				$email = $result[$ldapClient->getConfig( ClientConfig::USERINFO_EMAIL_ATTR )] ?? '';
			} else {
				$this->getLogger()->error( "No user info found for user: $username." .
					'Please check LDAP domain configuration' );
			}
		} catch ( Exception $ex ) {
			$errorMessage = wfMessage(
				'ldapauthentication2-error-authentication-failed-userinfo', $domain
			)->text();

			wfDebugLog( 'LDAPAuthentication2', "Error fetching userinfo: {$ex->getMessage()}" );
			wfDebugLog( 'LDAPAuthentication2', $ex->getTraceAsString() );

			return false;
		}

		$this->getLogger()->info( 'LDAP login succeeded.' );

		return true;
	}

	/**
	 * @param UserIdentity &$user to log out
	 */
	public function deauthenticate( UserIdentity &$user ): void {
		// Nothing to do, really
		$user = null;
	}

	/**
	 * @param int $userId for user
	 */
	public function saveExtraAttributes( int $userId ): void {
		$domain = $this->authManager->getAuthenticationSessionData(
			static::DOMAIN_SESSION_KEY
		);

		/**
		 * This can happen, when user account creation was initiated by a foreign source
		 * (e.g Auth_remoteuser). There is no way of knowing the domain at this point.
		 * This can also not be a local login attempt as it would be caught in `authenticate`.
		 */
		if ( $domain === null ) {
			return;
		}
		$userDomainStore = new UserDomainStore( $this->loadBalancer );

		$userDomainStore->setDomainForUser(
			$this->userFactory->newFromId( $userId ),
			$domain
		);
	}

	/**
	 * Return user if the authentication is successful, null otherwise.
	 *
	 * @param string $username
	 * @param string $password
	 * @return ?User
	 */
	protected function checkLocalPassword( $username, $password ) {
		$user = $this->userFactory->newFromName( $username );

		$dbr = $this->loadBalancer->getConnection( DB_REPLICA );
		$row = $dbr->selectRow( 'user', 'user_password', [ 'user_name' => $user->getName() ] );
		$passwordInDB = $this->passwordFactory->newFromCiphertext( $row->user_password );

		return $passwordInDB->verify( $password ) ? $user : null;
	}

	/**
	 * @inheritDoc
	 */
	public static function getExtraLoginFields(): array {
		return [
			static::USERNAME => [
				'type' => 'string',
				'label' => wfMessage( 'userlogin-yourname' ),
				'help' => wfMessage( 'authmanager-username-help' ),
			],
			static::PASSWORD => [
				'type' => 'password',
				'label' => wfMessage( 'userlogin-yourpassword' ),
				'help' => wfMessage( 'authmanager-password-help' ),
				'sensitive' => true,
			]
		];
	}
}
