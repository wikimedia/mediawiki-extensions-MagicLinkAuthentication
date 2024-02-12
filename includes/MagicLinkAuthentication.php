<?php
/*
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

namespace MediaWiki\Extension\MagicLinkAuthentication;

use Config;
use MailAddress;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Extension\PluggableAuth\PluggableAuth;
use MediaWiki\Extension\PluggableAuth\PluggableAuthLogin;
use MediaWiki\Mail\Emailer;
use MediaWiki\User\UserIdentity;
use MediaWiki\User\UserIdentityLookup;
use Message;
use SpecialPage;
use Title;

class MagicLinkAuthentication extends PluggableAuth {

	/**
	 * @var Config
	 */
	private $mainConfig;

	/**
	 * @var AuthManager
	 */
	private $authManager;

	/**
	 * @var Emailer
	 */
	private $emailer;

	/**
	 * @var UserIdentityLookup
	 */
	private $userIdentityLookup;

	/**
	 * @var DBInterface
	 */
	private $dbInterface;

	/**
	 * @var JWTHandler
	 */
	private $jwtHandler;

	/**
	 * @var string
	 */
	private $signingKey;

	/**
	 * @var string
	 */
	private $encryptionKey;

	/**
	 * @var string
	 */
	private $emailSender;

	/**
	 * @param Config $mainConfig
	 * @param AuthManager $authManager
	 * @param Emailer $emailer
	 * @param UserIdentityLookup $userIdentityLookup
	 * @param DBInterface $dbInterface
	 * @param JWTHandler $jwtHandler
	 */
	public function __construct(
		Config $mainConfig,
		AuthManager $authManager,
		Emailer $emailer,
		UserIdentityLookup $userIdentityLookup,
		DBInterface $dbInterface,
		JWTHandler $jwtHandler
	) {
		$this->mainConfig = $mainConfig;
		$this->authManager = $authManager;
		$this->emailer = $emailer;
		$this->userIdentityLookup = $userIdentityLookup;
		$this->dbInterface = $dbInterface;
		$this->jwtHandler = $jwtHandler;
		$this->authManager->removeAuthenticationSessionData( 'LoginThrottle' );
	}

	/**
	 * @param string $configId
	 * @param array $config
	 * @return void
	 */
	public function init( string $configId, array $config ): void {
		parent::init( $configId, $config );
		$this->signingKey = $this->getConfigValue( 'SigningKey' );
		$this->encryptionKey = $this->getConfigValue( 'EncryptionKey' );
		$this->jwtHandler->init( $this->getConfigValue( 'TokenLifetime' ) );
		$this->emailSender = $this->getConfigValue( 'EmailSender' );
		if ( !$this->emailSender ) {
			$this->emailSender = $this->mainConfig->get( 'PasswordSender' );
		}
	}

	/**
	 * @param string $name
	 * @return mixed
	 */
	private function getConfigValue( string $name ) {
		return $this->getData()->has( $name ) ? $this->getData()->get( $name ) :
			$this->mainConfig->get( 'MagicLinkAuthentication_' . $name );
	}

	/**
	 * @return array[]
	 */
	public static function getExtraLoginFields(): array {
		return [
			'email' => [
				'type' => 'string',
				'label' => wfMessage( 'authmanager-email-label' ),
				'help' => wfMessage( 'authmanager-email-help' )
			]
		];
	}

	/**
	 * @param int|null &$id The user's user ID
	 * @param string|null &$username The user's username
	 * @param string|null &$realname The user's real name
	 * @param string|null &$email The user's email address
	 * @param string|null &$errorMessage Returns a descriptive message if there's an error
	 * @return bool true if the user has been authenticated and false otherwise
	 */
	public function authenticate(
		?int &$id,
		?string &$username,
		?string &$realname,
		?string &$email,
		?string &$errorMessage
	): bool {
		if ( $this->signingKey === null || $this->encryptionKey === null ) {
			$errorMessage = ( new Message( "magic-link-authentication-missing-secret" ) )->text();
			return false;
		}

		$code = $this->authManager->getRequest()->getVal( 'code' );
		if ( $code ) {
			return $this->validateCode( $code, $id, $username, $realname, $email );
		}
		$this->sendMagicLink();

		$redirectURL = SpecialPage::getTitleFor( 'ContinueMagicLinkAuthentication' )->getFullURL();
		header( 'Location: ' . $redirectURL );
		$this->dbInterface->restInPeace();
		exit;
	}

	/**
	 * @param string $code The code returned from the magic link
	 * @param int|null &$id The user's user ID
	 * @param string|null &$username The user's username
	 * @param string|null &$realname The user's real name
	 * @param string|null &$email The user's email address
	 * @return bool true if the user has been authenticated and false otherwise
	 */
	public function validateCode(
		string $code,
		?int &$id,
		?string &$username,
		?string &$realname,
		?string &$email
	): bool {
		$email = $this->jwtHandler->validateToken( $this->signingKey, $this->encryptionKey, $code );
		if ( !$email ) {
			return false;
		}
		$this->getLogger()->debug( 'Email: ' . $email );

		$result = $this->dbInterface->findUser( $email );
		if ( $result ) {
			$id = $result['id'];
			$username = $result['username'];
			$realname = $result['realname'];
			return true;
		}

		$preferred_username = $this->getPreferredUsername( $email );
		$this->getLogger()->debug( 'Preferred username: ' . $preferred_username . PHP_EOL );

		$username = $this->getAvailableUsername( $preferred_username );
		$this->getLogger()->debug( 'Available username: ' . $username . PHP_EOL );

		return true;
	}

	/**
	 * @return void
	 */
	private function sendMagicLink(): void {
		$extraLoginFields =
			$this->authManager->getAuthenticationSessionData( PluggableAuthLogin::EXTRALOGINFIELDS_SESSION_KEY );
		$email = $extraLoginFields['email'];
		$jwt = $this->jwtHandler->createToken( $this->signingKey, $this->encryptionKey, $email );

		$redirectURL = SpecialPage::getTitleFor( 'PluggableAuthLogin' )->getFullURL( [
			'code' => $jwt
		] );

		$to = new MailAddress( $email );
		$from = new MailAddress( $this->emailSender );
		$subject = ( new Message( 'magic-link-authentication-email-subject' ) )->text();
		$bodyText = $redirectURL;
		$this->emailer->send( $to, $from, $subject, $bodyText );
	}

	/**
	 * @param string $email
	 * @return ?string
	 */
	private function getPreferredUsername( string $email ): ?string {
		$pos = strpos( $email, '@' );
		if ( $pos !== false && $pos > 0 ) {
			$preferred_username = substr( $email, 0, $pos );
		} else {
			$preferred_username = $email;
		}
		$nt = Title::makeTitleSafe( NS_USER, $preferred_username );
		if ( $nt === null ) {
			return null;
		}
		return $nt->getText();
	}

	/**
	 * @param ?string $preferred_username
	 * @return string
	 */
	private function getAvailableUsername( ?string $preferred_username ): string {
		if ( $preferred_username === null ) {
			$preferred_username = 'User';
		}

		$userIdentity = $this->userIdentityLookup->getUserIdentityByName( $preferred_username );
		if ( !$userIdentity || !$userIdentity->isRegistered() ) {
			return $preferred_username;
		}

		$count = 1;
		$userIdentity = $this->userIdentityLookup->getUserIdentityByName( $preferred_username . $count );
		while ( $userIdentity && $userIdentity->isRegistered() ) {
			$count++;
			$userIdentity = $this->userIdentityLookup->getUserIdentityByName( $preferred_username . $count );
		}
		return $preferred_username . $count;
	}

	/**
	 * @param UserIdentity &$user
	 * @return void
	 */
	public function deauthenticate( UserIdentity &$user ): void {
		// intentionally left blank
	}

	/**
	 * @param int $id
	 * @return void
	 */
	public function saveExtraAttributes( int $id ): void {
		// intentionally left blank
	}
}
