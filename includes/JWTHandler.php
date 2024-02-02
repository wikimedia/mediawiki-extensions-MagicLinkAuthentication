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

class JWTHandler {

	/**
	 * @var int
	 */
	private $tokenLifetime;

	/**
	 * @var DBInterface
	 */
	private $dbInterface;

	/**
	 * @param DBInterface $dbInterface
	 */
	public function __construct(
		DBInterface $dbInterface
	) {
		$this->dbInterface = $dbInterface;
	}

	/**
	 * @param int $tokenLifetime
	 * @return void
	 */
	public function init( int $tokenLifetime ) {
		$this->tokenLifetime = $tokenLifetime;
	}

	/**
	 * @param string $secret
	 * @param string $email
	 * @return string
	 */
	public function createToken( string $secret, string $email ): string {
		$this->dbInterface->purgeExpiredTokens();

		$header = [ 'typ' => 'JWT', 'alg' => 'HS256' ];
		$base64UrlHeader = $this->base64URLencode( json_encode( $header ) );

		$iv = openssl_random_pseudo_bytes( openssl_cipher_iv_length( 'aes-256-cbc' ) );
		$entropy = $this->generateEntropy();
		$private = $this->encryptString(
			json_encode( [
				'email' => $email,
				'entropy' => $entropy
			] ),
			$secret,
			$iv
		);
		$now = time();
		$expiry = $now + $this->tokenLifetime;
		$payload = [
			'private' => $private,
			'iat' => $now,
			'exp' => $expiry
		];
		$base64UrlPayload = $this->base64URLencode( json_encode( $payload ) );

		$signature = hash_hmac(
			'sha256',
			$base64UrlHeader . "." . $base64UrlPayload,
			$secret,
			true
		);
		$signature = $this->base64URLencode( $signature );

		$jwt = $base64UrlHeader . "." . $base64UrlPayload . "." . $signature;

		$this->dbInterface->saveToken( $jwt, $iv, $email, $entropy, $expiry );

		return $jwt;
	}

	/**
	 * @param string $secret
	 * @param string $token
	 * @return ?string
	 */
	public function validateToken( string $secret, string $token ): ?string {
		$this->dbInterface->purgeExpiredTokens();
		$data = $this->dbInterface->getToken( $token );
		if ( !$data ) {
			return null;
		}
		$this->dbInterface->deleteToken( $token );

		list( $base64UrlHeader, $base64UrlPayload, $signature ) = explode( '.', $token );

		$header = json_decode( $this->base64URLdecode( $base64UrlHeader ), true );

		if ( !isset( $header['typ'] ) || $header['typ'] != 'JWT' ) {
			return null;
		}
		if ( !isset( $header['alg'] ) || $header['alg'] != 'HS256' ) {
			return null;
		}

		$expectedSignature = hash_hmac(
			'sha256',
			$base64UrlHeader . '.' . $base64UrlPayload,
			$secret,
			true
		);
		$expectedSignature = $this->base64URLencode( $expectedSignature );

		if ( $signature !== $expectedSignature ) {
			return null;
		}

		$payload = json_decode( $this->base64URLdecode( $base64UrlPayload ), true );

		if ( !isset( $payload['exp'] ) ) {
			return null;
		}
		if ( $payload['exp'] < time() ) {
			return null;
		}

		if ( !isset( $payload['private'] ) ) {
			return null;
		}
		$iv = $data['iv'];
		$private = json_decode( $this->decryptString( $payload['private'], $secret, $iv ), true );

		if ( !isset( $private['email' ] ) ) {
			return null;
		}
		if ( $data['email'] !== $private['email'] ) {
			return null;
		}
		if ( $data['entropy'] !== $private['entropy'] ) {
			return null;
		}
		return $private['email'];
	}

	/**
	 * @param string $value
	 * @return string
	 */
	private function base64URLencode( string $value ): string {
		return str_replace(
			[ '+', '/', '=' ],
			[ '-', '_', '' ],
			base64_encode( $value )
		);
	}

	/**
	 * @param string $value
	 * @return string
	 */
	private function base64URLdecode( string $value ): string {
		$padding = strlen( $value ) % 4;
		if ( $padding ) {
			$value .= str_repeat( '=', 4 - $padding );
		}
		return base64_decode( str_replace(
			[ '+', '/' ],
			[ '-', '_' ],
			$value
		) );
	}

	/**
	 * @return string
	 */
	private function generateEntropy(): string {
		$length = 32;
		$randomBytes = random_bytes( $length );
		return base64_encode( $randomBytes );
	}

	/**
	 * @param string $data
	 * @param string $key
	 * @param string $iv
	 * @return false|string
	 */
	private function encryptString( string $data, string $key, string $iv ) {
		return openssl_encrypt( $data, 'aes-256-cbc', $key, 0, $iv );
	}

	/**
	 * @param string $data
	 * @param string $key
	 * @param string $iv
	 * @return false|string
	 */
	private function decryptString( string $data, string $key, string $iv ) {
		return openssl_decrypt( $data, 'aes-256-cbc', $key, 0, $iv );
	}
}
