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

use Wikimedia\Rdbms\ILBFactory;
use Wikimedia\Rdbms\ILoadBalancer;
use Wikimedia\Rdbms\LBFactory;

class DBInterface {

	/**
	 * @var LBFactory
	 */
	private $loadBalancerFactory;

	/**
	 * @var ILoadBalancer
	 */
	private $loadBalancer;

	public function __construct(
		LBFactory $loadBalancerFactory,
		ILoadBalancer $loadBalancer
	) {
		$this->loadBalancerFactory = $loadBalancerFactory;
		$this->loadBalancer = $loadBalancer;
	}

	/**
	 * @param string $email
	 * @return ?array
	 */
	public function findUser( string $email ): ?array {
		$dbr = $this->loadBalancer->getConnection( DB_REPLICA );
		$row = $dbr->newSelectQueryBuilder()
			->select(
				[
					'user_id',
					'user_name',
					'user_real_name'
				]
			)
			->from( 'user' )
			->where(
				[
					'user_email' => $email
				]
			)
			->caller( __METHOD__ )->fetchRow();
		if ( $row === false ) {
			return null;
		} else {
			return [
				'id' => $row->user_id,
				'username' => $row->user_name,
				'realname' => $row->user_real_name
			];
		}
	}

	/**
	 * @param string $jwt
	 * @param string $iv
	 * @param string $email
	 * @param string $entropy
	 * @param int $expiry
	 * @return void
	 */
	public function saveToken(
		string $jwt,
		string $iv,
		string $email,
		string $entropy,
		int $expiry
	): void {
		$dbw = $this->loadBalancer->getConnection( DB_PRIMARY );
		$dbw->insert(
			'magic_link_auth',
			[
				'mla_jwt' => $jwt,
				'mla_iv' => $iv,
				'mla_email' => $email,
				'mla_entropy' => $entropy,
				'mla_expiry' => $expiry
			],
			__METHOD__
		);
	}

	/**
	 * @param string $jwt
	 * @return ?array
	 */
	public function getToken( string $jwt ): ?array {
		$dbr = $this->loadBalancer->getConnection( DB_REPLICA );
		$row = $dbr->newSelectQueryBuilder()
			->select(
				[
					'mla_iv',
					'mla_email',
					'mla_entropy',
					'mla_expiry'
				]
			)
			->from( 'magic_link_auth' )
			->where(
				[
					'mla_jwt' => $jwt
				]
			)
			->caller( __METHOD__ )->fetchRow();
		if ( $row === false ) {
			return null;
		} else {
			return [
				'iv' => $row->mla_iv,
				'email' => $row->mla_email,
				'entropy' => $row->mla_entropy,
				'expiry' => $row->mla_expiry
			];
		}
	}

	/**
	 * @param string $jwt
	 * @return void
	 */
	public function deleteToken( string $jwt ): void {
		$dbw = $this->loadBalancer->getConnection( DB_PRIMARY );
		$dbw->delete(
			'magic_link_auth',
			[
				'mla_jwt' => $jwt
			],
			__METHOD__
		);
	}

	/**
	 * @return void
	 */
	public function purgeExpiredTokens(): void {
		$now = time();
		$dbw = $this->loadBalancer->getConnection( DB_PRIMARY );
		$dbw->delete(
			'magic_link_auth',
			[
				'mla_expiry < ' . $now
			],
			__METHOD__
		);
	}

	/**
	 * @return void
	 */
	public function restInPeace() {
		$this->loadBalancerFactory->commitPrimaryChanges();
		$this->loadBalancerFactory->shutdown( ILBFactory::SHUTDOWN_NO_CHRONPROT );
	}
}
