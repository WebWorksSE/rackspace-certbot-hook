<?php

namespace App\Hook;

use OpenCloud\DNS\Resource\Domain;
use OpenCloud\Rackspace;

class Certbot
{
	private CONST ACME_CHALLENGE = '_acme-challenge.';

	/**
	 * @var Rackspace
	 */
	private $client;

	public function __construct()
	{
		$this->client = new Rackspace(Rackspace::US_IDENTITY_ENDPOINT, [
			'username' => Credentials::USER,
			'apiKey'   => Credentials::API_KEY
		]);
	}

	/**
	 * @param string $domainName
	 * @param string $recordValue
	 */
	public function createTXTRecordForDomain(string $domainName, string $recordValue): void
	{
		$baseDomainName = $this->getBaseDomain($domainName);
		$dnsService = $this->client->dnsService();

		/** @var Domain $domain */
		$domain = $dnsService->domainByName($baseDomainName);

		$records = $domain->recordList(array(
			'name' => self::ACME_CHALLENGE . $domainName,
			'type' => 'TXT'
		));

		if (count($records) === 0) {
			$record = $domain->record([
				'type' => 'TXT',
				'name' => '_acme-challenge.' . $domainName,
				'data' => $recordValue,
				'ttl' => 3600
			]);
			$record->create();
		} else {
			foreach ($records as $loadedRecord) {
				$loadedRecordId = $loadedRecord->id;
				break;
			}

			$record = $domain->record($loadedRecordId);

			$record->data = 'test456';
			$record->update();
		}
	}

	/**
	 * @param string $domainName
	 */
	public function deleteTXTRecordForDomain(string $domainName): void
	{
		$baseDomainName = $this->getBaseDomain($domainName);
		$dnsService = $this->client->dnsService();

		/** @var Domain $domain */
		$domain = $dnsService->domainByName($baseDomainName);

		$records = $domain->recordList(array(
			'name' => self::ACME_CHALLENGE . $domainName,
			'type' => 'TXT'
		));

		if (count($records) > 0) {
			foreach ($records as $loadedRecord) {
				$loadedRecordId = $loadedRecord->id;
				break;
			}

			$record = $domain->record($loadedRecordId);

			$record->delete();
		}
	}

	/**
	 * @param string $domain
	 *
	 * @return string
	 */
	private function getBaseDomain(string $domain): string
	{
		$baseDomain = strtolower(trim($domain));
		$count = substr_count($baseDomain, '.');

		if ($count === 2) {
			if (strlen(explode('.', $baseDomain)[1]) > 3) {
				$baseDomain = explode('.', $baseDomain, 2)[1];
			}
		} else if($count > 2) {
			$baseDomain = $this->getBaseDomain(explode('.', $baseDomain, 2)[1]);
		}

		return $baseDomain;
	}
}