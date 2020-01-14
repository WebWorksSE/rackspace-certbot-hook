<?php

namespace App\Hook;

use OpenCloud\DNS\Resource\Domain;
use OpenCloud\Rackspace;

class Certbot
{
	private CONST ACME_CHALLENGE = '_acme-challenge.';
	private CONST RECORD_TYPE = 'TXT';

	/**
	 * @var Rackspace
	 */
	private $client;

	public function __construct()
	{
		$this->client = new Rackspace(
			Rackspace::US_IDENTITY_ENDPOINT,
			[
				'username' => Credentials::USER,
				'apiKey'   => Credentials::API_KEY
			],
			[
				Rackspace::SSL_CERT_AUTHORITY => 'system',
				Rackspace::CURL_OPTIONS => [
					CURLOPT_SSL_VERIFYPEER => true,
					CURLOPT_SSL_VERIFYHOST => 2,
				],
			]
		);
	}

	/**
	 * @param string $domainName
	 * @param string $recordValue
	 */
	public function createTXTRecordForDomain(string $domainName, string $recordValue): void
	{
		$domainName = $this->stripWildcardFromDomain($domainName);
		$baseDomainName = $this->getBaseDomain($domainName);
		$dnsService = $this->client->dnsService();

		/** @var Domain $domain */
		$domain = $dnsService->domainByName($baseDomainName);

		$records = $domain->recordList(array(
			'name' => self::ACME_CHALLENGE . $domainName,
			'type' => self::RECORD_TYPE
		));

		if (count($records) === 0) {
			$record = $domain->record([
				'type' => self::RECORD_TYPE,
				'name' => self::ACME_CHALLENGE . $domainName,
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
			$record->data = $recordValue;

			$record->update();
		}

		sleep(45);
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
			'type' => self::RECORD_TYPE
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

	/**
	 * @param string $domain
	 *
	 * @return string
	 */
	private function stripWildcardFromDomain(string $domain): string
	{
		if (strpos($domain, '*.') === 0) {
			return substr($domain, 2);
		}

		return $domain;
	}
}