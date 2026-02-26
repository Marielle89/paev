<?php

namespace App\Service;

final class ElectionLab3Service
{
    private \Redis $redis;

    // BR (Registration Bureau)
    private const BR_VOTERS = 'lab3_br_voters';
    private const BR_RN_TO_NAME = 'lab3_br_rn_to_name';
    private const BR_RN_POOL = 'lab3_br_rn_pool';
    private const BR_LOG = 'lab3_br_log';


    // EC (Election Commission)
    private const EC_KEYS = 'lab3_ec_keys';
    private const EC_RN_VALID = 'lab3_ec_rn_valid';
    private const EC_RN_USED = 'lab3_ec_rn_used';
    private const EC_ID_USED = 'lab3_ec_id_used';
    private const EC_TALLY = 'lab3_ec_tally';
    private const EC_PUBLISHED = 'lab3_ec_published';
    private const EC_LOG = 'lab3_ec_log';

    public function __construct(
        private readonly RsaService $rsa,
        string $redisHost,
        int $redisPort
    ) {
        $this->redis = new \Redis();
        $this->redis->connect($redisHost, $redisPort);
    }

    public function reset(): void
    {
        $this->redis->del(
            self::BR_VOTERS, self::BR_RN_TO_NAME, self::BR_RN_POOL, self::BR_LOG,
            self::EC_KEYS, self::EC_RN_VALID, self::EC_RN_USED, self::EC_ID_USED,
            self::EC_TALLY, self::EC_PUBLISHED, self::EC_LOG
        );
        $this->brLog("RESET");
        $this->ecLog("RESET");
    }

    public function setup(): array
    {
        $this->reset();

        // Keys for EC (for encrypt/decrypt)
        $ec = $this->rsa->generateKeyPair(512);
        $this->redis->set(self::EC_KEYS, json_encode($ec));

        // Init tally
        $this->redis->hMSet(self::EC_TALLY, ['A' => 0, 'B' => 0]);

        $this->ecLog("SETUP: EC keys generated");
        return [
            'ecPublic' => ['e' => $ec['e'], 'n' => $ec['n']],
        ];
    }

    // ---------- BR ----------

    public function brGetRn(string $name): ?string
    {
        $rn = $this->redis->hGet(self::BR_VOTERS, $name);
        return $rn ?: null;
    }

    // Test #1: one RN per voter name
    public function brIssueRn(string $name): array
    {
        $existing = $this->brGetRn($name);
        if ($existing) {
            $this->brLog("BR: {$name} already has RN={$existing}");
            return ['ok' => false, 'error' => 'ALREADY_HAS_RN', 'rn' => $existing];
        }

        $rn = $this->generateRn();
        $this->redis->hSet(self::BR_VOTERS, $name, $rn);
        $this->redis->hSet(self::BR_RN_TO_NAME, $rn, $name);
        $this->redis->sAdd(self::BR_RN_POOL, $rn);

        $this->brLog("BR: issued RN={$rn} to {$name}");
        return ['ok' => true, 'rn' => $rn];
    }

    // BR sends RN list to EC (without names)
    public function brSendRnListToEc(): array
    {
        $rns = $this->redis->sMembers(self::BR_RN_POOL) ?: [];
        if (!$rns) {
            return ['ok' => false, 'error' => 'NO_RNS', 'message' => 'No RN issued yet'];
        }

        // replace EC valid list
        $this->redis->del(self::EC_RN_VALID);
        foreach ($rns as $rn) {
            $this->redis->sAdd(self::EC_RN_VALID, $rn);
        }

        $this->brLog("BR: sent RN list to EC (count=" . count($rns) . ")");
        $this->ecLog("EC: received RN list from BR (count=" . count($rns) . ")");
        return ['ok' => true, 'count' => count($rns)];
    }

    // ---------- EC ----------

    public function ecPublic(): array
    {
        $ec = $this->getEcKeys();
        return ['e' => $ec['e'], 'n' => $ec['n']];
    }

    /**
     * Voter sends encrypted message to EC.
     * EC:
     *  - decrypts
     *  - verifies voter signature on payload
     *  - checks RN valid and unused
     *  - checks ID unused
     *  - stores published ballot by ID
     */
    public function ecReceiveEncryptedVote(string $cipher): array
    {
        $ec = $this->getEcKeys();

        $plain = $this->rsa->decryptString($cipher, $ec['d'], $ec['n']);
        $msg = json_decode($plain, true);

        if (!is_array($msg) || !isset($msg['payload'], $msg['sig'], $msg['voterPub'])) {
            $this->ecLog("EC: reject (bad message format)");
            return ['ok' => false, 'error' => 'BAD_FORMAT'];
        }

        $payload = $msg['payload'];
        $sigDec = (string)$msg['sig'];
        $voterPub = $msg['voterPub'];

        if (!is_array($payload) || !isset($payload['rn'], $payload['id'], $payload['vote'])) {
            $this->ecLog("EC: reject (bad payload)");
            return ['ok' => false, 'error' => 'BAD_PAYLOAD'];
        }

        $rn = (string)$payload['rn'];
        $id = (string)$payload['id'];
        $vote = (string)$payload['vote'];

        // signature check (RSA lab hash + powm)
        $payloadJson = json_encode($payload, JSON_UNESCAPED_UNICODE);
        $m = $this->rsa->labHash($payloadJson, $voterPub['n']); // hash mod n (voter)
        $okSig = $this->rsa->verifySignatureOnMessageNumber($m, $sigDec, $voterPub['e'], $voterPub['n']);

        if (!$okSig) {
            $this->ecLog("EC: reject (signature failed) rn={$rn} id={$id}");
            return ['ok' => false, 'error' => 'SIGNATURE_FAILED'];
        }

        // RN must be valid
        if (!$this->redis->sIsMember(self::EC_RN_VALID, $rn)) {
            $this->ecLog("EC: reject (invalid RN) rn={$rn}");
            return ['ok' => false, 'error' => 'INVALID_RN'];
        }

        // RN cannot be reused
        if ($this->redis->sIsMember(self::EC_RN_USED, $rn)) {
            $this->ecLog("EC: reject (RN already used) rn={$rn}");
            return ['ok' => false, 'error' => 'RN_ALREADY_USED'];
        }

        // ID cannot be reused
        if ($this->redis->sIsMember(self::EC_ID_USED, $id)) {
            $this->ecLog("EC: reject (ID already used) id={$id}");
            return ['ok' => false, 'error' => 'ID_ALREADY_USED'];
        }

        // accept
        $this->redis->sAdd(self::EC_RN_USED, $rn);
        $this->redis->sAdd(self::EC_ID_USED, $id);
        $this->redis->hIncrBy(self::EC_TALLY, $vote, 1);

        $published = [
            'payload' => $payload,
            'sig' => $sigDec,
            'voterPub' => $voterPub,
        ];
        $this->redis->hSet(self::EC_PUBLISHED, $id, json_encode($published, JSON_UNESCAPED_UNICODE));

        $this->ecLog("EC: accepted rn={$rn} id={$id} vote={$vote}");
        return ['ok' => true, 'accepted' => true];
    }

    public function results(): array
    {
        $t = $this->redis->hGetAll(self::EC_TALLY) ?: [];
        $published = $this->redis->hGetAll(self::EC_PUBLISHED) ?: [];

        // decode published for UI
        $pubDecoded = [];
        foreach ($published as $id => $json) {
            $pubDecoded[$id] = json_decode($json, true);
        }

        return [
            'tally' => ['A' => (int)($t['A'] ?? 0), 'B' => (int)($t['B'] ?? 0)],
            'published' => $pubDecoded,
            'brLog' => $this->redis->lRange(self::BR_LOG, 0, -1) ?: [],
            'ecLog' => $this->redis->lRange(self::EC_LOG, 0, -1) ?: [],
        ];
    }

    // voter check after publish
    public function checkMyVote(string $id, string $expectedVote): array
    {
        $json = $this->redis->hGet(self::EC_PUBLISHED, $id);
        if (!$json) {
            return ['ok' => false, 'error' => 'ID_NOT_FOUND'];
        }

        $data = json_decode($json, true);
        $actualVote = $data['payload']['vote'] ?? null;

        if ($actualVote === $expectedVote) {
            return ['ok' => true, 'match' => true, 'actualVote' => $actualVote];
        }

        return ['ok' => true, 'match' => false, 'actualVote' => $actualVote];
    }

    // ---------- helpers ----------

    private function getEcKeys(): array
    {
        $json = $this->redis->get(self::EC_KEYS);
        if (!$json) {
            throw new \RuntimeException('Run /lab3/setup first');
        }
        return json_decode($json, true);
    }

    private function generateRn(): string
    {
        // random long RN, hard to guess
        return 'RN-' . bin2hex(random_bytes(8));
    }

    private function brLog(string $s): void
    {
        $this->redis->rPush(self::BR_LOG, date('H:i:s') . ' ' . $s);
    }

    private function ecLog(string $s): void
    {
        $this->redis->rPush(self::EC_LOG, date('H:i:s') . ' ' . $s);
    }
}
