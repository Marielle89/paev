<?php

namespace App\Service;

final class ElectionLab6Service
{
    private \Redis $redis;

    private const VOTERS = ['A', 'B', 'C', 'D', 'E'];

    private const CANDIDATES = [
        'A' => 24,
        'B' => 30,
    ];

    private const MEDIUMS = ['M1', 'M2'];

    private const MEDIUM_LOW_MAP = [
        'M1' => ['L1', 'L2'],
        'M2' => ['L3', 'L4'],
    ];

    private const VOTER_MEDIUM_MAP = [
        'A' => 'M1',
        'B' => 'M1',
        'C' => 'M1',
        'D' => 'M2',
        'E' => 'M2',
    ];

    private const KEY_BR_REGISTRY   = 'lab6_br_registry';
    private const KEY_VOTER_KEYS    = 'lab6_voter_keys';
    private const KEY_CEC_KEYS      = 'lab6_cec_keys';
    private const KEY_MEDIUM_KEYS   = 'lab6_medium_keys';
    private const KEY_TOKENS        = 'lab6_tokens';
    private const KEY_MEDIUM_DECODE = 'lab6_medium_decode';
    private const KEY_CEC_PUBLISH   = 'lab6_cec_publish';
    private const KEY_TALLY         = 'lab6_tally';
    private const KEY_LOG           = 'lab6_log';

    public function __construct(
        private readonly RsaService $rsa,
        string $redisHost,
        int $redisPort
    ) {
        $this->redis = new \Redis();
        $this->redis->connect($redisHost, $redisPort);
    }

    // -------------------- Public API --------------------

    public function reset(): void
    {
        $this->redis->del(
            self::KEY_BR_REGISTRY,
            self::KEY_VOTER_KEYS,
            self::KEY_CEC_KEYS,
            self::KEY_MEDIUM_KEYS,
            self::KEY_TOKENS,
            self::KEY_MEDIUM_DECODE,
            self::KEY_CEC_PUBLISH,
            self::KEY_TALLY,
            self::KEY_LOG,
            $this->lowKey('L1'),
            $this->lowKey('L2'),
            $this->lowKey('L3'),
            $this->lowKey('L4')
        );

        $this->log('RESET');
    }

    public function setup(): array
    {
        $this->reset();

        // 1) BR registry + voter signing keys
        foreach (self::VOTERS as $voter) {
            $voterKey = $this->rsa->generateKeyPair(512);
            $this->redis->hSet(
                self::KEY_VOTER_KEYS,
                $voter,
                json_encode($voterKey, JSON_UNESCAPED_UNICODE)
            );

            $registry = [
                'registered' => true,
                'rn' => strtoupper(bin2hex(random_bytes(4))),
                'medium' => self::VOTER_MEDIUM_MAP[$voter],
                'tokenIssued' => false,
            ];

            $this->redis->hSet(
                self::KEY_BR_REGISTRY,
                $voter,
                json_encode($registry, JSON_UNESCAPED_UNICODE)
            );
        }

        // 2) CEC keys for blind signature
        $cec = $this->rsa->generateKeyPair(512);
        $this->redis->set(self::KEY_CEC_KEYS, json_encode($cec, JSON_UNESCAPED_UNICODE));

        // 3) Medium commission keys (M1, M2)
        foreach (self::MEDIUMS as $medium) {
            $mediumKey = $this->rsa->generateKeyPair(512);

            $this->redis->hSet(
                self::KEY_MEDIUM_KEYS,
                $medium,
                json_encode($mediumKey, JSON_UNESCAPED_UNICODE)
            );
        }

        // 4) clear medium decoded buckets
        foreach (self::MEDIUMS as $medium) {
            $this->redis->hDel(self::KEY_MEDIUM_DECODE, $medium);
        }

        // 5) init tally
        $this->redis->hMSet(self::KEY_TALLY, ['A' => 0, 'B' => 0, 'invalid' => 0]);

        $this->log('SETUP: BR, CEC, M1/M2, L1..L4 initialized');

        return $this->state();
    }

    public function requestBlindToken(string $voter): array
    {
        $this->assertVoter($voter);

        $registry = $this->getRegistry($voter);
        if (!$registry['registered']) {
            return ['ok' => false, 'error' => 'NOT_REGISTERED'];
        }
        if ($registry['tokenIssued']) {
            return ['ok' => false, 'error' => 'TOKEN_ALREADY_ISSUED'];
        }

        $cec = $this->getCecKeys();

        $ballotId = (string) random_int(100000, 999999);

        $m = gmp_init($ballotId, 10);
        $e = gmp_init($cec['e'], 10);
        $d = gmp_init($cec['d'], 10);
        $n = gmp_init($cec['n'], 10);

        $r = $this->randomCoprimeToN($n);
        $rPowE = gmp_powm($r, $e, $n);
        $blinded = gmp_mod(gmp_mul($m, $rPowE), $n);

        $signedBlind = gmp_powm($blinded, $d, $n);

        $rInv = gmp_invert($r, $n);
        if ($rInv === false) {
            return ['ok' => false, 'error' => 'R_INVERSE_FAILED'];
        }

        $blindSig = gmp_strval(gmp_mod(gmp_mul($signedBlind, $rInv), $n), 10);

        $token = [
            'ballotId' => $ballotId,
            'blindSig' => $blindSig,
            'medium' => $registry['medium'],
            'used' => false,
        ];

        $this->redis->hSet(self::KEY_TOKENS, $voter, json_encode($token, JSON_UNESCAPED_UNICODE));

        $registry['tokenIssued'] = true;
        $this->redis->hSet(self::KEY_BR_REGISTRY, $voter, json_encode($registry, JSON_UNESCAPED_UNICODE));

        $this->log("CEC: blind token issued for {$voter}, ballotId={$ballotId}, medium={$registry['medium']}");

        return ['ok' => true];
    }

    public function castVote(string $voter, string $choice): array
    {
        $this->assertVoter($voter);

        if (!isset(self::CANDIDATES[$choice])) {
            return ['ok' => false, 'error' => 'BAD_CHOICE'];
        }

        $token = $this->getToken($voter);
        if ($token === null) {
            return ['ok' => false, 'error' => 'NO_BLIND_TOKEN'];
        }
        if ($token['used']) {
            return ['ok' => false, 'error' => 'TOKEN_ALREADY_USED'];
        }

        $candidateId = self::CANDIDATES[$choice];
        [$part1, $part2] = $this->splitCandidateId($candidateId);

        $medium = (string)$token['medium'];

        try {
            $mediumKey = $this->getMediumKeys($medium);
        } catch (\Throwable $e) {
            return ['ok' => false, 'error' => $e->getMessage()];
        }

        [$low1, $low2] = self::MEDIUM_LOW_MAP[$medium];

        $cipher1 = $this->rsa->encryptNumber((string)$part1, $mediumKey['e'], $mediumKey['n']);
        $cipher2 = $this->rsa->encryptNumber((string)$part2, $mediumKey['e'], $mediumKey['n']);

        $voterKey = $this->getVoterKeys($voter);

        $payload1 = $token['ballotId'] . '|' . $medium . '|' . $low1 . '|' . $cipher1;
        $payload2 = $token['ballotId'] . '|' . $medium . '|' . $low2 . '|' . $cipher2;

        $hash1 = $this->rsa->labHash($payload1, $voterKey['n']);
        $hash2 = $this->rsa->labHash($payload2, $voterKey['n']);

        $sig1 = $this->rsa->signMessageNumber($hash1, $voterKey['d'], $voterKey['n']);
        $sig2 = $this->rsa->signMessageNumber($hash2, $voterKey['d'], $voterKey['n']);

        $r1 = $this->lowReceive($low1, $medium, $voter, $token['ballotId'], $token['blindSig'], $cipher1, $sig1);
        $r2 = $this->lowReceive($low2, $medium, $voter, $token['ballotId'], $token['blindSig'], $cipher2, $sig2);

        if (!$r1['ok'] || !$r2['ok']) {
            return ['ok' => false, 'error' => 'LOW_REJECTED'];
        }

        $token['used'] = true;
        $this->redis->hSet(self::KEY_TOKENS, $voter, json_encode($token, JSON_UNESCAPED_UNICODE));

        $this->log("VOTE: {$voter} -> {$choice} ({$candidateId}), medium={$medium}, parts={$part1}*{$part2}");
        return ['ok' => true];
    }

    public function mediumTally(string $medium): array
    {
        if (!in_array($medium, self::MEDIUMS, true)) {
            return ['ok' => false, 'error' => 'BAD_MEDIUM'];
        }

        [$low1, $low2] = self::MEDIUM_LOW_MAP[$medium];
        $store1 = $this->getLowStore($low1);
        $store2 = $this->getLowStore($low2);

        $mediumKey = $this->getMediumKeys($medium);

        $decoded = [];
        $localTally = ['A' => 0, 'B' => 0, 'invalid' => 0];

        $allBallotIds = array_unique(array_merge(array_keys($store1), array_keys($store2)));

        foreach ($allBallotIds as $ballotId) {
            if (!isset($store1[$ballotId], $store2[$ballotId])) {
                $decoded[$ballotId] = [
                    'result' => 'missing_part',
                    'blindSig' => $store1[$ballotId]['blindSig'] ?? $store2[$ballotId]['blindSig'] ?? '',
                ];
                $localTally['invalid']++;
                continue;
            }

            $c1 = (string)$store1[$ballotId]['cipher'];
            $c2 = (string)$store2[$ballotId]['cipher'];

            $n = gmp_init($mediumKey['n'], 10);
            $combined = gmp_strval(
                gmp_mod(
                    gmp_mul(gmp_init($c1, 10), gmp_init($c2, 10)),
                    $n
                ),
                10
            );

            $m = $this->rsa->decryptNumber($combined, $mediumKey['d'], $mediumKey['n']);
            $mInt = (int)$m;

            if ($mInt === self::CANDIDATES['A']) {
                $decoded[$ballotId] = ['result' => 'A', 'blindSig' => $store1[$ballotId]['blindSig']];
                $localTally['A']++;
            } elseif ($mInt === self::CANDIDATES['B']) {
                $decoded[$ballotId] = ['result' => 'B', 'blindSig' => $store1[$ballotId]['blindSig']];
                $localTally['B']++;
            } else {
                $decoded[$ballotId] = ['result' => 'invalid', 'blindSig' => $store1[$ballotId]['blindSig']];
                $localTally['invalid']++;
            }
        }

        $payload = [
            'results' => $decoded,
            'tally' => $localTally,
        ];

        $this->redis->hSet(self::KEY_MEDIUM_DECODE, $medium, json_encode($payload, JSON_UNESCAPED_UNICODE));

        $this->log("MEDIUM {$medium}: tally done");
        return ['ok' => true];
    }

    public function finalTally(): array
    {
        $cec = $this->getCecKeys();
        $e = $cec['e'];
        $n = $cec['n'];

        $mediumDecoded = $this->getMediumDecodedAll();
        $published = [];
        $seenBallotIds = [];

        $this->redis->hMSet(self::KEY_TALLY, ['A' => 0, 'B' => 0, 'invalid' => 0]);

        foreach ($mediumDecoded as $medium => $data) {
            foreach (($data['results'] ?? []) as $ballotId => $row) {
                if (isset($seenBallotIds[$ballotId])) {
                    $published[$ballotId] = 'duplicate';
                    $this->redis->hIncrBy(self::KEY_TALLY, 'invalid', 1);
                    continue;
                }

                $blindSig = (string)($row['blindSig'] ?? '');
                if ($blindSig === '') {
                    $published[$ballotId] = 'invalid';
                    $this->redis->hIncrBy(self::KEY_TALLY, 'invalid', 1);
                    continue;
                }

                $ok = $this->rsa->verifySignatureOnMessageNumber((string)$ballotId, $blindSig, $e, $n);

                if (!$ok) {
                    $published[$ballotId] = 'invalid';
                    $this->redis->hIncrBy(self::KEY_TALLY, 'invalid', 1);
                    continue;
                }

                $res = (string)($row['result'] ?? 'invalid');
                $published[$ballotId] = $res;

                if ($res === 'A') {
                    $this->redis->hIncrBy(self::KEY_TALLY, 'A', 1);
                } elseif ($res === 'B') {
                    $this->redis->hIncrBy(self::KEY_TALLY, 'B', 1);
                } else {
                    $this->redis->hIncrBy(self::KEY_TALLY, 'invalid', 1);
                }

                $seenBallotIds[$ballotId] = true;
            }
        }

        $this->redis->del(self::KEY_CEC_PUBLISH);
        foreach ($published as $ballotId => $res) {
            $this->redis->hSet(self::KEY_CEC_PUBLISH, $ballotId, $res);
        }

        $this->log('CEC: final tally published');
        return ['ok' => true];
    }

    public function tamperLowPart(string $low, string $ballotId, string $newCipher): array
    {
        $store = $this->getLowStore($low);
        if (!isset($store[$ballotId])) {
            return ['ok' => false, 'error' => 'BALLOT_NOT_FOUND'];
        }

        $store[$ballotId]['cipher'] = $newCipher;
        $this->saveLowStore($low, $store);

        $this->log("TAMPER: {$low} changed cipher for ballotId={$ballotId}");
        return ['ok' => true];
    }

    public function removeLowPart(string $low, string $ballotId): array
    {
        $store = $this->getLowStore($low);
        if (!isset($store[$ballotId])) {
            return ['ok' => false, 'error' => 'BALLOT_NOT_FOUND'];
        }

        unset($store[$ballotId]);
        $this->saveLowStore($low, $store);

        $this->log("REMOVE: {$low} removed ballotId={$ballotId}");
        return ['ok' => true];
    }

    public function addFakeLowPart(string $low, string $ballotId, string $cipher): array
    {
        $store = $this->getLowStore($low);
        $store[$ballotId] = [
            'voter' => 'FAKE',
            'medium' => in_array($low, ['L1', 'L2'], true) ? 'M1' : 'M2',
            'blindSig' => '123456',
            'cipher' => $cipher,
            'sig' => '123456',
        ];
        $this->saveLowStore($low, $store);

        $this->log("ADD_FAKE: {$low} added fake ballotId={$ballotId}");
        return ['ok' => true];
    }

    // UI

    public function state(): array
    {
        $registry = [];
        foreach (self::VOTERS as $v) {
            $registry[$v] = $this->getRegistry($v);
        }

        $tokens = [];
        foreach (self::VOTERS as $v) {
            $tokens[$v] = $this->getToken($v) ?? [
                'ballotId' => null,
                'blindSig' => null,
                'medium' => null,
                'used' => false,
            ];
        }

        $mediumDecoded = $this->getMediumDecodedAll();
        $publish = $this->redis->hGetAll(self::KEY_CEC_PUBLISH) ?: [];
        $t = $this->redis->hGetAll(self::KEY_TALLY) ?: [];

        $keysShort = [];
        foreach (self::MEDIUMS as $m) {
            $k = $this->safeGetMediumKeys($m);
            $keysShort[$m] = [
                'e' => $k['e'] ?? '',
                'n' => $this->short($k['n'] ?? '', 12),
                'd' => $this->short($k['d'] ?? '', 12),
            ];
        }

        $cec = $this->safeGetCecKeys();
        $cecShort = [
            'e' => $cec['e'] ?? '',
            'n' => $this->short($cec['n'] ?? '', 12),
            'd' => $this->short($cec['d'] ?? '', 12),
        ];

        return [
            'voters' => self::VOTERS,
            'candidates' => self::CANDIDATES,
            'registry' => $registry,
            'tokens' => $tokens,
            'lows' => [
                'L1' => $this->getLowStore('L1'),
                'L2' => $this->getLowStore('L2'),
                'L3' => $this->getLowStore('L3'),
                'L4' => $this->getLowStore('L4'),
            ],
            'mediumDecoded' => $mediumDecoded,
            'publish' => $publish,
            'tally' => [
                'A' => (int)($t['A'] ?? 0),
                'B' => (int)($t['B'] ?? 0),
                'invalid' => (int)($t['invalid'] ?? 0),
            ],
            'keysShort' => $keysShort,
            'cecShort' => $cecShort,
            'log' => $this->redis->lRange(self::KEY_LOG, 0, -1) ?: [],
        ];
    }

    // Logs, helpers

    private function lowReceive(string $low, string $medium, string $voter, string $ballotId, string $blindSig, string $cipher, string $sig): array
    {
        $voterKey = $this->getVoterKeys($voter);

        $payload = $ballotId . '|' . $medium . '|' . $low . '|' . $cipher;
        $hash = $this->rsa->labHash($payload, $voterKey['n']);

        $ok = $this->rsa->verifySignatureOnMessageNumber($hash, $sig, $voterKey['e'], $voterKey['n']);
        if (!$ok) {
            $this->log("LOW {$low}: reject bad voter signature for {$voter}, ballotId={$ballotId}");
            return ['ok' => false];
        }

        $store = $this->getLowStore($low);
        $store[$ballotId] = [
            'voter' => $voter,
            'medium' => $medium,
            'blindSig' => $blindSig,
            'cipher' => $cipher,
            'sig' => $sig,
        ];
        $this->saveLowStore($low, $store);

        $this->log("LOW {$low}: accepted part for {$voter}, ballotId={$ballotId}");
        return ['ok' => true];
    }

    private function splitCandidateId(int $candidateId): array
    {
        $common = [2, 3, 6];
        $choices = array_values(array_filter($common, fn($d) => $candidateId % $d === 0));
        $a = $choices[random_int(0, count($choices) - 1)];
        $b = intdiv($candidateId, $a);

        return random_int(0, 1) ? [$a, $b] : [$b, $a];
    }

    private function getRegistry(string $voter): array
    {
        $json = $this->redis->hGet(self::KEY_BR_REGISTRY, $voter);
        return $json ? (json_decode($json, true) ?: []) : [
            'registered' => false,
            'rn' => '',
            'medium' => '',
            'tokenIssued' => false,
        ];
    }

    private function getToken(string $voter): ?array
    {
        $json = $this->redis->hGet(self::KEY_TOKENS, $voter);
        return $json ? (json_decode($json, true) ?: null) : null;
    }

    private function getVoterKeys(string $voter): array
    {
        $json = $this->redis->hGet(self::KEY_VOTER_KEYS, $voter);
        if (!$json) {
            throw new \RuntimeException("No voter keys for {$voter}");
        }

        return json_decode($json, true);
    }

    private function getCecKeys(): array
    {
        $json = $this->redis->get(self::KEY_CEC_KEYS);
        if (!$json) {
            throw new \RuntimeException('Run setup first (CEC keys missing)');
        }

        return json_decode($json, true);
    }

    private function safeGetCecKeys(): array
    {
        $json = $this->redis->get(self::KEY_CEC_KEYS);
        return $json ? (json_decode($json, true) ?: []) : [];
    }

    private function getMediumKeys(string $medium): array
    {
        $json = $this->redis->hGet(self::KEY_MEDIUM_KEYS, $medium);
        if (!$json) {
            throw new \RuntimeException("No medium keys for {$medium}. Run setup first.");
        }

        return json_decode($json, true);
    }

    private function safeGetMediumKeys(string $medium): array
    {
        $json = $this->redis->hGet(self::KEY_MEDIUM_KEYS, $medium);
        return $json ? (json_decode($json, true) ?: []) : [];
    }

    private function lowKey(string $low): string
    {
        return 'lab6_low_' . $low;
    }

    private function getLowStore(string $low): array
    {
        $json = (string)($this->redis->get($this->lowKey($low)) ?: '{}');
        return json_decode($json, true) ?: [];
    }

    private function saveLowStore(string $low, array $store): void
    {
        $this->redis->set($this->lowKey($low), json_encode($store, JSON_UNESCAPED_UNICODE));
    }

    private function getMediumDecodedAll(): array
    {
        $out = [];
        foreach (self::MEDIUMS as $m) {
            $json = $this->redis->hGet(self::KEY_MEDIUM_DECODE, $m);
            $out[$m] = $json ? (json_decode($json, true) ?: []) : [];
        }
        return $out;
    }

    private function randomCoprimeToN(\GMP $n): \GMP
    {
        do {
            $r = gmp_init((string) random_int(2, 100000), 10);
        } while (gmp_cmp(gmp_gcd($r, $n), 1) !== 0);

        return $r;
    }

    private function assertVoter(string $voter): void
    {
        if (!in_array($voter, self::VOTERS, true)) {
            throw new \InvalidArgumentException('Unknown voter');
        }
    }

    private function short(string $x, int $keep = 10): string
    {
        $x = (string) $x;
        if (strlen($x) <= $keep * 2) {
            return $x;
        }

        return substr($x, 0, $keep) . '…' . substr($x, -$keep);
    }

    private function log(string $line): void
    {
        $this->redis->rPush(self::KEY_LOG, date('H:i:s') . ' ' . $line);
    }
}
