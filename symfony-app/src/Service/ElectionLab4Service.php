<?php
namespace App\Service;

final class ElectionLab4Service
{
    private \Redis $redis;

    private const KEY_CEC_KEYS   = 'lab4_cec_keys';     // json {e,n,d}
    private const KEY_VK1_STORE  = 'lab4_vk1_store';    // hash anonId -> json(message)
    private const KEY_VK2_STORE  = 'lab4_vk2_store';    // hash anonId -> json(message)
    private const KEY_VK1_PUB    = 'lab4_vk1_pub';      // hash anonId -> c1
    private const KEY_VK2_PUB    = 'lab4_vk2_pub';      // hash anonId -> c2
    private const KEY_RESULTS    = 'lab4_cec_results';  // hash anonId -> candidateId
    private const KEY_TALLY      = 'lab4_tally';        // hash A,B,invalid
    private const KEY_LOG        = 'lab4_log';          // list
    private const KEY_DECRYPTED = 'lab4_cec_decrypted'; // hash anonId -> decrypted number (m)

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
            self::KEY_CEC_KEYS, self::KEY_VK1_STORE, self::KEY_VK2_STORE,
            self::KEY_VK1_PUB, self::KEY_VK2_PUB,
            self::KEY_RESULTS, self::KEY_TALLY, self::KEY_LOG
        );
        $this->log("RESET");
    }

    public function setup(): array
    {
        $this->reset();

        // CEC keys for number-RSA
        $cec = $this->rsa->generateKeyPair(512);
        $this->redis->set(self::KEY_CEC_KEYS, json_encode($cec));

        $this->redis->hMSet(self::KEY_TALLY, ['A'=>0,'B'=>0,'invalid'=>0]);
        $this->log("SETUP: CEC keys generated");

        // candidates with many divisors
        return [
            'cecPublic' => ['e'=>$cec['e'], 'n'=>$cec['n']],
            'candidates' => [
                'A' => 24,
                'B' => 30,
            ]
        ];
    }

    public function cecPublic(): array
    {
        $cec = $this->getCec();
        return ['e'=>$cec['e'], 'n'=>$cec['n']];
    }

    public function candidates(): array
    {
        return ['A'=>24,'B'=>30];
    }

    /**
     * Split candidateId into 2 random factors (not pre-prepared).
     * We choose a factor from a pool that tends to be shared between candidates.
     */
    public function splitCandidateId(int $candidateId): array
    {
        // common divisors for 24 and 30: 2,3,6 (good so VK cannot infer uniquely)
        $common = [2,3,6];

        $choices = array_values(array_filter($common, fn($d) => $candidateId % $d === 0));
        $a = $choices[random_int(0, count($choices)-1)];
        $b = intdiv($candidateId, $a);

        // random order (which part goes to which VK)
        return random_int(0,1) ? [$a,$b] : [$b,$a];
    }

    /**
     * VK receives one part:
     * - verifies voter signature on (anonId|vk|cipher)
     * - stores message by anonId
     * If $tamperSig=true -> we simulate broken signature (test #1)
     */
    public function vkReceive(
        int $vkIndex,
        string $name,
        string $anonId,
        string $cipherPartDec,
        array $voterPub,
        string $sigDec
    ): array {
        // verify signature
        $payload = $anonId . '|' . $vkIndex . '|' . $cipherPartDec;

        // compute m = H(payload) mod voter_n
        $m = $this->rsa->labHash($payload, $voterPub['n']);
        $ok = $this->rsa->verifySignatureOnMessageNumber($m, $sigDec, $voterPub['e'], $voterPub['n']);

        if (!$ok) {
            $this->log("VK{$vkIndex}: reject bad signature for {$name}, anonId={$anonId}");
            return ['ok'=>false,'error'=>'BAD_SIGNATURE'];
        }

        $msg = [
            'name'=>$name,
            'anonId'=>$anonId,
            'cipher'=>$cipherPartDec,
            'voterPub'=>$voterPub,
            'sig'=>$sigDec,
        ];

        $key = $vkIndex === 1 ? self::KEY_VK1_STORE : self::KEY_VK2_STORE;
        $this->redis->hSet($key, $anonId, json_encode($msg, JSON_UNESCAPED_UNICODE));
        $this->log("VK{$vkIndex}: accepted part for {$name}, anonId={$anonId}, cipher={$cipherPartDec}");

        return ['ok'=>true];
    }

    /**
     * VK publishes its stored ciphertext parts (anonId -> cipher)
     */
    public function vkPublish(int $vkIndex): array
    {
        $storeKey = $vkIndex === 1 ? self::KEY_VK1_STORE : self::KEY_VK2_STORE;
        $pubKey   = $vkIndex === 1 ? self::KEY_VK1_PUB : self::KEY_VK2_PUB;

        $all = $this->redis->hGetAll($storeKey) ?: [];
        $this->redis->del($pubKey);

        foreach ($all as $anonId => $json) {
            $msg = json_decode($json, true);
            $this->redis->hSet($pubKey, $anonId, (string)$msg['cipher']);
        }

        $this->log("VK{$vkIndex}: published " . count($all) . " parts");
        return ['ok'=>true,'count'=>count($all)];
    }

    /**
     * Optional: simulate VK tampering its published part for a voter (test #2)
     */
    public function vkTamperPublished(int $vkIndex, string $anonId, string $newCipherDec): array
    {
        $pubKey = $vkIndex === 1 ? self::KEY_VK1_PUB : self::KEY_VK2_PUB;
        if (!$this->redis->hExists($pubKey, $anonId)) {
            return ['ok'=>false,'error'=>'NOT_FOUND'];
        }
        $this->redis->hSet($pubKey, $anonId, $newCipherDec);
        $this->log("VK{$vkIndex}: TAMPER published anonId={$anonId} -> {$newCipherDec}");
        return ['ok'=>true];
    }

    /**
     * CEC tally:
     * IMPORTANT: combine ciphertext first, then decrypt!
     */
    public function cecTally(): array
    {
        $cec = $this->getCec();
        $n = $cec['n'];

        $pub1 = $this->redis->hGetAll(self::KEY_VK1_PUB) ?: [];
        $pub2 = $this->redis->hGetAll(self::KEY_VK2_PUB) ?: [];

        $this->redis->del(self::KEY_RESULTS);
        $this->redis->hMSet(self::KEY_TALLY, ['A'=>0,'B'=>0,'invalid'=>0]);

        $cand = $this->candidates();

        // match by anonId
        $allIds = array_unique(array_merge(array_keys($pub1), array_keys($pub2)));

        $this->redis->del(self::KEY_DECRYPTED);

        foreach ($allIds as $anonId) {
            if (!isset($pub1[$anonId], $pub2[$anonId])) {
                $this->redis->hSet(self::KEY_RESULTS, $anonId, 'missing_part');
                $this->redis->hIncrBy(self::KEY_TALLY, 'invalid', 1);
                $this->log("CEC: invalid anonId={$anonId} (missing part)");
                continue;
            }

            $c1 = (string)$pub1[$anonId];
            $c2 = (string)$pub2[$anonId];

            // 1) COMBINE ciphertext
            $combinedCipher = $this->rsa->mulCipher($c1, $c2, $n);
            $this->log("CEC: combine anonId={$anonId}: c = (c1*c2 mod n)");

            // 2) THEN decrypt
            $m = $this->rsa->decryptNumber($combinedCipher, $cec['d'], $cec['n']);
            $this->log("CEC: decrypt anonId={$anonId}: m = Dec(c) = {$m}");
            $this->redis->hSet(self::KEY_DECRYPTED, $anonId, $m);

            if ((int)$m === $cand['A']) {
                $this->redis->hSet(self::KEY_RESULTS, $anonId, 'A');
                $this->redis->hIncrBy(self::KEY_TALLY, 'A', 1);
            } elseif ((int)$m === $cand['B']) {
                $this->redis->hSet(self::KEY_RESULTS, $anonId, 'B');
                $this->redis->hIncrBy(self::KEY_TALLY, 'B', 1);
            } else {
                $this->redis->hSet(self::KEY_RESULTS, $anonId, 'invalid');
                $this->redis->hIncrBy(self::KEY_TALLY, 'invalid', 1);
            }
        }

        $this->log("CEC: tally finished");
        return $this->results();
    }

    public function results(): array
    {
        $t = $this->redis->hGetAll(self::KEY_TALLY) ?: [];
        return [
            'cecPublic' => $this->cecPublic(),
            'vk1Published' => $this->redis->hGetAll(self::KEY_VK1_PUB) ?: [],
            'vk2Published' => $this->redis->hGetAll(self::KEY_VK2_PUB) ?: [],
            'cecResults' => $this->redis->hGetAll(self::KEY_RESULTS) ?: [],
            'tally' => [
                'A'=>(int)($t['A']??0),
                'B'=>(int)($t['B']??0),
                'invalid'=>(int)($t['invalid']??0),
            ],
            'log' => $this->redis->lRange(self::KEY_LOG, 0, -1) ?: [],
            'candidates' => $this->candidates(),
            'cecDecrypted' => $this->redis->hGetAll(self::KEY_DECRYPTED) ?: [],
        ];
    }

    private function getCec(): array
    {
        $json = $this->redis->get(self::KEY_CEC_KEYS);
        if (!$json) throw new \RuntimeException("Run /lab4/setup first");
        return json_decode($json, true);
    }

    private function log(string $line): void
    {
        $this->redis->rPush(self::KEY_LOG, date('H:i:s').' '.$line);
    }
}
