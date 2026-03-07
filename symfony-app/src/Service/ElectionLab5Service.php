<?php

namespace App\Service;

final class ElectionLab5Service
{
    private \Redis $redis;

    private const VOTERS = ['A','B','C','D','E'];
    private const CANDIDATES = ['A' => 24, 'B' => 30];

    private const KEY_KEYS   = 'lab5_keys';
    private const KEY_PLAIN  = 'lab5_plain';
    private const KEY_LIST   = 'lab5_list';
    private const KEY_STAGE  = 'lab5_stage';
    private const KEY_SIG_BY = 'lab5_sig_by';
    private const KEY_SIG    = 'lab5_sig';
    private const KEY_LOG    = 'lab5_log';
    private const KEY_TALLY  = 'lab5_tally';

    private const KEY_SHARED_N   = 'lab5_shared_n';
    private const KEY_SHARED_PHI = 'lab5_shared_phi';

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
            self::KEY_KEYS, self::KEY_PLAIN, self::KEY_LIST,
            self::KEY_STAGE, self::KEY_SIG_BY, self::KEY_SIG,
            self::KEY_LOG, self::KEY_TALLY,
            self::KEY_SHARED_N, self::KEY_SHARED_PHI
        );
        $this->log('RESET');
    }

    /**
     * - генеруємо спільний модуль n (shared n) для всіх
     * - кожному виборцю генеруємо свій (e,d), але на цьому ж n
     */
    public function setup(): array
    {
        $this->reset();

        $shared = $this->rsa->generateSharedModulus(512);
        $this->redis->set(self::KEY_SHARED_N, $shared['n']);
        $this->redis->set(self::KEY_SHARED_PHI, $shared['phi']);

        foreach (self::VOTERS as $v) {
            $kp = $this->rsa->generateKeyPairWithSharedN($shared['phi'], $shared['n']);
            $this->redis->hSet(self::KEY_KEYS, $v, json_encode($kp, JSON_UNESCAPED_UNICODE));
            $this->redis->hSet(self::KEY_PLAIN, $v, '');
        }

        $this->redis->set(self::KEY_STAGE, 'setup_done');
        $this->redis->hMSet(self::KEY_TALLY, ['A'=>0,'B'=>0,'invalid'=>0]);

        $this->redis->del(self::KEY_SIG_BY, self::KEY_SIG);
        $this->saveList([]);

        $this->log('SETUP: shared n generated + voters keys generated');
        return $this->state();
    }

    public function castVote(string $voter, string $choice): array
    {
        $this->assertSetup();
        $this->assertVoter($voter);

        if (!isset(self::CANDIDATES[$choice])) {
            return ['ok'=>false,'error'=>'BAD_CHOICE'];
        }

        $candidateId = self::CANDIDATES[$choice];
        $this->redis->hSet(self::KEY_PLAIN, $voter, (string)$candidateId);
        $this->log("VOTE: {$voter} -> {$choice} (candidateId={$candidateId})");

        return ['ok'=>true];
    }

    /**
     * Encrypt 2 rounds:
     * - беремо 5 чисел (candidateId)
     * - робимо 2 раунди onion RSA: E->D->C->B->A
     */
    public function encryptTwoRounds(): array
    {
        $this->assertSetup();

        $plain = $this->redis->hGetAll(self::KEY_PLAIN) ?: [];
        foreach (self::VOTERS as $v) {
            if (empty($plain[$v] ?? '')) {
                return ['ok'=>false,'error'=>"NOT_ALL_VOTED ({$v} missing)"];
            }
        }

        $list = [];
        foreach (self::VOTERS as $v) {
            $list[] = (string)$plain[$v];
        }

        $list = $this->encryptRound($list, 1);
        $list = $this->encryptRound($list, 2);

        $this->saveList($list);
        $this->redis->set(self::KEY_STAGE, 'encrypted_sent_to_A');

        $this->redis->del(self::KEY_SIG_BY, self::KEY_SIG);

        $this->log('ENCRYPT: finished 2 rounds, list sent to A');
        return ['ok'=>true];
    }

    /**
     * Decrypt round:
     * A->B->C->D->E
     * 1) signature chain (підміна виявляється)
     * 2) count==5 (видалення/підкидання виявляється)
     */
    public function decryptRound(int $round): array
    {
        $this->assertSetup();
        if ($round !== 1 && $round !== 2) return ['ok'=>false,'error'=>'BAD_ROUND'];

        $list = $this->loadList();
        if ($round === 2) {
            $this->redis->del(self::KEY_SIG_BY, self::KEY_SIG);
            $this->log("DECRYPT ROUND 2: signature chain reset");
        }
        // Виявляє видалення / підкидання бюлетенів
        if (count($list) !== 5) {
            $this->log("DECRYPT ROUND {$round}: ABORT (count=" . count($list) . ", expected=5)");
            return ['ok'=>false,'error'=>'BALLOT_COUNT_MISMATCH'];
        }

        $prevSigner = (string)($this->redis->get(self::KEY_SIG_BY) ?: '');
        $prevSig    = (string)($this->redis->get(self::KEY_SIG) ?: '');

        foreach (self::VOTERS as $voter) {
            // Виявляє підміну списку між кроками
            if ($prevSigner !== '' && $prevSig !== '') {
                if (!$this->verifyListSignature($list, $round, $prevSigner, $prevSig)) {
                    $this->log("DECRYPT ROUND {$round}: {$voter} REJECT (bad signature from {$prevSigner})");
                    return ['ok'=>false,'error'=>'BAD_SIGNATURE_CHAIN'];
                }
            }

            // знімаємо шар
            $kp = $this->getKeyPair($voter);
            $list = array_map(
                fn(string $c) => $this->rsa->decryptNumber($c, $kp['d'], $kp['n']),
                $list
            );
            $this->log("DECRYPT ROUND {$round}: {$voter} removed own layer");

            // перемішуємо
            shuffle($list);
            $this->log("DECRYPT ROUND {$round}: {$voter} shuffled ballots");

            // підписуємо список для наступного
            $sig = $this->signList($list, $round, $voter);
            $prevSigner = $voter;
            $prevSig = $sig;

            $this->redis->set(self::KEY_SIG_BY, $prevSigner);
            $this->redis->set(self::KEY_SIG, $prevSig);
            $this->log("DECRYPT ROUND {$round}: {$voter} signed list");
        }

        $this->saveList($list);
        $this->redis->set(self::KEY_STAGE, $round === 1 ? 'round1_decrypted_done' : 'round2_decrypted_done');
        $this->log("DECRYPT ROUND {$round}: DONE");

        return ['ok'=>true];
    }

    public function tally(): array
    {
        $this->assertSetup();

        $stage = (string)($this->redis->get(self::KEY_STAGE) ?: '');
        if ($stage !== 'round2_decrypted_done') {
            return ['ok'=>false,'error'=>'RUN_DECRYPT_ROUND2_FIRST'];
        }

        $list = $this->loadList();
        $this->redis->hMSet(self::KEY_TALLY, ['A'=>0,'B'=>0,'invalid'=>0]);

        foreach ($list as $mDec) {
            $m = (int)$mDec;
            if ($m === self::CANDIDATES['A']) $this->redis->hIncrBy(self::KEY_TALLY, 'A', 1);
            elseif ($m === self::CANDIDATES['B']) $this->redis->hIncrBy(self::KEY_TALLY, 'B', 1);
            else $this->redis->hIncrBy(self::KEY_TALLY, 'invalid', 1);
        }

        $this->log('TALLY: finished');
        return ['ok'=>true];
    }


    /** Підміна одного бюлетеня (імітація шахрайства) */
    public function tamperAtIndex(int $index, string $newCipherDec): array
    {
        $list = $this->loadList();
        if (!isset($list[$index])) return ['ok'=>false,'error'=>'BAD_INDEX'];

        $list[$index] = $newCipherDec;
        $this->saveList($list);

        $this->log("TAMPER: replaced ballot[{$index}] with {$newCipherDec}");
        return ['ok'=>true];
    }

    /** Видалення бюлетеня (виявиться по count!=5) */
    public function removeAtIndex(int $index): array
    {
        $list = $this->loadList();
        if (!isset($list[$index])) return ['ok'=>false,'error'=>'BAD_INDEX'];

        array_splice($list, $index, 1);
        $this->saveList($list);

        $this->log("REMOVE: removed ballot[{$index}]");
        return ['ok'=>true];
    }

    /** Додавання зайвого бюлетеня (виявиться по count!=5) */
    public function addExtra(string $cipherDec): array
    {
        $list = $this->loadList();
        $list[] = $cipherDec;
        $this->saveList($list);

        $this->log("ADD: added extra ballot");
        return ['ok'=>true];
    }

    private function encryptRound(array $list, int $round): array
    {
        $this->log("ENCRYPT ROUND {$round}: start");

        $pub = $this->getPublicKeys();

        $out = [];
        foreach ($list as $mDec) {
            $x = (string)$mDec;

            // onion layers: E,D,C,B,A
            foreach (array_reverse(self::VOTERS) as $v) {
                $x = $this->rsa->encryptNumber($x, $pub[$v]['e'], $pub[$v]['n']);
            }

            $out[] = $x;
        }

        $this->log("ENCRYPT ROUND {$round}: done");
        return $out;
    }

    private function signList(array $list, int $round, string $signer): string
    {
        $kp = $this->getKeyPair($signer);
        $payload = "ROUND={$round}|LIST=" . json_encode($list, JSON_UNESCAPED_UNICODE);
        $m = $this->rsa->labHash($payload, $kp['n']);
        return $this->rsa->signMessageNumber($m, $kp['d'], $kp['n']);
    }

    private function verifyListSignature(array $list, int $round, string $signer, string $sigDec): bool
    {
        $kp = $this->getKeyPair($signer);
        $payload = "ROUND={$round}|LIST=" . json_encode($list, JSON_UNESCAPED_UNICODE);
        $m = $this->rsa->labHash($payload, $kp['n']);
        return $this->rsa->verifySignatureOnMessageNumber($m, $sigDec, $kp['e'], $kp['n']);
    }

    private function getPublicKeys(): array
    {
        $out = [];
        foreach (self::VOTERS as $v) {
            $kp = $this->getKeyPair($v);
            $out[$v] = ['e'=>$kp['e'], 'n'=>$kp['n']];
        }
        return $out;
    }

    private function getKeyPair(string $voter): array
    {
        $json = $this->redis->hGet(self::KEY_KEYS, $voter);
        if (!$json) throw new \RuntimeException('Run /lab5/setup first');
        return json_decode($json, true);
    }

    private function saveList(array $list): void
    {
        $this->redis->set(self::KEY_LIST, json_encode(array_values($list), JSON_UNESCAPED_UNICODE));
    }

    private function loadList(): array
    {
        $json = (string)($this->redis->get(self::KEY_LIST) ?: '[]');
        return json_decode($json, true) ?: [];
    }

    private function assertSetup(): void
    {
        if (($this->redis->hLen(self::KEY_KEYS) ?: 0) < 5) {
            throw new \RuntimeException('Run /lab5/setup first');
        }
    }

    private function assertVoter(string $v): void
    {
        if (!in_array($v, self::VOTERS, true)) {
            throw new \InvalidArgumentException('Unknown voter');
        }
    }

    private function short(string $x, int $keep = 10): string
    {
        $x = (string)$x;
        if (strlen($x) <= $keep * 2) return $x;
        return substr($x, 0, $keep) . '…' . substr($x, -$keep);
    }

    private function log(string $line): void
    {
        $this->redis->rPush(self::KEY_LOG, date('H:i:s') . ' ' . $line);
    }

    public function state(): array
    {
        $stage = (string)($this->redis->get(self::KEY_STAGE) ?: '');
        $plain = $this->redis->hGetAll(self::KEY_PLAIN) ?: [];
        $list  = $this->loadList();
        $t     = $this->redis->hGetAll(self::KEY_TALLY) ?: [];

        $sigBy = (string)($this->redis->get(self::KEY_SIG_BY) ?: '');
        $sig   = (string)($this->redis->get(self::KEY_SIG) ?: '');

        $sharedN = (string)($this->redis->get(self::KEY_SHARED_N) ?: '');

        // keysShort: щоб Twig не падав і ключі не рвали верстку
        $keysShort = [];
        $keys = $this->redis->hGetAll(self::KEY_KEYS) ?: [];
        foreach ($keys as $v => $json) {
            $k = json_decode($json, true) ?: [];
            $keysShort[$v] = [
                'e' => (string)($k['e'] ?? ''),
                'n' => $this->short((string)($k['n'] ?? ''), 12),
                'd' => $this->short((string)($k['d'] ?? ''), 12),
            ];
        }

        return [
            'stage' => $stage,
            'voters' => self::VOTERS,
            'candidates' => self::CANDIDATES,

            'sharedN' => $this->short($sharedN, 12),

            'plain' => $plain,
            'list'  => $list,

            'sigBy' => $sigBy,
            'sig'   => $this->short($sig, 12),

            'rp' => array_fill_keys(self::VOTERS, '—'),

            'tally' => [
                'A' => (int)($t['A'] ?? 0),
                'B' => (int)($t['B'] ?? 0),
                'invalid' => (int)($t['invalid'] ?? 0),
            ],

            'keysShort' => $keysShort,

            'log' => $this->redis->lRange(self::KEY_LOG, 0, -1) ?: [],
        ];
    }
}
