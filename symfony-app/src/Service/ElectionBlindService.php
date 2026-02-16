<?php

declare(strict_types=1);

namespace App\Service;

final readonly class ElectionBlindService
{
    private \Redis $redis;

    private const KEY_CEC = 'lab2_cec';
    private const KEY_ISSUED_NAMES = 'lab2_issued_names'; // set of names who already got signed set
    private const KEY_USED_IDS = 'lab2_used_ids';         // set of voter anonymous IDs already voted
    private const KEY_TALLY = 'lab2_tally';               // hash A,B
    private const KEY_LOG = 'lab2_log';                   // list

    private const VOTERS = ['Voter1','Voter2','Voter3','Voter4','Voter5'];
    private const CANDIDATES = ['A','B'];
    private const SETS = 10;

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
        $this->redis->del(self::KEY_CEC, self::KEY_ISSUED_NAMES, self::KEY_USED_IDS, self::KEY_TALLY, self::KEY_LOG);
        $this->log("RESET");
    }

    public function setup(): array
    {
        $this->reset();

        // ЦВК має RSA ключі для сліпого підпису (і ці ж можна використати для шифрування голосу)
        $cec = $this->rsa->generateKeyPair(512);
        $this->redis->set(self::KEY_CEC, json_encode($cec));

        $this->redis->hMSet(self::KEY_TALLY, ['A'=>0,'B'=>0]);

        $this->log("SETUP: CEC keys generated");
        return ['cecPublic' => ['e'=>$cec['e'],'n'=>$cec['n']], 'voters'=>self::VOTERS];
    }

    /**
     * Етап отримання підписаного комплекту бюлетенів.
     * - ЦВК по імені перевіряє, що виборець ще не отримував підпис (тест 1)
     * - Виборець генерує 10 наборів, ЦВК відкриває 9 і перевіряє
     * - Якщо ок — ЦВК підписує 10-й набір (всліпу) і повертає виборцю 2 підписані бюлетені (A,B)
     *
     * Параметр $cheat=true симулює шахрайство: один з наборів зробимо некоректним,
     * щоб ЦВК відмовила (тест 3).
     */
    public function requestSignedSet(string $name, bool $cheat = false): array
    {
        if (!in_array($name, self::VOTERS, true)) {
            return ['ok'=>false,'error'=>'UNREGISTERED_NAME','message'=>'Name is not in voter list'];
        }

        // Тест 1: не можна отримати 2 комплекти
        if ($this->redis->sIsMember(self::KEY_ISSUED_NAMES, $name)) {
            $this->log("CEC: refuse second signed set for {$name}");
            return ['ok'=>false,'error'=>'ALREADY_ISSUED','message'=>'Signed set already issued for this name'];
        }

        $cec = $this->getCec();
        $e = $cec['e']; $d = $cec['d']; $n = $cec['n'];

        // Виборець генерує 1 анонімний ID (відомий лише йому)
        $anonId = bin2hex(random_bytes(8));

        // 10 наборів: кожен має 2 бюлетені (A і B) з одним і тим самим anonId
        // Для кожного бюлетеня рахуємо m = H(ballot) mod n, маскуємо r
        $sets = [];
        for ($i=0; $i<self::SETS; $i++) {
            $set = [];
            foreach (self::CANDIDATES as $cand) {
                $ballot = json_encode(['id'=>$anonId,'vote'=>$cand], JSON_UNESCAPED_UNICODE);

                // шахрайство: у першому наборі для кандидата B підміняємо ID
                if ($cheat && $i === 0 && $cand === 'B') {
                    $ballot = json_encode(['id'=>'CHEAT_ID','vote'=>$cand], JSON_UNESCAPED_UNICODE);
                }

                $m = $this->rsa->labHash($ballot, $n); // m = H(ballot)
                $r = $this->rsa->randomCoprimeR($n);
                $mPrime = $this->rsa->blind($m, $r, $e, $n);

                $set[$cand] = [
                    'ballot' => $ballot, // розкриваються тільки в opened sets
                    'm' => $m,
                    'r' => $r,
                    'mPrime' => $mPrime,
                ];
            }
            $sets[] = $set;
        }

        // ЦВК випадково обирає 9 наборів для перевірки
        $indexes = range(0, self::SETS-1);
        shuffle($indexes);
        $open = array_slice($indexes, 0, 9);
        $keep = $indexes[9];

        // Перевірка 9 наборів (ЦВК знімає маску і дивиться, що в наборі A,B і однаковий ID)
        foreach ($open as $idx) {
            $a = $sets[$idx]['A'];
            $b = $sets[$idx]['B'];

            // 1) перевіряємо, що бюлетені валідні JSON
            $aObj = json_decode($a['ballot'], true);
            $bObj = json_decode($b['ballot'], true);
            if (!is_array($aObj) || !is_array($bObj) || !isset($aObj['id'],$aObj['vote'],$bObj['id'],$bObj['vote'])) {
                $this->log("CEC: cheat detected (invalid ballot json) in set {$idx}");
                return ['ok'=>false,'error'=>'CHEAT_DETECTED','message'=>'Invalid ballot structure'];
            }

            // 2) перевіряємо кандидати і однаковий ID
            if ($aObj['vote'] !== 'A' || $bObj['vote'] !== 'B' || $aObj['id'] !== $bObj['id']) {
                $this->log("CEC: cheat detected (wrong candidates or mismatched IDs) in set {$idx}");
                return ['ok'=>false,'error'=>'CHEAT_DETECTED','message'=>'Wrong ballots in opened sets'];
            }

            // 3) перевіряємо, що m == H(ballot) (щоб виборець не підсунув інші числа)
            if ($a['m'] !== $this->rsa->labHash($a['ballot'], $n) || $b['m'] !== $this->rsa->labHash($b['ballot'], $n)) {
                $this->log("CEC: cheat detected (hash mismatch) in set {$idx}");
                return ['ok'=>false,'error'=>'CHEAT_DETECTED','message'=>'Hash mismatch'];
            }
        }

        // Якщо 9 наборів ок — ЦВК підписує “всліпу” 10-й (keep) набір
        $signed = [];
        foreach (self::CANDIDATES as $cand) {
            $mPrime = $sets[$keep][$cand]['mPrime'];
            $sPrime = $this->rsa->blindSign($mPrime, $d, $n);
            $signed[$cand] = [
                'ballot' => $sets[$keep][$cand]['ballot'],
                'm' => $sets[$keep][$cand]['m'],
                'r' => $sets[$keep][$cand]['r'],
                'sPrime' => $sPrime, // підпис на m' (ще “в масці”)
            ];
        }

        // Виборець знімає маску: s = s' * r^{-1} mod n
        $final = [];
        foreach (self::CANDIDATES as $cand) {
            $s = $this->rsa->unblind($signed[$cand]['sPrime'], $signed[$cand]['r'], $n);
            $final[$cand] = [
                'ballot' => $signed[$cand]['ballot'],
                'm' => $signed[$cand]['m'],
                'sig' => $s, // підпис ЦВК на m
            ];
        }

        // ЦВК помічає, що видала підпис цьому імені (і більше не видасть)
        $this->redis->sAdd(self::KEY_ISSUED_NAMES, $name);
        $this->log("CEC: issued signed set to {$name}, kept set={$keep}, anonId={$anonId}");

        return [
            'ok'=>true,
            'name'=>$name,
            'anonId'=>$anonId,
            'cecPublic'=>['e'=>$e,'n'=>$n],
            'signedBallots'=>$final, // 2 бюлетені (A,B) з підписом ЦВК
        ];
    }

    /**
     * Власне голосування:
     * - виборець надсилає 1 підписаний бюлетень
     * - якщо sendBoth=true — надсилає обидва (тест 2: приймемо лише перший через унікальність ID)
     */
    public function submitVote(array $signedBallots, string $choice, bool $sendBoth = false): array
    {
        $cec = $this->getCec();
        $e = $cec['e']; $d = $cec['d']; $n = $cec['n'];

        $toSend = [];
        if ($sendBoth) {
            $toSend[] = $signedBallots['A'];
            $toSend[] = $signedBallots['B'];
        } else {
            $toSend[] = $signedBallots[$choice];
        }

        $accepted = 0;
        $ignored = 0;

        foreach ($toSend as $ballotPack) {
            $ballot = $ballotPack['ballot'];
            $m = $ballotPack['m'];
            $sig = $ballotPack['sig'];

            // (опційно) “шифрування” бюлетеня для передачі:
            $cipher = $this->rsa->encryptString(json_encode($ballotPack, JSON_UNESCAPED_UNICODE), $e, $n);
            $plain = $this->rsa->decryptString($cipher, $d, $n);
            $received = json_decode($plain, true);

            // 1) перевірка підпису ЦВК: m == sig^e mod n
            $okSig = $this->rsa->verifySignatureOnMessageNumber($received['m'], $received['sig'], $e, $n);
            if (!$okSig) {
                $ignored++;
                $this->log("CEC: reject vote (bad CEC signature)");
                continue;
            }

            // 2) унікальність ID: якщо вже є — ігнор
            $obj = json_decode($received['ballot'], true);
            $id = $obj['id'] ?? null;
            $vote = $obj['vote'] ?? null;

            if (!is_string($id) || !in_array($vote, self::CANDIDATES, true)) {
                $ignored++;
                $this->log("CEC: reject vote (bad ballot structure)");
                continue;
            }

            if ($this->redis->sIsMember(self::KEY_USED_IDS, $id)) {
                $ignored++;
                $this->log("CEC: ignore duplicate vote by anonId={$id}");
                continue;
            }

            $this->redis->sAdd(self::KEY_USED_IDS, $id);
            $this->redis->hIncrBy(self::KEY_TALLY, $vote, 1);
            $accepted++;
            $this->log("CEC: accepted vote anonId={$id} -> {$vote}");
        }

        return ['ok'=>true,'accepted'=>$accepted,'ignored'=>$ignored,'results'=>$this->results()];
    }

    public function results(): array
    {
        $t = $this->redis->hGetAll(self::KEY_TALLY);
        return [
            'tally' => ['A'=>(int)($t['A']??0), 'B'=>(int)($t['B']??0)],
            'usedIds' => $this->redis->sMembers(self::KEY_USED_IDS) ?: [],
            'log' => $this->redis->lRange(self::KEY_LOG, 0, -1) ?: [],
        ];
    }

    // ---- helpers ----
    private function getCec(): array
    {
        $json = $this->redis->get(self::KEY_CEC);
        if (!$json) throw new \RuntimeException("Run /lab2/setup first");
        return json_decode($json, true);
    }

    private function log(string $line): void
    {
        $this->redis->rPush(self::KEY_LOG, date('H:i:s').' '.$line);
    }
}
