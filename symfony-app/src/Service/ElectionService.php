<?php

declare(strict_types=1);

namespace App\Service;

final class ElectionService
{
    private \Redis $redis;

    private const KEY_CEC = 'lab_vote_cec';
    private const KEY_VOTERS = 'lab_vote_voters';     // hash: voterId -> json(keys)
    private const KEY_VOTED = 'lab_vote_voted_set';   // set of voterIds
    private const KEY_TALLY = 'lab_vote_tally';       // hash: candidate -> int
    private const KEY_LOG = 'lab_vote_log';           // list of strings

    public function __construct(
        private readonly RsaService $rsaService,
        string $redisHost,
        int $redisPort,
    ) {
        $this->redis = new \Redis();
        $this->redis->connect($redisHost, $redisPort);
    }

    public function setup(): array
    {
        $this->redis->del(
            self::KEY_CEC,
            self::KEY_VOTERS,
            self::KEY_VOTED,
            self::KEY_TALLY,
            self::KEY_LOG,
        );

        // ЦВК (CEC) ключі для шифрування (всі виборці шифрують на (e,n) ЦВК)
        $cec = $this->rsaService->generateKeyPair(bits: 512);
        $this->redis->set(self::KEY_CEC, json_encode($cec));

        // Результати голосування у розрізі кожного кандидату
        $this->redis->hMSet(self::KEY_TALLY, ['A' => 0, 'B' => 0]);

        // Реєстрація виборців та видача ключів
        $voters = [];
        for ($i=1; $i<=5; $i++) {
            $id = "Voter{$i}";
            $kp = $this->rsaService->generateKeyPair(bits: 512); // keys for signature
            $this->redis->hSet(self::KEY_VOTERS, $id, json_encode($kp));
            $voters[] = [
                'id' => $id,
                'privateKeyD' => $kp['d'], // закритий ключ. У реальному житті приватний ключ зберігається у виборця - сервер його лише створює та передає виборцю
                'publicE' => $kp['e'], // відкритий ключ
                'n' => $kp['n'], // модуль RSA (p × q)
            ];
        }

        $this->log("SETUP: created CEC keys + 5 voters");

        return [
            'cecPublic' => ['e' => $cec['e'], 'n' => $cec['n']],
            'voters' => $voters, // для демо UI покажемо (бо навчально)
        ];
    }

    public function getState(): array
    {
        $cec = $this->getCec();
        $tally = $this->redis->hGetAll(self::KEY_TALLY);
        $votedCount = $this->redis->sCard(self::KEY_VOTED);

        return [
            'cecPublic' => ['e' => $cec['e'], 'n' => $cec['n']],
            'tally' => ['A' => (int)($tally['A'] ?? 0), 'B' => (int)($tally['B'] ?? 0)],
            'votedCount' => $votedCount,
        ];
    }

    /** “Клієнт: Виборець”: формує бюлетень, хеш, ЕЦП, шифрує для ЦВК, “надсилає” */
    public function castVote(string $voterId, string $candidate): array
    {
        if (!in_array($candidate, ['A','B'], true)) {
            return $this->reject("UNKNOWN_CANDIDATE", "Candidate must be A or B");
        }

        $cec = $this->getCec();

        // Тест #2: незареєстрований (ЦВК не створювала ключів) -> ігнор
        $voterKp = $this->getVoterKeys($voterId);
        if ($voterKp === null) {
            $this->log("CEC: ignore unregistered voter {$voterId}");
            return $this->reject("UNREGISTERED_VOTER", "Voter is not registered");
        }

        // Тест #1: повторний бюлетень -> ігнор
        if ($this->redis->sIsMember(self::KEY_VOTED, $voterId)) {
            $this->log("CEC: ignore duplicate ballot from {$voterId}");
            return $this->reject("DUPLICATE_BALLOT", "Voter already voted");
        }

        // Повідомлення (бюлетень)
        $ballot = json_encode(['voterId'=>$voterId,'vote'=>$candidate], JSON_UNESCAPED_UNICODE);

        // ЕЦП: S = H^d mod n
        $sig = $this->rsaService->sign($ballot, $voterKp['d'], $voterKp['n']);

        // Пакет: { ballot, sig, voterPublicKey } — ЦВК знає public key з реєстру, тому public можна не слати
        $payload = json_encode(['ballot'=>$ballot,'sig'=>$sig], JSON_UNESCAPED_UNICODE);

        // Шифруємо payload на відкритому ключі ЦВК
        $cipher = $this->rsaService->encryptString($payload, $cec['e'], $cec['n']);

        // “Сервер ЦВК”: приймає зашифрований пакет
        return $this->cecReceive($cipher);
    }

    /** Тест #3: пошкоджений бюлетень (втрачено останній символ) */
    public function castDamagedBallot(string $voterId, string $candidate): array
    {
        $cec = $this->getCec();
        $voterKp = $this->getVoterKeys($voterId);
        if ($voterKp === null) return $this->reject("UNREGISTERED_VOTER", "Voter is not registered");
        if ($this->redis->sIsMember(self::KEY_VOTED, $voterId)) return $this->reject("DUPLICATE_BALLOT", "Voter already voted");

        $ballot = json_encode(['voterId'=>$voterId,'vote'=>$candidate], JSON_UNESCAPED_UNICODE);
        $sig = $this->rsaService->sign($ballot, $voterKp['d'], $voterKp['n']);

        $payload = json_encode(['ballot'=>$ballot,'sig'=>$sig], JSON_UNESCAPED_UNICODE);
        $payloadDamaged = substr($payload, 0, -1); // “втрачено останній символ”

        $cipher = $this->rsaService->encryptString($payloadDamaged, $cec['e'], $cec['n']);

        return $this->cecReceive($cipher);
    }

    public function results(): array
    {
        $tally = $this->redis->hGetAll(self::KEY_TALLY);
        $a = (int)($tally['A'] ?? 0);
        $b = (int)($tally['B'] ?? 0);

        $status = ($a === $b)
            ? ['type'=>'TIE','message'=>'Нічия. Потрібне повторне голосування.']
            : ['type'=>'WINNER','winner'=> ($a > $b ? 'A' : 'B')];

        return [
            'tally' => ['A'=>$a,'B'=>$b],
            'status' => $status,
            'log' => $this->getLog(),
        ];
    }

    public function runAllTests(): array
    {
        $this->setup();

        // 4 нормальні голоси: 2-2
        $this->castVote('Voter1','A');
        $this->castVote('Voter2','B');
        $this->castVote('Voter3','A');
        $this->castVote('Voter4','B');

        // Test #1 duplicate
        $this->castVote('Voter1','B');

        // Test #2 unregistered
        $this->castVote('Bob','A');

        // Test #3 damaged ballot (Voter5)
        $this->castDamagedBallot('Voter5','A');

        return $this->results(); // тут якраз буде tie 2-2 і повідомлення
    }

    // ---------------- CEC receive ----------------

    private function cecReceive(array $cipher): array
    {
        $cec = $this->getCec();
        $payloadJson = $this->rsaService->decryptString($cipher, $cec['d'], $cec['n']);

        $payload = json_decode($payloadJson, true);
        if (!is_array($payload) || !isset($payload['ballot'], $payload['sig'])) {
            $this->log("CEC: reject damaged payload (invalid JSON/format)");
            return $this->reject("DAMAGED_BALLOT", "Payload format invalid (damaged)");
        }

        $ballot = (string)$payload['ballot'];
        $sig = (string)$payload['sig'];

        $ballotObj = json_decode($ballot, true);
        if (!is_array($ballotObj) || !isset($ballotObj['voterId'], $ballotObj['vote'])) {
            $this->log("CEC: reject damaged ballot (invalid ballot JSON)");
            return $this->reject("DAMAGED_BALLOT", "Ballot JSON invalid (damaged)");
        }

        $voterId = (string)$ballotObj['voterId'];
        $vote = (string)$ballotObj['vote'];

        $voterKp = $this->getVoterKeys($voterId);
        if ($voterKp === null) {
            $this->log("CEC: ignore unregistered voter {$voterId}");
            return $this->reject("UNREGISTERED_VOTER", "Voter is not registered");
        }

        if ($this->redis->sIsMember(self::KEY_VOTED, $voterId)) {
            $this->log("CEC: ignore duplicate ballot from {$voterId}");
            return $this->reject("DUPLICATE_BALLOT", "Voter already voted");
        }

        // Перевірка ЕЦП: H(message) vs (S^e mod n)
        $ok = $this->rsaService->verify($ballot, $sig, $voterKp['e'], $voterKp['n']);
        if (!$ok) {
            $this->log("CEC: reject damaged/tampered ballot from {$voterId} (signature failed)");
            return $this->reject("SIGNATURE_FAILED", "Signature verification failed");
        }

        // Прийняти голос
        $this->redis->sAdd(self::KEY_VOTED, $voterId);
        $this->redis->hIncrBy(self::KEY_TALLY, $vote, 1);

        $this->log("CEC: accepted vote {$voterId} -> {$vote}");
        return ['ok'=>true,'message'=>"Accepted {$voterId} -> {$vote}"];
    }

    private function getCec(): array
    {
        $json = $this->redis->get(self::KEY_CEC);
        if (!$json) throw new \RuntimeException("Election not set up. Open /setup first.");
        return json_decode($json, true);
    }

    private function getVoterKeys(string $voterId): ?array
    {
        $json = $this->redis->hGet(self::KEY_VOTERS, $voterId);
        return $json ? json_decode($json, true) : null;
    }

    private function log(string $line): void
    {
        $this->redis->rPush(self::KEY_LOG, date('H:i:s') . ' ' . $line);
    }

    private function getLog(): array
    {
        return $this->redis->lRange(self::KEY_LOG, 0, -1) ?: [];
    }

    private function reject(string $code, string $message): array
    {
        return ['ok'=>false,'error'=>$code,'message'=>$message];
    }

    public function reset(): void
    {
        $this->redis->del(
            self::KEY_CEC,
            self::KEY_VOTERS,
            self::KEY_VOTED,
            self::KEY_TALLY,
            self::KEY_LOG,
        );

        $this->log("RESET: election state cleared");
    }
}
