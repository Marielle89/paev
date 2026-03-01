<?php

namespace App\Service;

/**
 * Учасники протоколу:
 *  - ЦВК (CEC): має пару RSA-ключів (e,n) / (d,n), об'єднує частини бюлетенів і розшифровує.
 *  - ВК-1 (VK1) та ВК-2 (VK2): незалежні комісії, кожна отримує лише ОДНУ частину бюлетеня.
 *
 * Ключова ідея протоколу:
 *  - Виборець НЕ надсилає ID кандидата напряму.
 *  - Виборець розкладає ID кандидата на два множники m1 і m2 так, що m1*m2 = candidateId.
 *  - Далі шифрує кожен множник відкритим ключем ЦВК:
 *      c1 = Enc(m1), c2 = Enc(m2)
 *    і надсилає c1 у ВК-1, а c2 у ВК-2.
 *
 * Властивість RSA, яку ми використовуємо (навчальна гомоморфність по множенню):
 *  - Enc(m) = m^e mod n
 *  - Enc(m1) * Enc(m2) mod n = Enc(m1*m2 mod n)
 *  - Тому якщо ЦВК спочатку перемножить шифротексти, а ПОТІМ розшифрує,
 *    то отримає m1*m2 (тобто candidateId).
 *
 * Важливо: у нашій програмі ми ДОВОДИМО порядок:
 *  1) Спочатку З’ЄДНАННЯ (об’єднання) двох шифротекстів: c = (c1*c2) mod n
 *  2) Лише потім РОЗШИФРУВАННЯ: m = Dec(c)
 *
 * Redis використовується як сховище стану
 */
final class ElectionLab4Service
{
    private \Redis $redis;

    /** JSON з ключами ЦВК: {e,n,d} */
    private const KEY_CEC_KEYS   = 'lab4_cec_keys';

    /**
     * Внутрішнє сховище ВК-1: hash anonId -> json(message)
     * Тут зберігаються лише ті повідомлення, що пройшли перевірку ЕЦП
     */
    private const KEY_VK1_STORE  = 'lab4_vk1_store';

    /** Внутрішнє сховище ВК-2: hash anonId -> json(message) */
    private const KEY_VK2_STORE  = 'lab4_vk2_store';

    /** Публікація ВК-1: hash anonId -> c1 */
    private const KEY_VK1_PUB    = 'lab4_vk1_pub';

    /** Публікація ВК-2: hash anonId -> c2 */
    private const KEY_VK2_PUB    = 'lab4_vk2_pub';

    /** Тут ЦВК зберігає інтерпретацію дешифрованого значення */
    private const KEY_RESULTS    = 'lab4_cec_results';

    /** Підрахунок голосів: hash A,B,invalid */
    private const KEY_TALLY      = 'lab4_tally';

    /** Лог протоколу для демонстрації */
    private const KEY_LOG        = 'lab4_log';

    /** Лог дозволяє наочно показати, що при підміні частини бюлетеня голос стає invalid */
    private const KEY_DECRYPTED  = 'lab4_cec_decrypted';

    public function __construct(
        private readonly RsaService $rsa,
        string $redisHost,
        int $redisPort
    ) {
        $this->redis = new \Redis();
        $this->redis->connect($redisHost, $redisPort);
    }

    /** Очищення, виконується перед setup(), щоб стартувати “з нуля” */
    public function reset(): void
    {
        $this->redis->del(
            self::KEY_CEC_KEYS,
            self::KEY_VK1_STORE,
            self::KEY_VK2_STORE,
            self::KEY_VK1_PUB,
            self::KEY_VK2_PUB,
            self::KEY_RESULTS,
            self::KEY_TALLY,
            self::KEY_LOG,
            self::KEY_DECRYPTED,
        );

        $this->log("RESET");
    }

    /**
     *  - генерує ключі ЦВК (CEC)
     *  - ініціалізує лічильники
     *  - повертає публічний ключ ЦВК і список кандидатів
     */
    public function setup(): array
    {
        $this->reset();

        // Генерація RSA-ключів ЦВК для RSA
        // 512 біт
        $cec = $this->rsa->generateKeyPair(512);

        // Зберігає ключі ЦВК у Redis. d (приватний) потрібен тільки ЦВК на етапі tally
        $this->redis->set(self::KEY_CEC_KEYS, json_encode($cec));

        // Лічильники голосів (A,B,invalid)
        $this->redis->hMSet(self::KEY_TALLY, ['A' => 0, 'B' => 0, 'invalid' => 0]);

        $this->log("SETUP: CEC keys generated");

        // Вибір кандидатів з багатьма дільниками:
        // 24 і 30 мають спільні дільники (2,3,6), щоб одна ВК не могла легко вгадати кандидата по одному множнику.
        return [
            'cecPublic' => ['e' => $cec['e'], 'n' => $cec['n']],
            'candidates' => [
                'A' => 24,
                'B' => 30,
            ],
        ];
    }

    /** Публічний ключ ЦВК (e,n) для шифрування частин бюлетеня виборцями. */
    public function cecPublic(): array
    {
        $cec = $this->getCec();
        return ['e' => $cec['e'], 'n' => $cec['n']];
    }

    public function candidates(): array
    {
        return ['A' => 24, 'B' => 30];
    }

    /** довільний розподіл candidateId на 2 множники (m1, m2) */
    public function splitCandidateId(int $candidateId): array
    {
        // Спільні дільники для 24 і 30: 2, 3, 6
        $common = [2, 3, 6];

        // Вибираємо з common ті, що реально ділять candidateId без остачі
        $choices = array_values(array_filter($common, fn($d) => $candidateId % $d === 0));

        // Випадково обираємо один дільник -> це перший множник
        $a = $choices[random_int(0, count($choices) - 1)];

        // Другий множник обчислюємо як candidateId / a
        $b = intdiv($candidateId, $a);

        // Випадковий порядок: яка частина піде в яку ВК (щоб не було шаблону)
        return random_int(0, 1) ? [$a, $b] : [$b, $a];
    }

    /** Прийом частини бюлетеня у ВК (VK1 або VK2)
     *
     * ВК виконує танступні функції:
     *  1) Перевіряє ЕЦП виборця на повідомленні (anonId|vkIndex|cipher).
     *     Це гарантує:
     *       - цілісність (cipher не змінено)
     *       - автентичність (повідомлення справді від виборця)
     *  2) Зберігає повідомлення у власне сховище (store) для подальшої публікації.
     *
     * Якщо підпис невалідний, то повідомлення відхиляється і не потрапляє в store.
     */
    public function vkReceive(
        int $vkIndex,
        string $name,
        string $anonId,
        string $cipherPartDec,
        array $voterPub,
        string $sigDec
    ): array {
        // Payload, який підписував виборець:
        // включає anonId, номер комісії (1 або 2) і конкретну частину шифротексту.
        // Якщо змінити хоч 1 символ у cipher/anonId/vkIndex -> підпис не зійдеться.
        $payload = $anonId . '|' . $vkIndex . '|' . $cipherPartDec;

        // У лабораторних ми працюємо з числовим RSA, тому текст payload переводимо у число через хеш:
        // m = H(payload) mod n_voter
        $m = $this->rsa->labHash($payload, $voterPub['n']);

        // Перевірка ЕЦП: m_from_sig = sig^e mod n, далі порівнюємо з m.
        $ok = $this->rsa->verifySignatureOnMessageNumber(
            $m,
            $sigDec,
            $voterPub['e'],
            $voterPub['n']
        );

        // Якщо ЕЦП невалідна -> ВК відмовляє (це тест #1 у лабораторній)
        if (!$ok) {
            $this->log("VK{$vkIndex}: reject bad signature for {$name}, anonId={$anonId}");
            return ['ok' => false, 'error' => 'BAD_SIGNATURE'];
        }

        // Повідомлення, яке зберігає ВК у store (внутрішньо):
        // Тут cipherPartDec - це частина бюлетеня у вигляді шифротексту (десятковий рядок).
        $msg = [
            'name' => $name,
            'anonId' => $anonId,
            'cipher' => $cipherPartDec,
            'voterPub' => $voterPub,
            'sig' => $sigDec,
        ];

        // ВК-1 і ВК-2 мають різні "store"
        $key = $vkIndex === 1 ? self::KEY_VK1_STORE : self::KEY_VK2_STORE;

        // Зберігаємо за anonId (анонімний ідентифікатор), без персональних даних у публікації.
        $this->redis->hSet($key, $anonId, json_encode($msg, JSON_UNESCAPED_UNICODE));

        $this->log("VK{$vkIndex}: accepted part for {$name}, anonId={$anonId}, cipher={$cipherPartDec}");

        return ['ok' => true];
    }

    /**
     * Публікація частин бюлетенів ВК.  ВК бере всі прийняті (store) частини та формує pub-структуру: anonId -> cipher
     */
    public function vkPublish(int $vkIndex): array
    {
        $storeKey = $vkIndex === 1 ? self::KEY_VK1_STORE : self::KEY_VK2_STORE;
        $pubKey   = $vkIndex === 1 ? self::KEY_VK1_PUB   : self::KEY_VK2_PUB;

        // Беремо всі прийняті повідомлення
        $all = $this->redis->hGetAll($storeKey) ?: [];

        // Очищаємо стару публікацію
        $this->redis->del($pubKey);

        foreach ($all as $anonId => $json) {
            $msg = json_decode($json, true);

            // Публікуємо лише cipher, без підпису/імені
            $this->redis->hSet($pubKey, $anonId, (string)$msg['cipher']);
        }

        $this->log("VK{$vkIndex}: published " . count($all) . " parts");
        return ['ok' => true, 'count' => count($all)];
    }

    /**
     * підміна частини бюлетеня
     */
    public function vkTamperPublished(int $vkIndex, string $anonId, string $newCipherDec): array
    {
        $pubKey = $vkIndex === 1 ? self::KEY_VK1_PUB : self::KEY_VK2_PUB;

        if (!$this->redis->hExists($pubKey, $anonId)) {
            return ['ok' => false, 'error' => 'NOT_FOUND'];
        }

        // Підміна "опублікованої" частини бюлетеня
        $this->redis->hSet($pubKey, $anonId, $newCipherDec);

        $this->log("VK{$vkIndex}: TAMPER published anonId={$anonId} -> {$newCipherDec}");
        return ['ok' => true];
    }

    /**
     * Підрахунок ЦВК (CEC tally)
     * Спочатку об’єднуємо частини бюлетеня у шифрованому вигляді:
     *      c = (c1 * c2) mod n
     *  - після дешифруємо:
     *      m = Dec(c)
     */
    public function cecTally(): array
    {
        $cec = $this->getCec();
        $n = $cec['n'];

        // Опубліковані дані з двох ВК
        $pub1 = $this->redis->hGetAll(self::KEY_VK1_PUB) ?: [];
        $pub2 = $this->redis->hGetAll(self::KEY_VK2_PUB) ?: [];

        // Очищаємо результати та лічильники
        $this->redis->del(self::KEY_RESULTS);
        $this->redis->hMSet(self::KEY_TALLY, ['A' => 0, 'B' => 0, 'invalid' => 0]);

        $cand = $this->candidates();

        // Збираємо всі anonId (щоб обробити навіть випадки, де десь не вистачає частини)
        $allIds = array_unique(array_merge(array_keys($pub1), array_keys($pub2)));

        // Очищаємо “доказові” дешифровані значення
        $this->redis->del(self::KEY_DECRYPTED);

        foreach ($allIds as $anonId) {
            // Якщо немає однієї з частин — бюлетень зіпсований (missing_part)
            if (!isset($pub1[$anonId], $pub2[$anonId])) {
                $this->redis->hSet(self::KEY_RESULTS, $anonId, 'missing_part');
                $this->redis->hIncrBy(self::KEY_TALLY, 'invalid', 1);
                $this->log("CEC: invalid anonId={$anonId} (missing part)");
                continue;
            }

            $c1 = (string)$pub1[$anonId];
            $c2 = (string)$pub2[$anonId];

            // 1) об’єднуємо шифротексти
            // c = (c1 * c2) mod n
            $combinedCipher = $this->rsa->mulCipher($c1, $c2, $n);
            $this->log("CEC: combine anonId={$anonId}: c = (c1*c2 mod n)");

            // 2) розшифровуємо об’єднаного шифротексту
            // m = Dec(c)
            $m = $this->rsa->decryptNumber($combinedCipher, $cec['d'], $cec['n']);
            $this->log("CEC: decrypt anonId={$anonId}: m = Dec(c) = {$m}");

            // Зберігаємо m у Redis, щоб на UI можна було показати доказ
            $this->redis->hSet(self::KEY_DECRYPTED, $anonId, $m);

            // Інтерпретація: дешифрований результат має дорівнювати ID одного з кандидатів
            if ((int)$m === $cand['A']) {
                $this->redis->hSet(self::KEY_RESULTS, $anonId, 'A');
                $this->redis->hIncrBy(self::KEY_TALLY, 'A', 1);
            } elseif ((int)$m === $cand['B']) {
                $this->redis->hSet(self::KEY_RESULTS, $anonId, 'B');
                $this->redis->hIncrBy(self::KEY_TALLY, 'B', 1);
            } else {
                // Якщо m не 24 і не 30 — це зіпсований бюлетень (наприклад через підміну частини)
                $this->redis->hSet(self::KEY_RESULTS, $anonId, 'invalid');
                $this->redis->hIncrBy(self::KEY_TALLY, 'invalid', 1);
            }
        }

        $this->log("CEC: tally finished");
        return $this->results();
    }

    /**
     * Збір всіх даних для сторінки результатів (UI).
     * Повертає:
     *  - опубліковані частини ВК-1/ВК-2
     *  - результати ЦВК (A/B/invalid)
     *  - лічильники
     *  - лог кроків
     *  - дешифровані значення m
     */
    public function results(): array
    {
        $t = $this->redis->hGetAll(self::KEY_TALLY) ?: [];

        return [
            'cecPublic' => $this->cecPublic(),
            'vk1Published' => $this->redis->hGetAll(self::KEY_VK1_PUB) ?: [],
            'vk2Published' => $this->redis->hGetAll(self::KEY_VK2_PUB) ?: [],
            'cecResults' => $this->redis->hGetAll(self::KEY_RESULTS) ?: [],
            'tally' => [
                'A' => (int)($t['A'] ?? 0),
                'B' => (int)($t['B'] ?? 0),
                'invalid' => (int)($t['invalid'] ?? 0),
            ],
            'log' => $this->redis->lRange(self::KEY_LOG, 0, -1) ?: [],
            'candidates' => $this->candidates(),
            'cecDecrypted' => $this->redis->hGetAll(self::KEY_DECRYPTED) ?: [],
        ];
    }

    /**
     * Витягуємо ключі ЦВК з Redis
     * Якщо ключів немає — значить setup() ще не запускали.
     */
    private function getCec(): array
    {
        $json = $this->redis->get(self::KEY_CEC_KEYS);

        if (!$json) {
            throw new \RuntimeException("Run /lab4/setup first");
        }

        return json_decode($json, true);
    }

    /**
     * Логування кроків протоколу.
     */
    private function log(string $line): void
    {
        $this->redis->rPush(self::KEY_LOG, date('H:i:s') . ' ' . $line);
    }
}
