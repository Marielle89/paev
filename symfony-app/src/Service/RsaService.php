<?php

declare(strict_types=1);

namespace App\Service;

final readonly class RsaService
{
    public function generateKeyPair(int $bits = 512): array
    {
        // Генеруємо два простих числа p та q
        $p = $this->randomPrime(intdiv($bits, 2));
        do { $q = $this->randomPrime(intdiv($bits, 2)); } while (gmp_cmp($p, $q) === 0);

        $n   = gmp_mul($p, $q); // модуль RSA, буде частиною і публічного, і приватного ключа.
        $phi = gmp_mul(gmp_sub($p, 1), gmp_sub($q, 1)); // функція Ейлера

        $e = gmp_init(65537);
        while (gmp_cmp(gmp_gcd($e, $phi), 1) !== 0) {
            $e = gmp_add($e, 2); // e збільшується на 2, поки не стане взаємно простим з phi
        }

        $d = gmp_invert($e, $phi); // знаходимо приватну експоненту, якщо оберненого не існує кидаємо виключення
        if ($d === false) {
            throw new \RuntimeException('No modular inverse for d');
        }

        return [
            'n' => gmp_strval($n, 10),
            'e' => gmp_strval($e, 10),
            'd' => gmp_strval($d, 10),
        ];
    }

    /**
     * Хеш квадратичної згортки
     * H0=0; Hi = (Hi-1 + Mi)^2 mod n
     * Для JSON/UTF-8 у вебі беремо Mi = байт (0..255).
     */
    public function labHash(string $message, string $nDec): string
    {
        $n = gmp_init($nDec, 10);
        $H = gmp_init(0);

        $bytes = array_values(unpack('C*', $message));
        foreach ($bytes as $Mi) {
            $H = gmp_mod(gmp_pow(gmp_add($H, $Mi), 2), $n);
        }

        return gmp_strval($H, 10);
    }

    /** S = H^d mod n */
    public function sign(string $message, string $dDec, string $nDec): string
    {
        $n = gmp_init($nDec, 10);
        $d = gmp_init($dDec, 10);
        $H = gmp_init($this->labHash($message, $nDec), 10);

        $S = gmp_powm($H, $d, $n);
        return gmp_strval($S, 10);
    }

    /** Hs = S^e mod n; compare to H(message) */
    public function verify(string $message, string $sigDec, string $eDec, string $nDec): bool
    {
        $n  = gmp_init($nDec, 10);
        $e  = gmp_init($eDec, 10);
        $S  = gmp_init($sigDec, 10);

        $H  = gmp_init($this->labHash($message, $nDec), 10);
        $Hs = gmp_powm($S, $e, $n);

        return gmp_cmp($H, $Hs) === 0;
    }

    /**
     * RSA шифрування/дешифрування по байтах
     * c_i = m_i^e mod n, m_i in [0..255]
     */
    public function encryptString(string $plain, string $eDec, string $nDec): array
    {
        $n = gmp_init($nDec, 10);
        $e = gmp_init($eDec, 10);

        $bytes = array_values(unpack('C*', $plain));
        $out = [];
        foreach ($bytes as $b) {
            $out[] = gmp_strval(gmp_powm(gmp_init($b), $e, $n), 10);
        }
        return $out; // array of decimal strings
    }

    public function decryptString(array $cipherDecArray, string $dDec, string $nDec): string
    {
        $n = gmp_init($nDec, 10);
        $d = gmp_init($dDec, 10);

        $bytes = [];
        foreach ($cipherDecArray as $cDec) {
            $m = gmp_powm(gmp_init((string)$cDec, 10), $d, $n);
            $bytes[] = (int) gmp_strval($m, 10);
        }

        return pack('C*', ...$bytes);
    }

    private function randomPrime(int $bits): \GMP
    {
        $bytes = intdiv($bits + 7, 8);
        $rand = random_bytes($bytes);
        $rand[0] = $rand[0] | chr(0x80); // старший біт (0x80) у першому байті
        $rand[$bytes - 1] = $rand[$bytes - 1] | chr(0x01); // робимо чило парним => точно не може бути простим

        $num = gmp_import($rand);

        return gmp_nextprime($num);
    }
}
