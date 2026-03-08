<?php
namespace App\Service;

final class RsaService
{
    private function gmpInt(string $x): \GMP
    {
        $x = trim($x);
        if ($x === '' || !preg_match('/^\d+$/', $x)) {
            throw new \InvalidArgumentException(
                "GMP expects decimal integer string, got: " . var_export($x, true)
            );
        }
        return gmp_init($x, 10);
    }

    /**
     * Генерує спільний модуль (p,q,n,phi) для всієї групи.
     * Це спрощення для лабораторної, щоб onion-шифрування працювало стабільно.
     */
    public function generateSharedModulus(int $bits = 512): array
    {
        $p = $this->randomPrimeGmp(intdiv($bits, 2));
        $q = $this->randomPrimeGmp(intdiv($bits, 2));

        $n   = gmp_mul($p, $q);
        $phi = gmp_mul(gmp_sub($p, 1), gmp_sub($q, 1));

        return [
            'n'   => gmp_strval($n, 10),
            'phi' => gmp_strval($phi, 10),
        ];
    }

    /**
     * Генерує (e,d) для вже готових phi та n.
     * У кожного виборця буде свій e/d, але спільний n.
     */
    public function generateKeyPairWithSharedN(string $phiDec, string $nDec): array
    {
        $phi = $this->gmpInt($phiDec);
        $n   = $this->gmpInt($nDec);

        // стартуємо з 65537, якщо не підходить — підбираємо
        $e = gmp_init('65537', 10);
        while (gmp_cmp(gmp_gcd($e, $phi), 1) !== 0) {
            $e = gmp_add($e, 2);
        }

        $d = gmp_invert($e, $phi);
        if ($d === false) {
            throw new \RuntimeException('Failed to compute modular inverse for d');
        }

        return [
            'e' => gmp_strval($e, 10),
            'd' => gmp_strval($d, 10),
            'n' => gmp_strval($n, 10),
        ];
    }

    public function encryptNumber(string $mDec, string $eDec, string $nDec): string
    {
        $m = $this->gmpInt($mDec);
        $e = $this->gmpInt($eDec);
        $n = $this->gmpInt($nDec);

        return gmp_strval(gmp_powm($m, $e, $n), 10);
    }

    public function decryptNumber(string $cDec, string $dDec, string $nDec): string
    {
        $c = $this->gmpInt($cDec);
        $d = $this->gmpInt($dDec);
        $n = $this->gmpInt($nDec);

        return gmp_strval(gmp_powm($c, $d, $n), 10);
    }

    public function attachRp(string $xDec, int $rp): string
    {
        if ($rp < 0 || $rp > 999) {
            throw new \InvalidArgumentException('RP must be in range 0..999');
        }
        $x = $this->gmpInt($xDec);
        return gmp_strval(gmp_add(gmp_mul($x, 1000), $rp), 10);
    }

    public function hasRp(string $xDec, int $rp): bool
    {
        $x = $this->gmpInt($xDec);
        return gmp_intval(gmp_mod($x, 1000)) === $rp;
    }

    public function stripRp(string $xDec): string
    {
        $x = $this->gmpInt($xDec);
        return gmp_strval(gmp_div_q($x, 1000), 10);
    }

    public function labHash(string $text, string $nDec): string
    {
        $n = $this->gmpInt($nDec);

        $h = gmp_init('0', 10);
        $bytes = array_values(unpack('C*', $text));
        foreach ($bytes as $b) {
            $mi2 = gmp_mul($b, $b);
            $h = gmp_mod(gmp_add($h, $mi2), $n);
        }
        return gmp_strval($h, 10);
    }

    public function signMessageNumber(string $mDec, string $dDec, string $nDec): string
    {
        $m = $this->gmpInt($mDec);
        $d = $this->gmpInt($dDec);
        $n = $this->gmpInt($nDec);

        return gmp_strval(gmp_powm($m, $d, $n), 10);
    }

    public function verifySignatureOnMessageNumber(string $mDec, string $sigDec, string $eDec, string $nDec): bool
    {
        $m = $this->gmpInt($mDec);
        $s = $this->gmpInt($sigDec);
        $e = $this->gmpInt($eDec);
        $n = $this->gmpInt($nDec);

        $mr = gmp_powm($s, $e, $n);
        return gmp_cmp($mr, $m) === 0;
    }

    // ---- prime helpers ----
    private function randomOddGmp(int $bits): \GMP
    {
        $bytesLen = intdiv($bits + 7, 8);
        $bytes = random_bytes($bytesLen);
        $bytes[0] = $bytes[0] | chr(0x80);
        $bytes[$bytesLen - 1] = $bytes[$bytesLen - 1] | chr(0x01);
        return gmp_init(bin2hex($bytes), 16);
    }

    private function randomPrimeGmp(int $bits): \GMP
    {
        while (true) {
            $x = $this->randomOddGmp($bits);
            if (gmp_prob_prime($x, 10) > 0) {
                return $x;
            }
        }
    }

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
