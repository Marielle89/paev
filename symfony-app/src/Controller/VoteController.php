<?php

namespace App\Controller;

use Psr\Cache\CacheItemPoolInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Contracts\Cache\ItemInterface;

final class VoteController extends AbstractController
{
    // Для лаби: 2 кандидати
    private const CANDIDATES = ['A', 'B'];

    // Для лаби: 5 виборців (зареєстровані)
    private const REGISTERED_VOTERS = ['Voter1', 'Voter2', 'Voter3', 'Voter4', 'Voter5'];

    // Redis keys
    private const KEY_TALLY = 'lab1_vote_tally';
    private const KEY_VOTED = 'lab1_vote_voted';


    public function __construct(
        private readonly CacheItemPoolInterface $cache,
    ) {}

    #[Route('/vote/reset', name: 'vote_reset', methods: ['GET'])]
    public function reset(): JsonResponse
    {
        // Просте "скидання": записуємо нульові результати і порожній список тих хто голосував
        $this->cache->delete(self::KEY_TALLY);
        $this->cache->delete(self::KEY_VOTED);

        $this->initIfEmpty();

        return $this->json([
            'ok' => true,
            'message' => 'Election state reset',
            'candidates' => self::CANDIDATES,
            'registeredVoters' => self::REGISTERED_VOTERS,
        ]);
    }

    #[Route('/vote/cast/{voter}/{candidate}', name: 'vote_cast', methods: ['GET'])]
    public function cast(string $voter, string $candidate): JsonResponse
    {
        $this->initIfEmpty();

        // Test #2: незареєстрований виборець
        if (!in_array($voter, self::REGISTERED_VOTERS, true)) {
            return $this->json([
                'ok' => false,
                'error' => 'UNREGISTERED_VOTER',
                'message' => "Voter '{$voter}' is not registered",
            ], 400);
        }

        // Валідація кандидата
        if (!in_array($candidate, self::CANDIDATES, true)) {
            return $this->json([
                'ok' => false,
                'error' => 'UNKNOWN_CANDIDATE',
                'message' => "Candidate '{$candidate}' is not allowed. Use: " . implode(',', self::CANDIDATES),
            ], 400);
        }

        // Дістаємо стан
        $voted = $this->getVoted();
        $tally = $this->getTally();

        // Test #1: повторний бюлетень
        if (!empty($voted[$voter])) {
            return $this->json([
                'ok' => false,
                'error' => 'DUPLICATE_BALLOT',
                'message' => "Voter '{$voter}' has already voted",
                'results' => $this->formatResults($tally),
            ], 409);
        }

        // Приймаємо голос
        $voted[$voter] = true;
        $tally[$candidate] = ($tally[$candidate] ?? 0) + 1;

        $this->saveVoted($voted);
        $this->saveTally($tally);

        return $this->json([
            'ok' => true,
            'message' => "Vote accepted: {$voter} -> {$candidate}",
            'results' => $this->formatResults($tally),
        ]);
    }

    #[Route('/vote/results', name: 'vote_results', methods: ['GET'])]
    public function results(): JsonResponse
    {
        $this->initIfEmpty();

        $tally = $this->getTally();
        $results = $this->formatResults($tally);

        return $this->json([
            'ok' => true,
            'results' => $results,
            'winner' => $this->winnerOrTie($tally),
        ]);
    }

    // -------------------- helpers --------------------

    private function initIfEmpty(): void
    {
        // Ініціалізація якщо Redis пустий
        $this->cache->get(self::KEY_TALLY, function (ItemInterface $item) {
            $item->expiresAfter(60 * 60); // 1 год (для лаби норм)
            return array_fill_keys(self::CANDIDATES, 0);
        });

        $this->cache->get(self::KEY_VOTED, function (ItemInterface $item) {
            $item->expiresAfter(60 * 60);
            return [];
        });
    }

    private function getTally(): array
    {
        return $this->cache->get(self::KEY_TALLY, fn() => array_fill_keys(self::CANDIDATES, 0));
    }

    private function saveTally(array $tally): void
    {
        $item = $this->cache->getItem(self::KEY_TALLY);
        $item->set($tally);
        $item->expiresAfter(60 * 60);
        $this->cache->save($item);
    }

    private function getVoted(): array
    {
        return $this->cache->get(self::KEY_VOTED, fn() => []);
    }

    private function saveVoted(array $voted): void
    {
        $item = $this->cache->getItem(self::KEY_VOTED);
        $item->set($voted);
        $item->expiresAfter(60 * 60);
        $this->cache->save($item);
    }

    private function formatResults(array $tally): array
    {
        // зручно для UI/перевірки
        $out = [];
        foreach (self::CANDIDATES as $c) {
            $out[] = ['candidate' => $c, 'votes' => (int)($tally[$c] ?? 0)];
        }
        return $out;
    }

    private function winnerOrTie(array $tally): array
    {
        $max = max($tally);
        $winners = [];
        foreach ($tally as $candidate => $count) {
            if ($count === $max) {
                $winners[] = $candidate;
            }
        }

        // Test #4: нічия
        if (count($winners) > 1) {
            return ['type' => 'TIE', 'winners' => $winners];
        }

        return ['type' => 'WINNER', 'winner' => $winners[0] ?? null];
    }
}
