<?php

namespace App\Controller;

use App\Service\ElectionLab5Service;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class Lab5Controller extends AbstractController
{
    public function __construct(private readonly ElectionLab5Service $lab5) {}

    #[Route('/lab5', name: 'lab5_dashboard', methods: ['GET'])]
    public function dashboard(): Response
    {
        return $this->render('lab5/dashboard.html.twig', [
            'state' => $this->lab5->state(),
        ]);
    }

    #[Route('/lab5/setup', name: 'lab5_setup', methods: ['POST'])]
    public function setup(): Response
    {
        $this->lab5->setup();
        return $this->redirectToRoute('lab5_dashboard');
    }

    #[Route('/lab5/reset', name: 'lab5_reset', methods: ['POST'])]
    public function reset(): Response
    {
        $this->lab5->reset();
        return $this->redirectToRoute('lab5_dashboard');
    }

    #[Route('/lab5/vote', name: 'lab5_vote', methods: ['POST'])]
    public function vote(Request $req): Response
    {
        $voter = (string)$req->request->get('voter');
        $choice = (string)$req->request->get('choice');

        try {
            $res = $this->lab5->castVote($voter, $choice);
        } catch (\Throwable $e) {
            $this->addFlash('error', $e->getMessage());
            return $this->redirectToRoute('lab5_dashboard');
        }

        if (!$res['ok']) {
            $this->addFlash('error', $res['error']);
        }

        return $this->redirectToRoute('lab5_dashboard');
    }

    #[Route('/lab5/encrypt', name: 'lab5_encrypt', methods: ['POST'])]
    public function encrypt(): Response
    {
        try {
            $res = $this->lab5->encryptTwoRounds();
            if (!$res['ok']) $this->addFlash('error', $res['error']);
        } catch (\Throwable $e) {
            $this->addFlash('error', $e->getMessage());
        }

        return $this->redirectToRoute('lab5_dashboard');
    }

    #[Route('/lab5/decrypt/{round}', name: 'lab5_decrypt', methods: ['POST'])]
    public function decrypt(int $round): Response
    {
        try {
            $res = $this->lab5->decryptRound($round);
            if (!$res['ok']) $this->addFlash('error', $res['error']);
        } catch (\Throwable $e) {
            $this->addFlash('error', $e->getMessage());
        }

        return $this->redirectToRoute('lab5_dashboard');
    }

    #[Route('/lab5/tally', name: 'lab5_tally', methods: ['POST'])]
    public function tally(): Response
    {
        try {
            $res = $this->lab5->tally();
            if (!$res['ok']) $this->addFlash('error', $res['error']);
        } catch (\Throwable $e) {
            $this->addFlash('error', $e->getMessage());
        }

        return $this->redirectToRoute('lab5_dashboard');
    }

    // ---------- Test actions (tamper/remove/add) ----------

    #[Route('/lab5/tamper', name: 'lab5_tamper', methods: ['POST'])]
    public function tamper(Request $req): Response
    {
        $index = (int)$req->request->get('index');
        $value = (string)$req->request->get('value');

        try {
            $res = $this->lab5->tamperAtIndex($index, $value);
            if (!$res['ok']) $this->addFlash('error', $res['error']);
        } catch (\Throwable $e) {
            $this->addFlash('error', $e->getMessage());
        }

        return $this->redirectToRoute('lab5_dashboard');
    }

    #[Route('/lab5/remove', name: 'lab5_remove', methods: ['POST'])]
    public function remove(Request $req): Response
    {
        $index = (int)$req->request->get('index');

        try {
            $res = $this->lab5->removeAtIndex($index);
            if (!$res['ok']) $this->addFlash('error', $res['error']);
        } catch (\Throwable $e) {
            $this->addFlash('error', $e->getMessage());
        }

        return $this->redirectToRoute('lab5_dashboard');
    }

    #[Route('/lab5/add', name: 'lab5_add', methods: ['POST'])]
    public function add(Request $req): Response
    {
        $value = (string)$req->request->get('value');

        try {
            $res = $this->lab5->addExtra($value);
            if (!$res['ok']) $this->addFlash('error', $res['error']);
        } catch (\Throwable $e) {
            $this->addFlash('error', $e->getMessage());
        }

        return $this->redirectToRoute('lab5_dashboard');
    }
}
