<?php

declare(strict_types=1);

namespace App\Controller;

use App\Service\ElectionLab6Service;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class Lab6Controller extends AbstractController
{
    public function __construct(private readonly ElectionLab6Service $lab6) {}

    #[Route('/lab6', name: 'lab6_dashboard', methods: ['GET'])]
    public function dashboard(): Response
    {
        return $this->render('lab6/dashboard.html.twig', [
            'state' => $this->lab6->state(),
        ]);
    }

    #[Route('/lab6/setup', name: 'lab6_setup', methods: ['POST'])]
    public function setup(): Response
    {
        $this->lab6->setup();
        return $this->redirectToRoute('lab6_dashboard');
    }

    #[Route('/lab6/reset', name: 'lab6_reset', methods: ['POST'])]
    public function reset(): Response
    {
        $this->lab6->reset();
        return $this->redirectToRoute('lab6_dashboard');
    }

    #[Route('/lab6/request-token', name: 'lab6_request_token', methods: ['POST'])]
    public function requestToken(Request $request): Response
    {
        $voter = (string)$request->request->get('voter');
        $res = $this->lab6->requestBlindToken($voter);

        if (!$res['ok']) {
            $this->addFlash('error', $res['error']);
        }

        return $this->redirectToRoute('lab6_dashboard');
    }

    #[Route('/lab6/vote', name: 'lab6_vote', methods: ['POST'])]
    public function vote(Request $request): Response
    {
        $voter = (string)$request->request->get('voter');
        $choice = (string)$request->request->get('choice');

        $res = $this->lab6->castVote($voter, $choice);
        if (!$res['ok']) {
            $this->addFlash('error', $res['error']);
        }

        return $this->redirectToRoute('lab6_dashboard');
    }

    #[Route('/lab6/medium/{medium}', name: 'lab6_medium_tally', methods: ['POST'])]
    public function mediumTally(string $medium): Response
    {
        $res = $this->lab6->mediumTally($medium);
        if (!$res['ok']) {
            $this->addFlash('error', $res['error']);
        }

        return $this->redirectToRoute('lab6_dashboard');
    }

    #[Route('/lab6/final-tally', name: 'lab6_final_tally', methods: ['POST'])]
    public function finalTally(): Response
    {
        $res = $this->lab6->finalTally();
        if (!$res['ok']) {
            $this->addFlash('error', $res['error']);
        }

        return $this->redirectToRoute('lab6_dashboard');
    }

    // ---------- Tests ----------

    #[Route('/lab6/tamper-low', name: 'lab6_tamper_low', methods: ['POST'])]
    public function tamperLow(Request $request): Response
    {
        $low = (string)$request->request->get('low');
        $ballotId = (string)$request->request->get('ballotId');
        $cipher = (string)$request->request->get('cipher');

        $res = $this->lab6->tamperLowPart($low, $ballotId, $cipher);
        if (!$res['ok']) {
            $this->addFlash('error', $res['error']);
        }

        return $this->redirectToRoute('lab6_dashboard');
    }

    #[Route('/lab6/remove-low', name: 'lab6_remove_low', methods: ['POST'])]
    public function removeLow(Request $request): Response
    {
        $low = (string)$request->request->get('low');
        $ballotId = (string)$request->request->get('ballotId');

        $res = $this->lab6->removeLowPart($low, $ballotId);
        if (!$res['ok']) {
            $this->addFlash('error', $res['error']);
        }

        return $this->redirectToRoute('lab6_dashboard');
    }

    #[Route('/lab6/add-fake-low', name: 'lab6_add_fake_low', methods: ['POST'])]
    public function addFakeLow(Request $request): Response
    {
        $low = (string)$request->request->get('low');
        $ballotId = (string)$request->request->get('ballotId');
        $cipher = (string)$request->request->get('cipher');

        $res = $this->lab6->addFakeLowPart($low, $ballotId, $cipher);
        if (!$res['ok']) {
            $this->addFlash('error', $res['error']);
        }

        return $this->redirectToRoute('lab6_dashboard');
    }
}
