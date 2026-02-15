<?php

namespace App\Controller;

use App\Service\ElectionService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class ElectionController extends AbstractController
{
    public function __construct(private readonly ElectionService $election)
    {
    }

    #[Route('/setup', name: 'election_setup', methods: ['GET'])]
    public function setup(): Response
    {
        $data = $this->election->setup();
        return $this->render('election/setup.html.twig', $data);
    }

    #[Route('/vote', name: 'election_vote', methods: ['GET', 'POST'])]
    public function vote(Request $request): Response
    {
        $msg = null;

        if ($request->isMethod('POST')) {
            $voter = (string)$request->request->get('voter');
            $candidate = (string)$request->request->get('candidate');

            $result = $this->election->castVote($voter, $candidate);
            $msg = $result;
        }

        return $this->render('election/vote.html.twig', [
            'state' => $this->election->getState(),
            'message' => $msg,
            'voters' => ['Voter1', 'Voter2', 'Voter3', 'Voter4', 'Voter5', 'Bob'], // Bob для тесту #2
            'candidates' => ['A', 'B'],
        ]);
    }

    #[Route('/results', name: 'election_results', methods: ['GET'])]
    public function results(): Response
    {
        return $this->render('election/results.html.twig', $this->election->results());
    }

    #[Route('/tests', name: 'election_tests', methods: ['GET'])]
    public function tests(): Response
    {
        return $this->render('election/results.html.twig', $this->election->runAllTests());
    }

    #[Route('/', name: 'home', methods: ['GET'])]
    public function home(): Response
    {
        return $this->redirectToRoute('election_vote');
    }

    #[Route('/reset', name: 'election_reset', methods: ['GET'])]
    public function reset(): Response
    {
        $this->election->reset();

        return $this->render('election/reset.html.twig');
    }
}
