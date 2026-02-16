<?php
namespace App\Controller;

use App\Service\ElectionBlindService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class Lab2Controller extends AbstractController
{
    // Для демо збережемо “виданий комплект” у сесії (простий навчальний варіант)
    #[Route('/lab2/setup', name: 'lab2_setup', methods: ['GET'])]
    public function setup(ElectionBlindService $svc): Response
    {
        $data = $svc->setup();
        return $this->render('lab2/setup.html.twig', $data);
    }

    #[Route('/lab2/request', name: 'lab2_request', methods: ['GET','POST'])]
    public function requestSigned(Request $request, ElectionBlindService $svc): Response
    {
        $session = $request->getSession();
        $all = $session->get('lab2_signed_by_name', []); // name => signedSet

        $msg = null;

        if ($request->isMethod('POST')) {
            $name = (string)$request->request->get('name');
            $cheat = (bool)$request->request->get('cheat');

            $res = $svc->requestSignedSet($name, $cheat);
            $msg = $res;

            if (($res['ok'] ?? false) === true) {
                $all[$name] = $res;
                $session->set('lab2_signed_by_name', $all);
            }
        }

        return $this->render('lab2/dashboard.html.twig', [
            'message' => $msg,
            'signedByName' => $all,
            'results' => $svc->results(),
            'voters' => ['Voter1','Voter2','Voter3','Voter4','Voter5'],
        ]);
    }

    #[Route('/lab2/vote', name: 'lab2_vote_action', methods: ['POST'])]
    public function voteAction(Request $request, ElectionBlindService $svc): Response
    {
        $session = $request->getSession();
        $all = $session->get('lab2_signed_by_name', []);

        $name = (string)$request->request->get('name');
        $choice = (string)$request->request->get('choice'); // A|B
        $sendBoth = (bool)$request->request->get('sendBoth');

        $msg = null;

        if (!isset($all[$name]) || !is_array($all[$name]) || ($all[$name]['ok'] ?? false) !== true) {
            $msg = ['ok'=>false,'error'=>'NO_SIGNED_SET','message'=>"No signed set for {$name}"];
        } else {
            $msg = $svc->submitVote($all[$name]['signedBallots'], $choice, $sendBoth);
            // (опційно) можна тут позначати в сесії що “цей виборець вже голосував”
        }

        return $this->redirectToRoute('lab2_request');
    }


    #[Route('/lab2/results', name: 'lab2_results', methods: ['GET'])]
    public function results(ElectionBlindService $svc): Response
    {
        return $this->render('lab2/results.html.twig', $svc->results());
    }

    #[Route('/lab2/reset', name: 'lab2_reset', methods: ['GET'])]
    public function reset(ElectionBlindService $svc): Response
    {
        $svc->reset();
        return $this->redirectToRoute('lab2_setup');
    }
}
