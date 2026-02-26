<?php
namespace App\Controller;

use App\Service\ElectionLab3Service;
use App\Service\RsaService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class Lab3Controller extends AbstractController
{
    private const VOTERS = ['Voter1','Voter2','Voter3','Voter4','Voter5'];

    #[Route('/lab3/setup', name: 'lab3_setup', methods: ['GET'])]
    public function setup(Request $request, ElectionLab3Service $svc, RsaService $rsa): Response
    {
        $data = $svc->setup();

        // For demo: generate RSA keys for each voter (for signing)
        $keysByName = [];
        foreach (self::VOTERS as $name) {
            $keysByName[$name] = $rsa->generateKeyPair(512); // has e,n,d
        }

        $session = $request->getSession();
        $session->set('lab3_voter_keys', $keysByName);
        $session->set('lab3_voter_state', []); // name => ['rn'=>..., 'id'=>..., 'vote'=>...]
        $session->set('lab3_last_action', null);

        return $this->render('lab3/setup.html.twig', [
            'ecPublic' => $data['ecPublic'],
            'voters' => self::VOTERS,
        ]);
    }

    #[Route('/lab3/br', name: 'lab3_br', methods: ['GET','POST'])]
    public function br(Request $request, ElectionLab3Service $svc): Response
    {
        $session = $request->getSession();
        $state = $session->get('lab3_voter_state', []);
        $last = $session->get('lab3_last_action');

        if ($request->isMethod('POST')) {
            $action = (string)$request->request->get('action');
            $name = (string)$request->request->get('name');

            if ($action === 'issue') {
                $res = $svc->brIssueRn($name);
                if (($res['rn'] ?? null) && !isset($state[$name]['rn'])) {
                    $state[$name]['rn'] = $res['rn'];
                }
                $last = $res;
            }

            if ($action === 'send') {
                $last = $svc->brSendRnListToEc();
            }

            $session->set('lab3_voter_state', $state);
            $session->set('lab3_last_action', $last);

            return $this->redirectToRoute('lab3_br');
        }

        // refresh RN from BR storage (in case)
        foreach (self::VOTERS as $name) {
            $rn = $svc->brGetRn($name);
            if ($rn) $state[$name]['rn'] = $rn;
        }
        $session->set('lab3_voter_state', $state);

        return $this->render('lab3/br.html.twig', [
            'voters' => self::VOTERS,
            'state' => $state,
            'last' => $last,
            'ecPublic' => $svc->ecPublic(),
        ]);
    }

    #[Route('/lab3/vote', name: 'lab3_vote', methods: ['GET','POST'])]
    public function vote(Request $request, ElectionLab3Service $svc, RsaService $rsa): Response
    {
        $session = $request->getSession();
        $keysByName = $session->get('lab3_voter_keys', []);
        $state = $session->get('lab3_voter_state', []);
        $last = $session->get('lab3_last_action');

        if ($request->isMethod('POST')) {
            $name = (string)$request->request->get('name');
            $vote = (string)$request->request->get('vote'); // A|B
            $mode = (string)$request->request->get('mode'); // normal|rn_again|id_again|invalid_rn

            $rn = $state[$name]['rn'] ?? null;
            if (!$rn) {
                $last = ['ok'=>false,'error'=>'NO_RN','message'=>"No RN for {$name}. Go to /lab3/br first."];
                $session->set('lab3_last_action', $last);
                return $this->redirectToRoute('lab3_vote');
            }

            // voter generates ID once (kept in session)
            if (!isset($state[$name]['id'])) {
                $state[$name]['id'] = bin2hex(random_bytes(8));
            }

            $id = $state[$name]['id'];

            // test modes
            $rnToSend = $rn;
            $idToSend = $id;

            if ($mode === 'invalid_rn') {
                $rnToSend = 'RN-INVALID-' . bin2hex(random_bytes(4));
            }
            if ($mode === 'id_again') {
                // reuse same ID on purpose (try to vote twice by ID)
                $idToSend = $id;
            }
            if ($mode === 'rn_again') {
                // reuse same RN (try to vote twice by RN)
                $rnToSend = $rn;
            }

            // build payload
            $payload = [
                'rn' => $rnToSend,
                'id' => $idToSend,
                'vote' => $vote,
                'ts' => time(),
            ];
            $payloadJson = json_encode($payload, JSON_UNESCAPED_UNICODE);

            // sign payload by voter private key
            $kp = $keysByName[$name] ?? null;
            if (!$kp) {
                $last = ['ok'=>false,'error'=>'NO_VOTER_KEYS','message'=>"Run /lab3/setup first"];
                $session->set('lab3_last_action', $last);
                return $this->redirectToRoute('lab3_vote');
            }

            $m = $rsa->labHash($payloadJson, $kp['n']);
            $sig = gmp_strval(gmp_powm(gmp_init($m,10), gmp_init($kp['d'],10), gmp_init($kp['n'],10)), 10);

            $message = [
                'payload' => $payload,
                'sig' => $sig,
                'voterPub' => ['e' => $kp['e'], 'n' => $kp['n']],
            ];

            // encrypt for EC
            $ecPub = $svc->ecPublic();
            $cipher = $rsa->encryptString(json_encode($message, JSON_UNESCAPED_UNICODE), $ecPub['e'], $ecPub['n']);

            // EC receives
            $last = $svc->ecReceiveEncryptedVote($cipher);

            // If first successful vote, remember what voter believes they voted (for later checking)
            if (($last['ok'] ?? false) === true) {
                // only set "expected vote" if not set yet
                $state[$name]['expectedVote'] ??= $vote;
            }

            $session->set('lab3_voter_state', $state);
            $session->set('lab3_last_action', $last);

            return $this->redirectToRoute('lab3_vote');
        }

        return $this->render('lab3/vote.html.twig', [
            'voters' => self::VOTERS,
            'state' => $state,
            'last' => $last,
            'results' => $svc->results(),
        ]);
    }

    #[Route('/lab3/results', name: 'lab3_results', methods: ['GET','POST'])]
    public function results(Request $request, ElectionLab3Service $svc): Response
    {
        $session = $request->getSession();
        $state = $session->get('lab3_voter_state', []);
        $check = null;

        if ($request->isMethod('POST')) {
            $id = (string)$request->request->get('id');
            $expected = (string)$request->request->get('expected');
            $check = $svc->checkMyVote($id, $expected);
        }

        return $this->render('lab3/results.html.twig', [
            'results' => $svc->results(),
            'state' => $state,
            'check' => $check,
        ]);
    }

    #[Route('/lab3/reset', name: 'lab3_reset', methods: ['GET'])]
    public function reset(ElectionLab3Service $svc): Response
    {
        $svc->reset();
        return $this->redirectToRoute('lab3_setup');
    }
}
