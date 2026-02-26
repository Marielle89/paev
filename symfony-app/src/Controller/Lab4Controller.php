<?php
namespace App\Controller;

use App\Service\ElectionLab4Service;
use App\Service\RsaService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class Lab4Controller extends AbstractController
{
    private const VOTERS = ['Voter1','Voter2','Voter3','Voter4','Voter5'];

    #[Route('/lab4/setup', name: 'lab4_setup', methods: ['GET'])]
    public function setup(Request $request, ElectionLab4Service $svc, RsaService $rsa): Response
    {
        $data = $svc->setup();

        // voter keys in session (like Lab3)
        $keysByName = [];
        foreach (self::VOTERS as $name) {
            $keysByName[$name] = $rsa->generateKeyPair(512);
        }

        $session = $request->getSession();
        $session->set('lab4_voter_keys', $keysByName);
        $session->set('lab4_voter_state', []); // name -> anonId, lastSplit, lastChoice
        $session->set('lab4_last_action', null);

        return $this->render('lab4/setup.html.twig', [
            'voters' => self::VOTERS,
            'cecPublic' => $data['cecPublic'],
            'candidates' => $data['candidates'],
        ]);
    }

    #[Route('/lab4/dashboard', name: 'lab4_dashboard', methods: ['GET','POST'])]
    public function dashboard(Request $request, ElectionLab4Service $svc, RsaService $rsa): Response
    {
        $session = $request->getSession();
        $keysByName = $session->get('lab4_voter_keys', []);
        $state = $session->get('lab4_voter_state', []);
        $last = $session->get('lab4_last_action');

        if ($request->isMethod('POST')) {
            $name = (string)$request->request->get('name');
            $choice = (string)$request->request->get('choice'); // A|B
            $breakSig = (bool)$request->request->get('breakSig'); // test #1

            if (!isset($state[$name]['anonId'])) {
                $state[$name]['anonId'] = bin2hex(random_bytes(8));
            }
            $anonId = $state[$name]['anonId'];

            $cand = $svc->candidates();
            $candidateId = $cand[$choice] ?? null;
            if (!$candidateId) {
                $last = ['ok'=>false,'error'=>'BAD_CHOICE'];
                $session->set('lab4_last_action', $last);
                return $this->redirectToRoute('lab4_dashboard');
            }

            // split candidate ID into 2 factors
            [$m1, $m2] = $svc->splitCandidateId((int)$candidateId);
            $state[$name]['lastSplit'] = [$m1,$m2];
            $state[$name]['lastChoice'] = $choice;

            // encrypt each factor with CEC public key
            $cecPub = $svc->cecPublic();
            $c1 = $rsa->encryptNumber((string)$m1, $cecPub['e'], $cecPub['n']);
            $c2 = $rsa->encryptNumber((string)$m2, $cecPub['e'], $cecPub['n']);

            // sign payload for each VK: anonId|vk|cipher
            $kp = $keysByName[$name] ?? null;
            if (!$kp) {
                $last = ['ok'=>false,'error'=>'NO_VOTER_KEYS','message'=>'Run /lab4/setup'];
                $session->set('lab4_last_action', $last);
                return $this->redirectToRoute('lab4_dashboard');
            }

            // VK1 signature
            $p1 = $anonId.'|1|'.$c1;
            $mHash1 = $rsa->labHash($p1, $kp['n']);
            $sig1 = gmp_strval(gmp_powm(gmp_init($mHash1,10), gmp_init($kp['d'],10), gmp_init($kp['n'],10)), 10);

            // VK2 signature
            $p2 = $anonId.'|2|'.$c2;
            $mHash2 = $rsa->labHash($p2, $kp['n']);
            $sig2 = gmp_strval(gmp_powm(gmp_init($mHash2,10), gmp_init($kp['d'],10), gmp_init($kp['n'],10)), 10);

            // simulate broken signature (test #1)
            if ($breakSig) {
                $sig1 = '12345'; // wrong
            }

            // send to VK1 and VK2
            $r1 = $svc->vkReceive(1, $name, $anonId, $c1, ['e'=>$kp['e'],'n'=>$kp['n']], $sig1);
            $r2 = $svc->vkReceive(2, $name, $anonId, $c2, ['e'=>$kp['e'],'n'=>$kp['n']], $sig2);

            $last = ['ok'=>true,'vk1'=>$r1,'vk2'=>$r2,'anonId'=>$anonId,'split'=>[$m1,$m2],'cipher'=>[$c1,$c2]];
            $session->set('lab4_voter_state', $state);
            $session->set('lab4_last_action', $last);

            return $this->redirectToRoute('lab4_dashboard');
        }

        return $this->render('lab4/dashboard.html.twig', [
            'voters' => self::VOTERS,
            'state' => $state,
            'last' => $last,
            'results' => $svc->results(),
            'candidates' => $svc->candidates(),
        ]);
    }

    #[Route('/lab4/publish', name: 'lab4_publish', methods: ['GET','POST'])]
    public function publish(Request $request, ElectionLab4Service $svc): Response
    {
        $last = null;

        if ($request->isMethod('POST')) {
            $action = (string)$request->request->get('action');

            if ($action === 'vk1') $last = $svc->vkPublish(1);
            if ($action === 'vk2') $last = $svc->vkPublish(2);

            if ($action === 'tamper_vk1') {
                $anonId = (string)$request->request->get('anonId');
                $newCipher = (string)$request->request->get('newCipher');
                $last = $svc->vkTamperPublished(1, $anonId, $newCipher); // test #2
            }

            if ($action === 'tally') $last = $svc->cecTally();
        }

        return $this->render('lab4/publish.html.twig', [
            'last' => $last,
            'results' => $svc->results(),
        ]);
    }

    #[Route('/lab4/results', name: 'lab4_results', methods: ['GET'])]
    public function results(ElectionLab4Service $svc): Response
    {
        return $this->render('lab4/results.html.twig', [
            'results' => $svc->results(),
        ]);
    }

    #[Route('/lab4/reset', name: 'lab4_reset', methods: ['GET'])]
    public function reset(ElectionLab4Service $svc): Response
    {
        $svc->reset();
        return $this->redirectToRoute('lab4_setup');
    }
}
