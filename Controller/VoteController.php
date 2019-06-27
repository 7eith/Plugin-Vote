<?php
class VoteController extends VoteAppController {

    public function index()
    {
        $this->set('title_for_layout', $this->Lang->get('VOTE__TITLE'));
        $this->set('config', $this->__getConfig());

        $this->loadModel('Vote.Website');
        $this->loadModel('Vote.Reward');        
        $this->loadModel('Server');
        $websites = $this->Website->find('all');
        $servers = $this->Server->findSelectableServers();
        $rewards = $this->Reward->find('all');
        $websitesByServers = [];
        foreach ($websites as $website) {
            if (!isset($servers[$website['Website']['server_id']]))
                continue;
            if (!isset($websitesByServers[$servers[$website['Website']['server_id']]]))
                $websitesByServers[$servers[$website['Website']['server_id']]] = [];
            $websitesByServers[$servers[$website['Website']['server_id']]][] = $website;
        }
        $this->set(compact('websitesByServers', 'rewards'));
        $this->set('users', array_map(function ($row) {
            return ['username' => $row['Vote']['username'], 'count' => $row[0]['count']];
        }, $this->Vote->find('all', [
            'fields' => ['username', 'COUNT(id) AS count'],
            'conditions' => [
              'created LIKE' =>  date('Y') . '-' . date('m') . '-%',
              'Vote.deleted_at' => null
            ],
            'order' => 'count DESC',
            'group' => 'username',
            'limit' => 15
        ])));
    }

    public function setUser()
    {
        $this->Session->delete('voted');
        if (!$this->request->is('post'))
            throw new NotFoundException();
        if ((empty($this->request->data) || !isset($this->request->data['username'])) && !$this->User->isConnected())
            throw new BadRequestException();
        $this->autoRender = false;
        $this->response->type('json');
        if (empty($this->request->data['username']) && !$this->User->isConnected())
            return $this->sendJSON(['statut' => false, 'msg' => $this->Lang->get('ERROR__FILL_ALL_FIELDS')]);

        if ($this->User->isConnected()) { // If already logged
            $user = ['username' => $this->User->getKey('pseudo'), 'id' => $this->User->getKey('id')];
        } else if ($this->__getConfig()->need_register) { // If need register, check if username is valid
            $searchUser = $this->User->find('first', ['fields' => ['pseudo', 'id'], 'conditions' => ['pseudo' => $this->request->data['username']]]);
            if (empty($searchUser))
                return $this->sendJSON(['statut' => false, 'msg' => $this->Lang->get('VOTE__SET_USER_ERROR_USER_NOT_FOUND')]);
            $user = ['username' => $searchUser['User']['pseudo'], 'id' => $searchUser['User']['id']];
        } else {
            $searchUser = $this->User->find('first', ['fields' => ['id'], 'conditions' => ['pseudo' => $this->request->data['username']]]);
            if (empty($searchUser))
                $user = ['username' => $this->request->data['username']];
            else
                $user = ['username' => $this->request->data['username'], 'id' => $searchUser['User']['id']];
        }

        // Store it
        $this->Session->write('vote.user', $user);
        $this->sendJSON(['statut' => true, 'msg' => $this->Lang->get('VOTE__SET_USER_SUCCESS')]);
    }

    public function setWebsite()
    {
        $this->Session->delete('voted');
        if (!$this->request->is('post'))
            throw new NotFoundException();
        if (empty($this->request->data) || empty($this->request->data['website_id']))
            throw new BadRequestException();
        $this->autoRender = false;
        $this->response->type('json');

        // Check if user is stored
        if (!$this->Session->check('vote.user.username'))
            throw new ForbiddenException();

        // Find website
        $this->loadModel('Vote.Website');
        $website = $this->Website->find('first', ['conditions' => ['id' => $this->request->data['website_id']]]);
        if (empty($website))
            throw new NotFoundException();

        // Check if has already vote and if time isn't enough
        $this->loadModel('Vote.Vote');
        if (!$this->Vote->can($this->Session->read('vote.user'), $this->Util->getIP(), $website['Website']))
            return $this->sendJSON(['status' => false, 'error' => $this->Lang->get('VOTE__SET_WEBSITE_ERROR_NEED_WAIT', ['{TIME}' => $this->Util->generateStringFromTime($this->Vote->getNextVoteTime($this->Session->read('vote.user'), $this->Util->getIP(), $website['Website']))])]);

        // Store it
        $this->Session->write('vote.website.id', $this->request->data['website_id']);
        $this->sendJSON(['status' => true, 'success' => $this->Lang->get('VOTE__SET_WEBSITE_SUCCESS'), 'data' => ['website' => ['url' => $website['Website']['url']]]]);
    }

    public function checkVote()
    {
        $this->Session->delete('voted');
        if (!$this->request->is('ajax'))
            throw new NotFoundException();
        $this->autoRender = false;
        $this->response->type('json');

        // Check if user is stored
        if (!$this->Session->check('vote.user.username'))
            throw new ForbiddenException();
        // Check if website is stored
        if (!$this->Session->check('vote.website.id'))
            throw new ForbiddenException();

        // Check if website type need verification
        $this->loadModel('Vote.Website');
        $website = $this->Website->find('first', ['conditions' => ['id' => $this->Session->read('vote.website.id')]]);
        if (empty($website))
            throw new NotFoundException();
        $this->loadModel('Vote.Vote');
        if (!$this->Website->valid($this->Session->read('vote.user'), $this->Util->getIP(), $website['Website']))
            return $this->sendJSON(['status' => false]);

        // Store it
        $this->Session->write('vote.check', true);
        $this->sendJSON(['status' => true, 'success' => $this->Lang->get('VOTE__VOTE_SUCCESS'), 'reward_later' => $this->Session->check('vote.user.id')]);
    }

    public function getReward()
    {
        if (!$this->request->is('ajax'))
            throw new NotFoundException();
        if (empty($this->request->data) || empty($this->request->data['reward_time']) || !in_array($this->request->data['reward_time'], ['NOW', 'LATER']))
            throw new BadRequestException();
        if ($this->request->data['reward_time'] === 'LATER' && !$this->Session->check('vote.user.id'))
            throw new BadRequestException();
        $this->autoRender = false;
        $this->response->type('json');

        if ($this->Session->check('voted')) { // Fail
            // Get last vote not collected
            $findVote = $this->Vote->find('first', ['conditions' => ['collected' => 0, 'vote.ip' => $this->Util->getIP()], 'recursive' => 1]);
            if (empty($findVote))
                throw new ForbiddenException();
            $this->loadModel('Vote.Reward');
            if (!$this->Reward->collect($findVote['Reward'], $findVote['Website']['id'], $this->Session->read('voted'), $this->Server, [$this->__getConfig()->global_command]))
                return $this->sendJSON(['status' => false, 'error' => $this->Lang->get('VOTE__GET_REWARDS_NOW_ERROR_RETRY')]);

            $this->Vote->read(null, $findVote['Vote']['id']);
            $this->Vote->set(['collected' => 1]);
            $this->Vote->save();

            $this->Session->delete('voted');
            return $this->sendJSON(['status' => true, 'success' => $this->Lang->get('VOTE__GET_REWARDS_NOW_SUCCESS')]);
        }

        // Check if user is stored
        if (!$this->Session->check('vote.user.username'))
            throw new ForbiddenException();
        // Check if website is stored
        if (!$this->Session->check('vote.website.id'))
            throw new ForbiddenException();
        // Check if vote is stored
        if (!$this->Session->check('vote.check'))
            throw new ForbiddenException();

        // Get website
        $this->loadModel('Vote.Website');
        $website = $this->Website->find('first', ['conditions' => ['id' => $this->Session->read('vote.website.id')]]);
        if (empty($website))
            throw new NotFoundException();

        // Check if user can vote
        $this->loadModel('Vote.Vote');
        if (!$this->Vote->can($this->Session->read('vote.user'), $this->Util->getIP(), $website['Website']))
            return $this->sendJSON(['status' => false, 'error' => $this->Lang->get('VOTE__SET_WEBSITE_ERROR_NEED_WAIT', ['{TIME}' => $this->Util->generateStringFromTime($this->Vote->getNextVoteTime($this->Session->read('vote.user'), $this->Util->getIP(), $website['Website']))])]);

        // Generate random reward
        $this->loadModel('Vote.Reward');
        $reward = $this->Reward->getFromWebsite($website['Website']);

        // Store it
        $user = $this->Session->read('vote.user');
        $this->Vote->create();
        $this->Vote->set([
            'username' => $user['username'],
            'user_id' => (isset($user['id'])) ? $user['id'] : null,
            'reward_id' => $reward['id'],
            'collected' => 0,
            'website_id' => $website['Website']['id'],
            'ip' => $this->Util->getIP()
        ]);
        $this->Vote->save();

        // Destroy session
        $this->Session->delete('vote');
        $this->Session->delete('voted');

        // If he want reward now, try to give it
        if ($this->request->data['reward_time'] === 'LATER')
            return $this->sendJSON(['status' => true, 'success' => $this->Lang->get('VOTE__GET_REWARDS_LATER_SUCCESS')]);
        // Try to collect
        if (!($collect = $this->Reward->collect($reward, $website['Website']['server_id'], $user['username'], $this->Server, [$this->__getConfig()->global_command])) && isset($user['id']))
            return $this->sendJSON(['status' => true, 'success' => $this->Lang->get('VOTE__GET_REWARDS_NOW_ERROR')]);
        else if (!$collect && !isset($user['id'])) {
            $this->Session->write('voted', $user['username']);
            return $this->sendJSON(['status' => false, 'error' => $this->Lang->get('VOTE__GET_REWARDS_NOW_ERROR_RETRY')]);
        }

        // money
        if ($reward['amount'] > 0 && isset($user['id']))
            $this->User->setToUser('money', (floatval($this->User->getFromUser('money', $user['id'])) + floatval($reward['amount'])), $user['id']);

        // Set as collected
        $this->Vote->read(null, $this->Vote->getLastInsertId());
        $this->Vote->set(['collected' => 1]);
        $this->Vote->save();

        // Success message
        $this->sendJSON(['status' => true, 'success' => $this->Lang->get('VOTE__GET_REWARDS_NOW_SUCCESS')]);
    }

    public function getNotCollectedReward()
    {
        if (!$this->Permissions->can('VOTE__COLLECT_REWARD'))
            throw new ForbiddenException();
        $this->loadModel('Vote.Vote');
        $findVote = $this->Vote->find('first', ['conditions' => ['user_id' => $this->User->getKey('id'), 'collected' => 0], 'recursive' => 1]);
        if (empty($findVote))
            throw new NotFoundException();
        // Give it
        $this->loadModel('Vote.Reward');
        $reward = $findVote['Reward'];
        if (!$this->Reward->collect($reward, $findVote['Website']['server_id'], $this->User->getKey('pseudo'), $this->Server, [$this->__getConfig()->global_command])) {
            $this->Session->setFlash($this->Lang->get('VOTE__COLLECT_REWARD_ERROR'), 'default.error');
            $this->redirect($this->referer());
            return;
        }
        // Add money
        if ($reward['amount'] > 0)
            $this->User->setKey('money', (floatval($this->User->getKey('money')) + floatval($reward['amount'])));
        // Set as collected
        $this->Vote->read(null, $findVote['Vote']['id']);
        $this->Vote->set(['collected' => 1]);
        $this->Vote->save();

        // Redirect
        $this->Session->setFlash($this->Lang->get('VOTE__COLLECT_REWARD_SUCCESS'), 'default.success');
        $this->redirect($this->referer());
    }

    private function __getConfig()
    {
        $this->loadModel('Vote.VoteConfiguration');
        return (object)$this->VoteConfiguration->getConfig();
    }

    public function admin_configuration()
    {
        if (!$this->Permissions->can('VOTE__ADMIN_MANAGE'))
            throw new ForbiddenException();
        $this->set('title_for_layout', $this->Lang->get('VOTE__ADMIN_VOTE_CONFIGURATION_TITLE'));
        $this->loadModel('Vote.VoteConfiguration');
        $this->set('configuration', $this->VoteConfiguration->getConfig());
        $this->layout = 'admin';

        if ($this->request->is('ajax')) {
            $this->autoRender = false;
            $this->response->type('json');
            if (!isset($this->request->data['need_register']) || !isset($this->request->data['global_command']))
                return $this->sendJSON(['statut' => false, 'msg' => $this->Lang->get('ERROR__FILL_ALL_FIELDS')]);
            $this->VoteConfiguration->read(null, 1);
            $this->VoteConfiguration->set([
                'need_register' => $this->request->data['need_register'],
                'global_command' => $this->request->data['global_command']
            ]);
            $this->VoteConfiguration->save();

            $this->History->set('EDIT_VOTE_CONFIGURATION', 'vote');
            return $this->sendJSON(['statut' => true, 'msg' => $this->Lang->get('VOTE__ADMIN_EDIT_CONFIG_SUCCESS')]);
        }
    }

    public function apiCheck()
    {
        $this->loadModel('Vote.Vote');
        $this->loadModel('Vote.Website');
        $username = $this->request->params['username'];
        return $this->sendJSON([
            'status' => true,
            'can_vote' => $this->Vote->canInAll(['username' => $username], '0.0.0.0', $this->Website->find('all'))
        ]);
    }

    /** ----------------------
     *      Snkh Inc.
     ---------------------- */

    public function checkOut()
    {
        if (!$this->request->is('ajax'))
            throw new NotFoundException();

        $this->autoRender = false;
        $this->response->type('json');

        // has params out
        if (empty($this->request->data['out']))
            return $this->sendJSON(['statut' => false, 'msg' => $this->Lang->get('VOTE__ERROR_OUT_EMPTY')]);

        $out = $this->request->data['out'];

        // is numeric
        if(!is_numeric($out)) 
            return $this->response->body(json_encode(array('statut' => false, 'msg' => $this->Lang->get('VOTE__ERROR_OUT_NOT_NUMBER'))));

        // error :( 
        if($this->getCurrentOut() == -1) {
            return $this->response->body(json_encode(array('statut' => true, 'msg' => $this->Lang->get('VOTE__RPG__API_ERROR'))));
        }

        if($out == $this->getCurrentOut()) {
            return $this->response->body(json_encode(array('statut' => true, 'msg' => $this->Lang->get('VOTE__CHECK_OUT_SUCCESS'))));
        } else {
            return $this->response->body(json_encode(array('statut' => false, 'msg' => $this->Lang->get('VOTE__ERROR_OUT_INVALID'))));
        }
    }


    private function getCurrentOut()
    {
        $url = "http://rpg-paradize.com/site-Qataria++Serveur+PvP-Faction-110512";
        $user_agent = 'Mozilla/5.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100101 Firefox/4.0.1'; // simule Firefox 4.
        $header[0] = "Accept: text/xml,application/xml,application/xhtml+xml,";
        $header[0] .= "text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5";
        $header[] = "Cache-Control: max-age=0";
        $header[] = "Connection: keep-alive";
        $header[] = "Keep-Alive: 300";
        $header[] = "Accept-Charset: utf-8";
        $header[] = "Accept-Language: fr"; // langue fr.
        $header[] = "Pragma: "; // Simule un navigateur

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url); // l'url visité
        curl_setopt($ch, CURLOPT_FAILONERROR, 1);// Gestion d'erreur
        curl_setopt($ch, CURLOPT_RETURNTRANSFER,1); // stock la response dans une variable
        curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
        curl_setopt($ch, CURLOPT_PORT, 80); // set port 80
        curl_setopt($ch, CURLOPT_TIMEOUT, 2); //  timeout curl à 15 secondes.
        curl_setopt($ch, CURLOPT_USERAGENT, $user_agent);

        $result=curl_exec($ch);
        $error = curl_errno($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if($result !== false) {
            $str = substr($result, strpos($result, 'Clic Sortant'), 20);
            $out = filter_var($str, FILTER_SANITIZE_NUMBER_INT);
            $array = array($out, $out-1, $out-2, $out-3, $out+1, $out+2, $out+3);
            return $out;
        } else {
            return -1;
        }
    }
}