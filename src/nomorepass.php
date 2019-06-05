<?php

/*
 * NoMorePass class: PHP interface for sending/retrieving credentials
 * using nomorepass.com cybersecurity services.
 * 
 * (C)BiblioEteca Technologies 2019.
 * @author Jose A. Espinosa (yoprogramo@gmail.com)
 * 
 */

class NoMorePass {
    
    private $server;
    private $base;
    private $getidUrl;
    private $checkUrl;
    private $referenceUrl;
    private $grantUrl;
    private $pingUrl;
    private $stopped;
    private $token;
    private $ticket;

    
    public function __construct($server=NULL) {
        if ($server==NULL)
            $server='nomorepass.com';
        $this->server=$server;
        $this->base="https://".$server;
        $this->getidUrl = $this->base."/api/getid.php";
        $this->checkUrl = $this->base."/api/check.php";
        $this->referenceUrl = $this->base."/api/reference.php";
        $this->grantUrl = $this->base."/api/grant.php";
        $this->pingUrl = $this->base."/api/ping.php";
        $this->stopped = false;
    }

    /*
     * Cryptogrphic functions 
     */
    public function newToken() {
        $length = 12;
        $charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        $retVal = "";
        for ($i=0; $i<$length; $i++){
            $retVal =$retVal.substr($charset, rand(0,$length-1), 1);
        }
        return $retVal;
    }

    public function encrypt($plaintext, $password) {
        $salt = openssl_random_pseudo_bytes(8);
        list($key, $iv) = $this->evpkdf($password, $salt);
        $ct = openssl_encrypt($plaintext, 'aes-256-cbc', $key, true, $iv);
        return $this->encode($ct, $salt);
    }
    
    public function decrypt($encrypted, $passphrase) {
        list($ct, $salt) = $this->decode($encrypted);
        list($key, $iv) = $this->evpkdf($passphrase, $salt);
        $data = openssl_decrypt($ct, 'aes-256-cbc', $key, true, $iv);
        return $data;
    }

    public function evpkdf($passphrase, $salt) {
        $salted = '';
        $dx = '';
        while (strlen($salted) < 48) {
            $dx = md5($dx . $passphrase . $salt, true);
            $salted .= $dx;
        }
        $key = substr($salted, 0, 32);
        $iv = substr($salted, 32, 16);

        return [$key, $iv];
    }

    public function decode($base64) {
        $data = base64_decode($base64);
        if (substr($data, 0, 8) !== "Salted__") {
            throw new \InvalidArgumentException();
        }
        $salt = substr($data, 8, 8);
        $ct = substr($data, 16);
        return [$ct, $salt];
    }

    public function encode($ct, $salt) {
        return base64_encode("Salted__" . $salt . $ct);
    }

    /*
    * NMP Protocol 2 functions
    */

    public function getHeaders () {
        $headers = [
            'Accept: application/json',
            'Cache-Control: no-cache',
            'Content-Type: application/x-www-form-urlencoded; charset=utf-8',
            'User-Agent: NoMorePass-PHP/1.0'
        ];
        return $headers;
    }

    public function prepareRequest ($url,$fields) {
        $data = http_build_query($fields);
        $ch = curl_init ();
        //set the url, number of POST vars, POST data
        curl_setopt($ch,CURLOPT_HTTPHEADER, $this->getHeaders());
        curl_setopt($ch,CURLOPT_URL, $url);
        curl_setopt($ch,CURLOPT_POST, true);
        curl_setopt($ch,CURLOPT_POSTFIELDS, $data);
        curl_setopt($ch,CURLOPT_RETURNTRANSFER, true); 
        return $ch;
    }

    public function getQrText($site){
        $fields = ['site' => $site];
        $ch = $this->prepareRequest($this->getidUrl,$fields);
        //execute post
        $result = curl_exec($ch);
        $http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($http_status==200){
            $res = json_decode($result, true);
            if ($res['resultado']=='ok') {
                $this->ticket = $res['ticket'];
                $this->token = $this->newToken();
                $text = 'nomorepass://'.$this->token.$this->ticket.$site;
                return $text;
            } else {
                return FALSE;
            }
        }
        return FALSE;
    }

    public function getQrSend ($site, $user, $password, $extra) {
        if ($site==NULL) {
            $site='WEBDEVICE';
        }
        $device = 'WEBDEVICE';
        $fields = ['device' => $device, 'fromdevice' => $device];
        $ch = $this->prepareRequest($this->referenceUrl,$fields);
        $result = curl_exec($ch);
        $http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($http_status==200){
            $res = json_decode($result, true);
            if ($res['resultado']=='ok'){
                $token = $res['token'];
                $fields = ['site' => $site];
                $ch = $this->prepareRequest($this->getidUrl,$fields);
                $result = curl_exec($ch);
                $http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                curl_close($ch);
                if ($http_status==200){
                    $res = json_decode($result, true);
                    if ($res['resultado']=='ok'){
                        $tk = $this->newToken();
                        $this->token = $tk;
                        $this->ticket = $res['ticket'];
                        $ep = $this->encrypt($password,$tk);
                        error_log($this->ticket);
                        error_log($tk);
                        error_log($ep);
                        if (is_array($extra)){
                            if (array_key_exists('extra',$extra)){
                                if (is_array($extra['extra']) && array_key_exists('secret',$extra['extra'])){
                                    $extra['extra']['secret']=$this->encrypt($extra['extra']['secret'],$tk);
                                    $extra = json_encode($extra);
                                }
                            }
                        }
                        $fields = ['grant' => 'grant','ticket' => $this->ticket,'user' => $user, 'password' => $ep, 'extra' => $extra];
                        $ch = $this->prepareRequest($this->grantUrl,$fields);
                        $result = curl_exec($ch);
                        $http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                        curl_close($ch);
                        if ($http_status==200){
                            $res = json_decode($result, true);
                            error_log("Granted");
                            $text = 'nomorepass://SENDPASS'.$tk.$this->ticket.$site;
                            return $text;
                        } else {
                            error_log("Error calling grant");
                            return FALSE;
                        }
                    } else {
                        error_log("Not known device");
                        return FALSE;
                    }
                } else {
                    error_log("Error calling getid");
                    return FALSE;
                }
            } else {
                error_log("Error calling getid");
                return FALSE;
            }
        } else {
            return FALSE;
        }
    }

    public function start() {
        while ($this->stopped == False) {
            $fields = ['ticket' => $this->ticket];
            $ch = $this->prepareRequest($this->checkUrl,$fields);
            $result = curl_exec($ch);
            $http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            if ($http_status==200){
                    $res = json_decode($result, true);
                    if ($res['resultado']=='ok'){
                        if ($res['grant']=='deny'){
                            return ['error' => 'denied'];
                        } else {
                            if ($res['grant']=='grant'){
                                $datos = ['user' => $res['usuario'], 'password' => $this->decrypt($res['password'],$this->token), 'extra' => $res['extra']];
                                return $datos;
                            } else {
                                if ($res['grant']=='expired'){
                                    return ['error' => 'expired'];
                                } else {
                                    sleep(4);
                                }
                            }
                        }
                    } else {
                        return ['error' => $res['error']];
                    }
            } else {
                return ['error' => 'network error'];
            }
        }
        $this->stopped = False;
        return ['error' => 'stopped'];

    }

    public function send() {
        while ($this->stopped == False){
            $fields = ['device'=> 'WEBDEVICE','ticket' => $this->ticket];
            $ch = $this->prepareRequest($this->pingUrl,$fields);
            $result = curl_exec($ch);
            $http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            if ($http_status==200){
                $res = json_decode($result, true);
                    if ($res['resultado']=='ok' && $res['ping']=='ok'){
                        sleep(4);
                    } else {
                        return $res;
                    }
            }
        }
    }
}
 
