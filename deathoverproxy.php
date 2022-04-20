<?php

namespace App\Models;

use CodeIgniter\Model;

class deathoverproxy extends Model
{
   
    protected $useProxy = false;
    protected $trustedProxies = array('0.0.0.0', '127.0.0.1'); // add here IPs from your network structure.
    protected $proxyHeader = 'HTTP_X_FORWARDED_FOR';

    public function getIpAddress()
    {
        $ip = $this->getIpAddressFromProxy();
        
        if ($ip) {
            return $ip;
        }

        if (isset(getenv('REMOTE_ADDR'))) {
            return getenv('REMOTE_ADDR');
        }

        return null;
    }

    protected function getIpAddressFromProxy()
    {
        if (!$this->useProxy || (isset(getenv('REMOTE_ADDR')) && !in_array(getenv('REMOTE_ADDR'), $this->trustedProxies))) {
            return false;
        }

        $header = $this->proxyHeader;
        
        if (!isset(getenv($header)) || empty(getenv($header))) {
            return false;
        }

        $ips = array_diff(array_map('trim', explode(',', getenv($header))), $this->trustedProxies);

        if (empty($ips)) { 
            return false; 
      
        }

        $ip = array_pop($ips);
        return $ip;
    }
    
    
    function SafeBrowsing($url) {
    $apiUrl = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=YOUR_API_KEY_HERE'; // get a free api key through your gmail account.

    $params = ['client' => ['clientId' => 'foobar','clientVersion' => '1.2.3'], 'threatInfo' => ["threatTypes" => ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"], "platformTypes" => ["WINDOWS"], 'threatEntryTypes' => ['URL'],'threatEntries' => [[ 'url' => $url ]]]];

    $ch = curl_init($apiUrl);

    curl_setopt_array($ch, [
        CURLOPT_POST => 1,
        CURLOPT_RETURNTRANSFER => 1,
        CURLOPT_HEADER => 0,
        CURLOPT_POSTFIELDS => json_encode($params),
        CURLOPT_HTTPHEADER => ['Content-Type: text/json'],
    ]);

    $res = curl_exec($ch);
    $err = curl_error($ch);
    
    curl_close($ch);

    if ($err) {
        return 'error';
    } else {
        preg_match_all('/\w+/', $res, $m);
        return (array_diff($m[0], array("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE")) === $m[0]) ? "clean" : "detected";
    }
   }
  
   
   public function blockAdversary() {
    if(!empty($this->getIpAddress())) {
    if(getenv('HTTP_HOST') == getenv('SERVER_NAME')) {
      return $this->SafeBrowsing(getenv('SERVER_NAME'));
   } else {
       return null;
   }
   } else {
       return null;
   }
  }
}
