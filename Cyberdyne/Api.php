<?php
/**
 * Intellectual Property of Cyberdyne Security Consultancy LTD - Sweden All rights reserved.
 * 
 * @copyright (c) 2017, Cyberdyne Security Consultancy LTD, Dubai, United Arabic Emirates
 * @author V.A. (Victor) Angelier <victor@thecodingcompany.se>
 * @version 1.0
 * @license http://www.apache.org/licenses/GPL-compatibility.html GPL
 * @package Smart Security Scan
 * 
 */

namespace Cyberdyne;

use \GuzzleHttp\Client;

/**
 * HTTP Library for API communication 
 */
class Api extends Client
{
    /**
     * Set path of the Endpoint
     * @var string 
     */
    private $api_url = "";
    
    /**
     * Our HTTP API request object
     * @var type 
     */
    private $request = null;
    
    /**
     * Holds our API access token
     * @var string 
     */
    private $api_access_token = null;
    
    /**
     * Holds our headers
     * @var type 
     */
    private $headers = array();
    
    /**
     * Construct using Singleton pattern
     * @param array $config array("api_url => "", "api_token" => "")
     */
    public function __construct(array $config = array()) {
        
        //Disable SSL verify
        $config["verify"] = false;
        
        //Construct the parent (Client)
        parent::__construct($config);
        
        if(isset($config["api_url"]) && !empty($config["api_url"])){
            $this->api_url = $config["api_url"];
        }
        if(isset($config["api_token"]) && !empty($config["api_token"])){
            $this->api_access_token = $config["api_token"];
            //Set access token
            $this->headers["Authorization"] = $this->api_access_token;
        }
    }
    
    /**
     * Set API URL
     * @param string $url FQDN url to API, https://api.internet.com/v1/
     */
    public function api_url($url = ""){
        if(!empty($url)){
            $this->api_url = $url;
        }        
        return $this;
    }
    
    /**
     * Set API access token
     * @param type $token
     * @return \Cyberdyne\Api
     */
    public function api_token($token = ""){
        if(!empty($token)){
            $this->api_access_token = $token;
        }
        return $this;
    }
    
    /**
     * GET request, to send to the API
     * @param string $path The path to request for example: user/:id
     */
    public function get($path = ""){
        $url = $this->api_url."/".$path;
        if(!$this->valid_url($url)){
            throw new \Exception("Malformed url");
        }
        
        //Send the request
        $this->request = $this->request("GET", $url, array("headers" => $this->headers));
        if((int)$this->request->getStatusCode() === 200){
            if(($json = $this->is_valid()) !== FALSE){
                return $json;
            }           
            return $this->request->getBody()->getContents();
        }else{
            throw new \Exception($this->request->getBody(), $this->request->getStatusCode());
        }
    }
    
    /**
     * POST request, to send to the API
     * @param string $path
     * @param array $parameters Array of key value parameters
     */
    public function post($path = "", $parameters = array()){
        $url = $this->api_url."/".$path;
        if(!$this->valid_url($url)){
            throw new \Exception("Malformed url");
        }
        
        //Creates application/x-www-form-urlencoded request
        $options = array(
            "headers"     => $this->headers
        );
        if(!empty($parameters)){
            $options["form_params"] = $parameters;
        }
        
        //Send the request
        $this->request = $this->request("POST", $url, $options);
        if((int)$this->request->getStatusCode() === 200){
            if(($json = $this->is_valid()) !== FALSE){
                return $json;
            }
            return $this->request->getBody()->getContents();
        }else{
            throw new \Exception($this->request->getBody(), $this->request->getStatusCode());
        }
    }
    
    /**
     * Check if url is valid
     * @param string $url FQDN
     * @return boolean
     */
    private function valid_url($url = ""){
        return (filter_var($url, FILTER_VALIDATE_URL) !== FALSE ? TRUE : FALSE);
    }
    
    /**
     * Handle API response
     * @return boolean
     */
    private function is_valid(){
        $content = $this->request->getBody()->getContents();
        $json = json_decode($content, true);
        if(!empty($json)){
            if(isset($json["result"]) && !empty($json["result"])){
                //If result is JSON
                $res = json_decode($json["result"], true);
                if(!empty($res)){
                    return $res;
                }
                //Probably string data
                return $json["result"];
            }elseif(isset($json["result"])){
                //JSON data returned
                return $json["result"];
            }
            return $json;
        }elseif(!empty($content)){
            return $content;
        }
        return false;
    }
}