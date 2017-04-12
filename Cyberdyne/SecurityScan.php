<?php
/**
 * Intellectual Property of Cyberdyne Security Consultancy LTD - Sweden All rights reserved.
 * 
 * @copyright (c) 2017, Cyberdyne Security Consultancy LTD, Dubai, United Arabic Emirates
 * @author V.A. (Victor) Angelier <victor@thecodingcompany.se>
 * @version 1.0
 * @license http://www.apache.org/licenses/GPL-compatibility.html GPL
 * @package 
 * 
 */
namespace Cyberdyne;

class SecurityScan
{
    /**
     * FQDN hostname or IPv4 IP address
     * @var type 
     */
    private $hostname = "";
    
    /**
     * Date of execution. For imidiate, set tot today
     * @var type 
     */
    private $execute_date = "";
    
    /**
     * Execution time. Fow imidiate, set to 00:00
     * @var type 
     */
    private $execute_time = "00:00";
    
    /**
     * Scan package chosen from scan package list
     * @var type 
     */
    private $package_id = 1;
        
    /**
     * Construct new scan
     * @param array $data Set of key value data
     */
    public function __construct(array $data = array()){  
        date_default_timezone_set("UTC");
        
        if(!empty($data)){
            if(isset($data["hostname"])){
                $this->hostname = $data["hostname"];
            }
            if(isset($data["execute_date"])){
                $this->execute_date = $data["execute_date"];
            }else{
                $this->execute_date = date("Y-m-d");
            }
            if(isset($data["execute_time"])){
                $this->execute_time = $data["execute_time"];
            }else{
                $this->execute_time = "00:00";
            }
            if(isset($data["package_id"])){
                $this->package_id = (int)$data["package_id"];
            }
        }
    }
    
    /**
     * Validate FQDN
     * @param type $domain
     * @return boolean
     */
    private function valid_domain(){
        ///Not even a single . this will eliminate things like abcd, since http://abcd is reported valid
        if(substr_count($this->hostname, ".") <= 1){
            return false;
        }
        if(stripos($this->hostname, "://") === FALSE){
            $domain = "http://{$this->hostname}";
        }else{
            $domain = $this->hostname;
        }
        return (filter_var($domain, FILTER_VALIDATE_URL) !== FALSE ? TRUE : FALSE);
    }
    
    /**
     * Validate IP address
     * @return type
     */
    private function valid_ipv4(){
        return (filter_var($this->hostname, FILTER_VALIDATE_IP) !== FALSE ? TRUE : FALSE);
    }
    
    /**
     * Full FQDN or IPv4 IP address of the target to scan
     * @param string $hostname FQDN hostname or IPv4 ip address
     * @return \SecurityScan
     */
    public function target($hostname = ""){
        $this->hostname = $hostname;
        return $this;
    }
    
    /**
     * Execution date. For immidiate, set to today
     * @param date $date Y-m-d format
     * @return \SecurityScan
     */
    public function date($date = ""){
        $this->execute_date = date("Y-m-d", strtotime($date));
        return $this;
    }
    
    /**
     * Execution time H:i format. For immidiate, set to 00:00
     * @param time $time H:i format
     * @return \SecurityScan
     */
    public function time($time = ""){
        $this->execute_time = $time;
        return $this;
    }
    
    /**
     * Set the package ID to use for the scan
     * @param int $package_id Package ID chosen from the list of scan packages
     * @return \SecurityScan
     */
    public function package($package_id = 1){
        $this->package_id = (int)$package_id;
        return $this;
    }
    
    /**
     * Validate our input
     */
    private function validate(){
        $is_domain = false;
        if($this->valid_domain() === FALSE){
            echo "<p>Invalid FQDN or hostname.</p>";
            return false;
        }else{
            $is_domain = true; //To bypass IPv4 check
        }
        if($is_domain === FALSE && $this->valid_ipv4() === FALSE){
            echo "<p>Invalid IPv4 IP address.</p>";
            return false;
        }
        if((int)mb_strlen($this->execute_time) !== 5){
            echo "<p>Invalid execution time provided.</p>";
            return false;
        }   
        if($this->execute_date == "1970-01-01" || $this->execute_date == "0000-00-00"){
            echo "<p>Invalid execution date provided.</p>";
            return false;
        }
        return true;
    }
    
    /**
     * Get the array with data
     */
    private function _get(){
        //Return our set of values
        return array(
            "hostname"      => $this->hostname,
            "package_id"    => $this->package_id,
            "execute_time"  => $this->execute_time,
            "execute_date"  => $this->execute_date
        );
    }
    
    /**
     * Validates and returns postable data to post
     * @return array|false Array with key => value data
     */
    public function get(){
        if($this->validate()){
            return $this->_get();            
        }
        return false;
    }
    
    /**
     * Get JSON data to post
     * @return json|false JSON dataset
     */
    public function getJSON(){
        if($this->validate()){
            return json_encode($this->_get());
        }
        return false;
    }
    
    /**
     * Get URL encoded string with data
     * @return string|false URL Encoded data
     */
    public function getURI(){
        if($this->validate()){
            return http_build_query($this->_get());
        }
        return false;
    }
}