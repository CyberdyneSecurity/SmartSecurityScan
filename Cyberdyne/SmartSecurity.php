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

use Cyberdyne\Api;
use Cyberdyne\SecurityScan;

class SmartSecurity extends Api
{
    /**
     * Inital scan task state
     */
    const STATUS_INITIAL = 0;
    
    /**
     * In progress scan task state
     */
    const STATUS_IN_PROGRESS = 1;
    
    /**
     * Scan task completed with sucess
     */
    const STATUS_COMPLETED = 2;
    
    /**
     * Scan task or sub task failed
     */
    const STATUS_FAILED = 3;
    
    /**
     * Holds our Security Scan object
     * @var SecurityScan 
     */
    private $scan = null;
    
    /**
     * Construct new SmartSecurity Scan array("api_url => "", "api_token" => "")
     * @param array $config
     */
    public function __construct(array $config = array()) {
        parent::__construct($config);
    }
    
    /**
     * Get CSRF token for posting data
     * @return boolean | string
     */
    public function getCSRF(){
        $token = $this->get("csrf_token");
        if(!empty($token)){
            return $token;
        }
        return false;
    }
    
    /**
     * Returns all available packages
     * @return boolean | array
     */
    public function getPackages(){
        $list = $this->get("packages");
        if(isset($list["status"]) && !empty($list)){
            return $list["status"];
        }
        return false;
    }
    
    /**
     * Returns all tasks related to the API token with status 'completed'
     * @return boolean | array
     */
    public function getTaskList(){
        $list = $this->post("task/list");
        if(!empty($list)){
            return $list;
        }
        return false;
    }
    
    /**
     * Return all pending tasks
     * @param int $verified Return all verified or non verified tasks
     * @return boolean | array
     */
    public function pendingTasks($verified = 1){
        $list = $this->post("task/list", array(
            "status"    => self::STATUS_INITIAL, 
            "verified"  => $verified));
        if(!empty($list)){
            return $list;
        }
        return false;
    }
    /**
     * Return all failed tasks
     * @return boolean | array
     */
    public function failedTasks(){
        $list = $this->post("task/list", array("status" => self::STATUS_FAILED));
        if(!empty($list)){
            return $list;
        }
        return false;
    }
    /**
     * Return all verification pending tasks
     * @return boolean | array
     */
    public function verifyTasks(){
        $list = $this->post("task/list", array("verified" => 0));
        if(!empty($list)){
            return $list;
        }
        return false;
    }
    /**
     * Return all verification pending tasks
     * @return boolean | array
     */
    public function completedTasks(){
        $list = $this->post("task/list", array("status" => self::STATUS_COMPLETED));
        if(!empty($list)){
            return $list;
        }
        return false;
    }
    
    /**
     * Returns the validation URL for a specific scan.
     * @param int $scan_id Scan task id
     * @return boolean | string Full validation URL
     */
    public function getValidationURL($scan_id = 0){
        $url = $this->get("task/validation/{$scan_id}");
        if(!empty($url)){
            return $url;
        }
        return false;
    }
    
    /**
     * Get scan task status
     * @param int $scan_id Scan task id
     * @return boolean | string
     */
    public function getStatus($scan_id = 0){
        $url = $this->get("task/status/$scan_id");
        if(!empty($url)){
            return $url;
        }
        return false;
    }
    
    /**
     * Create new Security Scan from array
     * @param array $data
     * @return SecurityScan Security Scan object
     */
    public function createScan(array $data = array()){
        $this->scan = new SecurityScan($data);
        return $this;
    }
    
    /**
     * Create new Security Scan with API
     * @param SecurityScan $scan
     * @return int|false Unique scan ID or false on failure
     */
    public function addScan(SecurityScan $scan = null){
        if(empty($this->scan)){
            $this->scan = $scan;
        }
        if($this->scan->get() !== FALSE){
            $info = $this->post("task/create", $this->scan->get());
            return (int)$info;
        }   
        return false;
    }
    
    /**
     * Get the scan report data
     * @param int $scan_id Scan task id
     * @return boolean | HTML data
     */
    public function getReport($scan_id = 0){
        $report_data = $this->get("report/{$scan_id}");
        if(!empty($report_data)){
            return $report_data;
        }
        return false;
    }
}