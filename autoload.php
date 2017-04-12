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
define('CLASS_DIR', __DIR__);
set_include_path(get_include_path().PATH_SEPARATOR.CLASS_DIR);
    
spl_autoload_register(function($name){
    //For namespaces we replace \ with / to correct the Path
    $filename = str_replace("\\", "/", $name);
    require_once "{$filename}.php";    
});