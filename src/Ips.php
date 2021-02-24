<?php
/**
 * Intrusion Detection System
 * Created by Eko Junaidi Salam <eko.junaidi.salam@gmail.com>
 * 
 * Filter based on PHPIDS with some modification
 * License : LGPL v3.0
 */

class Ips {
    private $fname = 'src/default_filter.json';
    private $filters;
    private static $instance;

    function __construct(){
        if(!file_exists($this->fname)){
            trigger_error($this->fname." is not exists.", E_USER_NOTICE);
            return false;
        }
        $contents = file_get_contents($this->fname);
        if(!isset($contents)){
            trigger_error("contents of ".$this->fname." is null.", E_USER_NOTICE);
            return false;
        }

        if(!$this->isJson($contents)){
            trigger_error("contents of ".$this->fname." must be json.", E_USER_NOTICE);
            return false;
        }

        $this->filters = json_decode($contents);
    }

    private function isJson($string) {
        json_decode($string);
        return (json_last_error() == JSON_ERROR_NONE);
    }       

    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function detect($sample=null,$format=null){
        if(!isset($sample)){
            trigger_error("sample string is null.", E_USER_NOTICE);
            return false;
        }
        switch ($format) {
            case 'b64':
                $mal = strtolower(base64_decode($sample));
                break;
            
            default:
                $mal = strtolower($sample);
                break;
        }
        
        $filters = $this->filters;
        $map_rule = function($mal) use ($filters) {
            yield array_values(array_filter(array_map(function($f) use ($mal){
                $re = '/'.$f->rule.'/';
                if(preg_match($re,$mal)){
                    return array(
                        'detection' => $mal,
                        'dictionary' => $f,
                        'timestamp' => date("Y-m-d H:i:s")
                    );
                }
            },$filters->filters->filter)));
        };
        $map = iterator_to_array($map_rule($mal));
        if(count($map[0])){
            return $map[0];
        }
        return false;
    }
}