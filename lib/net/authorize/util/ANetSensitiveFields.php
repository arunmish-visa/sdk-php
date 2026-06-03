<?php
namespace net\authorize\util;



define("ANET_SENSITIVE_XMLTAGS_JSON_FILE","AuthorizedNetSensitiveTagsConfig.json");
define("ANET_SENSITIVE_DATE_CONFIG_CLASS",'net\authorize\util\SensitiveDataConfigType');

class ANetSensitiveFields
{
    private static $applySensitiveTags = NULL;
    private static $sensitiveStringRegexes = NULL;

    private static function fetchFromConfigFiles(){
        if(!class_exists(ANET_SENSITIVE_DATE_CONFIG_CLASS))
            exit("Class (".ANET_SENSITIVE_DATE_CONFIG_CLASS.") doesn't exist; can't deserialize json; can't log. Exiting.");

        $configFilePath = dirname(__FILE__) . "/" . ANET_SENSITIVE_XMLTAGS_JSON_FILE;

        if(!file_exists($configFilePath)){
            exit("ERROR: No config file: " . $configFilePath);
        }

        try{
            $jsonFileData = file_get_contents($configFilePath);
            $sensitiveDataConfig = json_decode($jsonFileData);

            $sensitiveTags = $sensitiveDataConfig->sensitiveTags;
            self::$sensitiveStringRegexes = $sensitiveDataConfig->sensitiveStringRegexes;
        }
        catch(\Exception $e){
            exit("ERROR deserializing json from : " . $configFilePath  . "; Exception : " . $e->getMessage());
        }

        self::$applySensitiveTags = array();
        foreach($sensitiveTags as $sensitiveTag){
            if($sensitiveTag->disableMask){
                continue;
            }

            if(trim($sensitiveTag->pattern)) {
                if(@preg_match('/' . $sensitiveTag->pattern . '/u', '') === false) {
                    $sensitiveTag->pattern = "";
                }
            }

            array_push(self::$applySensitiveTags, $sensitiveTag);
        }

        if(is_array(self::$sensitiveStringRegexes)) {
            $validatedRegexes = array();
            foreach(self::$sensitiveStringRegexes as $regex) {
                if(@preg_match('/' . $regex . '/u', '') !== false) {
                    $validatedRegexes[] = $regex;
                }
            }
            self::$sensitiveStringRegexes = $validatedRegexes;
        }
    }
    
    public static function getSensitiveStringRegexes(){
        if(NULL == self::$sensitiveStringRegexes) {
            self::fetchFromConfigFiles();
        }
        return self::$sensitiveStringRegexes;
    }
    
    public static function getSensitiveXmlTags(){
        if(NULL == self::$applySensitiveTags) {
            self::fetchFromConfigFiles();
        }
        return self::$applySensitiveTags;
    }
}
