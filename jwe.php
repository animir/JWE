<?php

class JWE {
    private $_openssl_path = '/usr/local/bin/';
    private $_temp_dir = '/tmp/';
    
    public function __construct($openssl_path = null, $tmp_dir = null) {
        if (!is_null($openssl_path)) $this->_openssl_path;
        if (!is_null($tmp_dir)) $this->_temp_dir = $tmp_dir;
        set_include_path(__DIR__ . PATH_SEPARATOR . get_include_path());
    }
    
    public function getOpensslPath() {
        return $this->_openssl_path;
    }
    
    public function setOpensslPath($path) {
        return $this->_openssl_path = $path;
    }    
    /*
     * Decode JWE token with openssl
     * 
     * @param string $jwe JWE token
     * @param string $pemKey Private RSA key in pem format
     * @param string $id Id for temp files
     * @param array Values in JWE token
     */
    public function decodeJWE($jwe, $pemKey, $id = null) {
        require_once 'Zend/Crypt/Rsa.php';
        
        $tks = explode('.', $jwe);
        if (count($tks) != 5) {
            throw new UnexpectedValueException('Wrong number of segments');
        }

        list($headb64, $enckey64, $vector64, $ciphertext64, $values64) = $tks;
        if (null === ($header = $this->jsonDecode($this->urlsafeB64Decode($headb64)))
        ) {
            throw new UnexpectedValueException('Invalid segment encoding');
        }
        if (null === $enckey = $this->urlsafeB64Decode($enckey64)
        ) {
            throw new UnexpectedValueException('Invalid segment encoding');
        }
        $rsa = new Zend_Crypt_Rsa(array('pemString' => $pemKey));
        try {
            openssl_private_decrypt($enckey, $result_key, $rsa->getPrivateKey(), OPENSSL_PKCS1_OAEP_PADDING);
        } catch (Exception $e) {
            return $e->getMessage();
        }
        $vector = bin2hex($this->urlsafeB64Decode($vector64));
        
        $id = session_id();
        $in_filename = $this->_temp_dir . 'in_' . $id;
        $out_filename = $this->_temp_dir . 'out_' . $id;
        $pass_filename = $this->_temp_dir . 'key_' . $id;
        
        $f_in = fopen($in_filename, 'wb+');
        $f_pass = fopen($pass_filename, 'wb+');
        $f_out = fopen($out_filename, 'rb');
        flock($f_in, LOCK_EX);
        flock($f_pass, LOCK_EX);
        flock($f_out, LOCK_EX);        
        
        fwrite($f_in, base64_decode($ciphertext64));        
        
        fwrite($f_pass, $result_key);                
        
        system($this->_openssl_path . "openssl enc -aes-256-gcm -nosalt -d -pass file:$pass_filename -in $in_filename -out $out_filename  -iv $vector");
               
        $values = fread($f_out, filesize($out_filename));
        flock($f_in, LOCK_UN);
        flock($f_pass, LOCK_UN);
        flock($f_out, LOCK_UN);                
        
        fclose($f_in);
        fclose($f_pass);
        fclose($f_out);
        
        unlink($f_in);
        unlink($f_pass);
        unlink($f_out);        
        
        return array('values' => $values);
    }
    
    private function urlsafeB64Decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }
    
    private function jsonDecode($input)
    {
        $obj = json_decode($input);
        if (function_exists('json_last_error') && $errno = json_last_error()) {
            $this->handleJsonError($errno);
        }
        else if ($obj === null && $input !== 'null') {
            throw new DomainException('Null result with non-null input');
        }
        return $obj;
    }
    
    private function handleJsonError($errno)
    {
        $messages = array(
            JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON'
        );
        throw new DomainException(isset($messages[$errno])
            ? $messages[$errno]
            : 'Unknown JSON error: ' . $errno
        );
    }

}
?>