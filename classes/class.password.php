<?php
if (!defined('PASSWORD_DEFAULT')) {
        define('PASSWORD_BCRYPT', 1);
        define('PASSWORD_DEFAULT', PASSWORD_BCRYPT);
}

    Class Password {

        public function __construct() {}


        /**
         * Hash the password using the latest PHP algorithm
         *
         * @param string $password The password to hash
         *
         * @return string|false The hashed password, or false on error and trigger warning.
         */
        function password_hash(string $password): string {
	    if (is_string($password)) {
	        return password_hash($password, PASSWORD_DEFAULT);
	    } else {
                trigger_error("password_hash(): Password must be a string", E_USER_WARNING);
                return false;
	    }
	}

        /**
         * Get information about the password hash. Returns an array of the information
         * that was used to generate the password hash.
         *
         * array(
         *    'algo' => 1,
         *    'algoName' => 'bcrypt',
         *    'options' => array(
         *        'cost' => 10,
         *    ),
         * )
         *
         * @param string $hash The password hash to extract info from
         *
         * @return array The array of information about the hash.
         */
        function password_get_info($hash) {
            $return = array('algo' => 0, 'algoName' => 'unknown', 'options' => array(), );
            if (substr($hash, 0, 4) == '$2y$' && strlen($hash) == 60) {
                $return['algo'] = PASSWORD_BCRYPT;
                $return['algoName'] = 'bcrypt';
                list($cost) = sscanf($hash, "$2y$%d$");
                $return['options']['cost'] = $cost;
            }
            return $return;
        }

        /**
         * Determine if the password hash needs to be rehashed according to the options provided
         *
         * If the answer is true, after validating the password using password_verify, rehash it.
         *
         * @param string $hash    The hash to test
         * @param int    $algo    The algorithm used for new password hashes
         * @param array  $options The options array passed to password_hash
         *
         * @return boolean True if the password needs to be rehashed.
         */
        function password_needs_rehash($hash, $algo, array $options = array()) {
            $info = password_get_info($hash);
            if ($info['algo'] != $algo) {
                return true;
            }
            switch ($algo) {
                case PASSWORD_BCRYPT :
                    $cost = isset($options['cost']) ? $options['cost'] : 10;
                    if ($cost != $info['options']['cost']) {
                        return true;
                    }
                    break;
            }
            return false;
        }

        /**
         * Verify a password against a hash using a timing attack resistant approach
         *
         * @param string $password The password to verify
         * @param string $hash     The hash to verify against
         *
         * @return boolean If the password matches the hash
         */      
        public function password_verify(string $password, string $hash): bool {
            return password_verify($password, $hash);
        }

    }
