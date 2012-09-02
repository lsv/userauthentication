<?php

class Userauth_Auth
{

	/**
	 * @var string : The "table" name in redbean
	 */
	public $redbean_dispenser = 'userauth';

	/**
	 * @var string : The username
	 */
	protected $username;

	/**
	 * @var string : The password
	 */
	protected $password;

	/**
	 * @var boolean
	 */
	protected $encrypted = false;

    /**
     * @var Userauth_Auth
     */
    static protected $_instance = null;

	/**
	 * @param null $username : can be set with setUsername also
	 * @param null $password : can be set with setPassword also
	 * @param bool $encrypted : can be set with setEncrypted also
	 */
	protected function __construct($username, $password, $encrypted)
	{
		$this->setEncrypted($encrypted);
		$this->setUsername($username);
		$this->setPassword($password);
	}

    protected function __clone() {}

    /**
     * @static
     * @param null $username : can be set with setUsername also
     * @param null $password : can be set with setPassword also
     * @param bool $encrypted : can be set with setEncrypted also
     * @return Userauth_Auth
     */
    static public function getInstance($username = null, $password = null, $encrypted = false)
    {
        if (self::$_instance === null)
            return self::$_instance = new self($username, $password, $encrypted);
        return self::$_instance;
    }

	/**
	 * @param $username : username of the user
	 * @return Userauth_Auth
	 */
	public function setUsername($username)
	{
		$this->username = filter_var($username, FILTER_SANITIZE_STRING);
		return $this;
	}

	/**
	 * @param $password : password of the user
	 * @return Userauth_Auth
	 */
	public function setPassword($password)
	{
		$this->password = filter_var($password, FILTER_SANITIZE_STRING);
		return $this;
	}

	/**
	 * @param $encrypted : if the password is already in a encrypted format (if the password is set in the session ex. - should be false if it comes from the login page)
	 * @return Userauth_Auth
	 */
	public function setEncrypted($encrypted)
	{
		$this->encrypted = filter_var($encrypted, FILTER_VALIDATE_BOOLEAN);
		return $this;
	}

	/**
	 * Validates the user from the class properties
	 * @return bool
	 */
	public function validate()
	{
		$password = $this->password;
		if (!$this->encrypted) {
			$password = self::encrypt($password);
		}

		$user = $this->lookupUser($this->username);
		if (! $user instanceof RedBean_OODBBean) {
			return false;
		}

		try {
			$o = new Userauth_Bcrypt(15);
			$hash = $o->hash($password);
			return $o->verify($password, $hash);
		} catch (Exception $e) {
			$o = new Userauth_Mycrypt();
			$hash = $o->hash($password);
			return $o->verify($password, $hash);
		}
	}

    /**
     * @param array $session
     */
    public function logout(array $session)
	{
		if (isset($session['username'])) {
			unset($session['username']);
		}

		if (isset($session['password'])) {
			unset($session['password']);
		}
	}

    /**
     * @param array $session
     * @return Userauth_Auth
     */
    public function setFromSession(array $session)
	{
		if (isset($session['username'], $session['password'])) {
			$this->setUsername($session['username']);
			$this->setPassword($session['password']);
			$this->setEncrypted(true);
		}
		return $this;
	}

	/**
	 * @return array|bool
	 */
	public function getSession()
	{
		if ($this->validate()) {
			return array(
				'password' => $this->encrypt($this->password),
				'username' => $this->username
			);
		}
		return false;
	}

    /**
     * @param array $options : Other options for the user (fx. birthday, realname and such things
     * @return integer : Returns ID of the created user
     * @throws Exception
     */
    public function createUser(array $options = null)
	{
		if ($this->lookupUser($this->username)) {
			throw new Exception('User already exists');
		}

		$user = RedBean_Facade::dispense($this->redbean_dispenser);
		$user->username = $this->username;

		try {
			$o = new Userauth_Bcrypt(15);
			$password = $o->hash($this->encrypt($this->password));
		} catch (Exception $e) {
			$o = new Userauth_Mycrypt();
			$password = $o->hash($this->encrypt($this->password));
		}

		$user->password = $password;
		if (is_array($options)) {
			foreach($options AS $k => $v) {
				$user->{$k} = $v;
			}
		}

		return RedBean_Facade::store($user);

	}

	/**
	 * @param $username
	 * @return RedBean_OODBBean
	 */
	private function lookupUser($username)
	{
		return RedBean_Facade::findOne($this->redbean_dispenser, ' username = ? ', array($username));
	}

	/**
	 * @param $str : string to encrypt - these could be saved in the session
	 * @return string
	 */
	static private function encrypt($str)
	{
		return sha1(md5(sha1(sha1(md5(sha1($str))))));
	}

}