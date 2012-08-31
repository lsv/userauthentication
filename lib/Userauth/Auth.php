<?php

class Userauth_Auth
{

	/**
	 * @var string The "table" name in redbean
	 */
	public $redbean_dispenser = 'userauth';

	/**
	 * @var string
	 */
	protected $username;

	/**
	 * @var string
	 */
	protected $password;

	/**
	 * @var boolean
	 */
	protected $encrypted = false;

	/**
	 * @param RedBean_Facade $redbeanconnection
	 * @param null $username : can be set with setUsername also
	 * @param null $password : can be set with setPassword also
	 * @param bool $encrypted : can be set with setEncrypted also
	 */
	public function __construct($username = null, $password = null, $encrypted = true)
	{
		$this->setEncrypted($encrypted);
		$this->setUsername($username);
		$this->setPassword($password);

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

	public function logout($session)
	{
		if (isset($session['username'])) {
			unset($session['username']);
		}

		if (isset($session['password'])) {
			unset($session['password']);
		}
	}

	public function setFromSession($session)
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
	 * @param $username : username of the new user
	 * @param $password : password of the new user
	 * @param array $options : other settings for the user, ex age, city or other stuff you would like to set on the user
	 *
	 * @return int : if the user is created the ID of the user gets returned
	 * @throws Exception : if the username already exists
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