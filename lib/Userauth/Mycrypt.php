<?php

class Userauth_Mycrypt implements Userauth_Interface_Crypt
{

	public function __construct() {}

	public function hash($input)
	{
		return crypt($input);
	}

	public function verify($input, $hash)
	{
		return (crypt($input, $hash) == $hash);
	}
}
