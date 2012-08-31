<?php

interface Userauth_Interface_Crypt
{

	public function hash($input);
	public function verify($input, $hash);


}
