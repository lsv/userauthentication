<?php
// First we setup our Redbean connection
RedBean_Facade::setup();
// Lookup the redbean manual to get more setup details

// Create a user
$o = new Userauth_Auth();

try {
	$userid = $o->setUsername('username')
		->setPassword('password')
		->createUser();
} catch (Exception $e) {
	echo $e->getMessage();
}

// Exception is cast if the username already exists
// ID from the database is returned if the user is created


// Login from a HTML form (where the password is not encrypted)
$valid = $o->setUsername($username)
	->setPassword($password)
	->validate();

if ($valid) { // If valid is true, the user exists and the correct password is entered
	$_SESSION['yourkeytoauth'] = $o->getSession(); // Lets add to a session
} else {
	// Your login was not correct
	// Send a message to the user
}

// Lets validte from the session
if ($o->setFromSession($_SESSION['yourkeytoauth'])->validate()) { // True if validated other wise false
	// Your are still logged in
} else {
	// Redirect to login page
}

// Lets logout again
$o->logout($_SESSION['yourkeytoauth']);

// When creating a user, we could also add other stuff to the user, ex. city, language or what ever you want
$birthday = new DateTime();
$options = array(
	'city' => 'Copenhagen',
	'language' => 'danish',
	'birthday' => $birthday->format('Y-m-d')
);

$o->setUsername('newuser')
	->setPassword('newpassword')
	->createUser($options);