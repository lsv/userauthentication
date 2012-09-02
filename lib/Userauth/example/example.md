# Easy userauthentication
## Use with composer
php composer.phar install lsv/userauthentication

## Setup Redbean
First we setup our Redbean connection
RedBean_Facade::setup();
Lookup the redbean manual to get more setup details

## Create a user
Exception is cast if the username already exists
ID from the database is returned if the user is created
try {
$id = Userauth_Auth::getInstance()
->setUsername('username')
->setPassword('password')
->setEncrypted(false) // False if the password provided is not encrypted
->createUser();
} catch (Exception $e) {
// Throws Exception if the username already exists
}

We can also add birthday, language, city, realname and other kind of stuff when we create our user
$birthday = new DateTime();
$options = array(
'birthday' => $birthday->format('Y-m-d'),
'realname' => 'My name'
);
try {
$id = Userauth_Auth::getInstance()
->setUsername('username')
->setPassword('password')
->setEncrypted(false) // False if the password provided is not encrypted
->createUser($options);
} catch (Exception $e) {
// Throws Exception if the username already exists
}


## Validate user
Lets validate the user from the login page (where the password is not encrypted)
$o = Userauth_Auth::getInstance()
->setUsername('username')
->setPassword('username')
->setEncrypted(false);
$valid = $o->validate();
if ($valid === true) {
// User is valid - so lets put down the info into a session
$_SESSION['yourkeytoauth'] = $o->getSession();
} else {
// User is not valid
}

Lets validte from the session (where the password is encrypted)
$valid = Userauth_Auth::getInstance()->setFromSession($_SESSION['yourkeytoauth'])->validate();
if ($valid) {
// They user is still valid
} else {
// The user is not valid anymore (properly changed password)
// Redirect to login page or something similar
}

## Logout
Lets logout again
Userauth_Auth::getInstance()->logout($_SESSION['yourkeytoauth']);