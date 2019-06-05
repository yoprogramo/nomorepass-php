# nomorepass-php
PHP libraries for nomorepass.com public API

You can use this library in combination with nomorepass app (nomorepass.com) to send or receive passwords in a safe an easy way.

## How to use

Just copy the nomorepass.php file in your sources an import it:

```
requiere_once 'nomorepass.php';
```

## To send passwords

```
$username = 'myusername';
$password = 'mypassword';
$site = 'mysite';

$nmp = new NoMorePass();
$qrtext = $nmp->getQrSend($site,$username,$password,['type' => 'pwd']);

// Here you can show the QR with $qrtext inside
// the user has 2 hours to scan and receive the password
```

If you want to wait until the password were received you can do with

```
$res = $nmp->send();
```

## To receive passwords

```
$nmp = new NoMorePass();
$qrtext = $nmp->getQrText('misitio');
// Show the qrcode and wait for response
$res = $nmp->start();
if (array_key_exists('error',$res)) {
    error_log("Error");
} else {
    $username = $res['user'];
    $password = $res['password'];
    $extra = $res['extra'];
}
```

## Examples

You can see the examples in this directory to check the libraries

* testsend.php : example to send a password to mobile phone
* testreceive.php : example to receive a password sent from mobile phone

## More info

visit https://nomorepass.com or open here an issue

## Other libraries

* node/js: https://github.com/yoprogramo/nomorepass
* python: https://github.com/yoprogramo/nomorepass-py

## How to use NoMorePass

1. Download and install the mobile app

* [android] https://play.google.com/store/apps/details?id=com.biblioeteca.apps.NoMorePass
* [ios] https://itunes.apple.com/us/app/no-more-pass/id1199780162?l=es&ls=1&mt=8

3. Open it and create a new password (or use some of yours)
4. Then you can scan the qrcode generated by the library to send securely this password to your app or send/update passwords from your code to the app.

(c) 2019 Nomorepass.com
