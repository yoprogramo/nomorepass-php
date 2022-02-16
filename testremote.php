<?php
/* Example to send password to device using remote credential
 * 
 * (C)BiblioEteca Technologies 2019-2022.
 * @author Jose A. Espinosa 
 * 
 * This example uses the nomorekeys iot network to communicate with the device.
*/
require_once 'src/nomorepass.php';

$cloud = 'https://test.nmkeys.com/extern/send_ticket';
$deviceid='TEST01';
$usuario = 'user';
$password = 'pass';
$secret = 'bada749ad86aa76df533193e464281d9';
$extra = NULL;


$nmp = new NoMorePass(NULL,'FREEKEY');

$result = $nmp->sendRemotePassToDevice($cloud,$deviceid,$secret,$usuario,$password,$extra);
print_r($result);
