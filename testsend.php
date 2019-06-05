<?php
/*
 * Sample sending password to device using QR
 * 
 * (C)BiblioEteca Technologies 2019.
 * @author Jose A. Espinosa (yoprogramo@gmail.com)
 * 
 */

require_once 'src/nomorepass.php';

$username = 'myusername';
$password = 'mypassword';
$site = 'mysite';

$nmp = new NoMorePass();
$qrtext = $nmp->getQrSend($site,$username,$password,['type' => 'pwd']);

?>
<html>
    <head>
        <title>Sending passwords via QR</title>
    </head>
    <body>
      <img id='barcode' 
            src="https://api.qrserver.com/v1/create-qr-code/?data=<?php echo $qrtext;?>&size=250x250" 
            alt="Scan this" 
            title="Scan this"/>
      <p>Waiting for user to scan code</p>
    </body>
</html>
<?php 
ob_flush();
flush();
$res = $nmp->send();
if (array_key_exists('error',$res)) {
    ?><p><strong>ERROR</strong>: <?php echo $res['error'];?></p> <?php
} else {
    ?><p>Password received</p><?php
}
ob_flush();
flush();
