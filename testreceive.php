<?php
/*
 * Sample receiving password from device
 * 
 * (C)BiblioEteca Technologies 2019.
 * @author Jose A. Espinosa (yoprogramo@gmail.com)
 * 
 */

require_once 'src/nomorepass.php';

$nmp = new NoMorePass();
$qrtext = $nmp->getQrText('misitio');
?>
<html>
    <head>
        <title>Receiving passwords via QR</title>
    </head>
    <body>
      <img id='barcode' 
            src="https://api.qrserver.com/v1/create-qr-code/?data=<?php echo $qrtext;?>&size=250x250" 
            alt="Scan this" 
            title="Scan this"/>
    </body>
</html>
<?php 
ob_flush();
flush();
$res = $nmp->start();
if (array_key_exists('error',$res)) {
    ?><p><strong>ERROR</strong>: <?php echo $res['error'];?></p> <?php
} else {
    $username = $res['user'];
    $password = $res['password'];
    $extra = $res['extra'];
    ?><p><strong>Password received</strong><br/>Username: <?php echo $username;?><br/>Password: <?php echo $password;?></p><?php
}
ob_flush();
flush();
