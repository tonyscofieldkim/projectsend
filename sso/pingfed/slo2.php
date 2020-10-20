<?php

/**
 * SLO Request Endpoint.
 * Sends a logout request to IDP
 */


if(isset($_GET['finish'])){
    $location_ =  BASE_URI.'index.php';
    header("Location: $location");
}

require_once('../../sys.includes.php');
require_once('sp_settings/settings.php');

if(!defined('SAML2_SSO_ENABLED') || SAML2_SSO_ENABLED != '1'){
    echo '<p>SSO Method is off</p>';
    exit();
}
$samlSettings = new OneLogin_Saml2_Settings($advancedSettings);
try {
    $idpData = $samlSettings->getIdPData();
    if (isset($idpData['singleLogoutService']) && isset($idpData['singleLogoutService']['url'])) {
        $sloUrl = $idpData['singleLogoutService']['url'];
    } else {
        throw new Exception("The IdP does not support Single Log Out");
    }

    if (isset($_SESSION['IdPSessionIndex']) && !empty($_SESSION['IdPSessionIndex'])) {
        $logoutRequest = new OneLogin_Saml2_LogoutRequest($samlSettings, null, $_SESSION['IdPSessionIndex']);
    } else {
        $logoutRequest = new OneLogin_Saml2_LogoutRequest($samlSettings);
    }

    $samlRequest = $logoutRequest->getRequest();

    $parameters = array('SAMLRequest' => $samlRequest);

    $url = OneLogin_Saml2_Utils::redirect($sloUrl, $parameters, true);

    header("Location: $url");
} catch (Exception $e) {
    echo '<p>Error with request. Could not send Logout request to IDP</p>';
}
