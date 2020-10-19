<?php

/**
 * Asertion consumption Endponit for SSO
 */

session_start();
session_regenerate_id();

require_once('../../sys.includes.php');
require_once('sp_settings/settings.php');

$auth = new OneLogin_Saml2_Auth($advancedSettings);
if (isset($_SESSION) && isset($_SESSION['AuthNRequestID'])) {
    $requestID = $_SESSION['AuthNRequestID'];
} else {
    $requestID = null;
}

$auth->processResponse($requestID);

$errors = $auth->getErrors();

if (!empty($errors)) {
    echo '<p>', implode(', ', $errors), '</p>'; //not good to print these errors to user
}

if (!$auth->isAuthenticated()) {
    echo "<p>Not authenticated</p>";
    exit();
}
//check if the user exist
$attributes = $auth->getAttributes();
$nameId = $auth->getNameId();
$nameIdFormat = $auth->getNameIdFormat();
$nameIdQualifier = $auth->getNameIdNameQualifier();
$nameIdServiceNameQualifier = $auth->getNameIdSPNameQualifier();
$sessionIndex = $auth->getSessionIndex();
unset($_SESSION['AuthNRequestID']);




//last if might be redundant
if (isset($_POST['RelayState']) && OneLogin_Saml2_Utils::getSelfURL() != $_POST['RelayState']) {
    $auth->redirectTo($_POST['RelayState']);
}
