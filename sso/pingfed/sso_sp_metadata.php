<?php
 
/**
 *  SP Metadata Endpoint
 */

require_once('../../sys.includes.php');
require_once('sp_settings/settings.php');

if(!defined('SAML2_SSO_ENABLED') || SAML2_SSO_ENABLED != '1'){
    exit('SSO Method is off');
}
try {
    $auth = new OneLogin_Saml2_Auth($advancedSettings);
    $settings = $auth->getSettings();
    $metadata = $settings->getSPMetadata();
    $errors = $settings->validateMetadata($metadata);
    if (empty($errors)) {
        header('Content-Type: text/xml');
        echo $metadata;
    } else {
        throw new OneLogin_Saml2_Error(
            'Invalid SP metadata: '.implode(', ', $errors),
            OneLogin_Saml2_Error::METADATA_SP_INVALID
        );
    }
} catch (Exception $e) {
    echo $e->getMessage();
}