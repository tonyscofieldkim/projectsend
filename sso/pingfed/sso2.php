<?php

/**
 * Asertion consumption Endponit for SSO
 */
define('NO_AUTO_REGISTER', 1);

require_once('../../sys.includes.php');
require_once('sp_settings/settings.php');
require_once('./include.view.php');

if (!defined('SAML2_SSO_ENABLED') || SAML2_SSO_ENABLED != '1') {
    echo createView('SSO Not Enabled', 'SSO Login Method is disabled at the moment.');
    exit();
}

try {
    //ob_start();
    //code...
    //session_start();
    $_SESSION['REGEN_XID'] = 0;
    session_regenerate_id(false);
    unset($_SESSION['REGEN_XID']);
    unset($_SESSION['IdPSessionIndex']);
} catch (\Throwable $th) {
    //throw $th;
}
$allowed_levels = array(9, 8, 7, 0);
$defaultPassword = 'P.a.ss*W.or.d01#';
$auth = null;
$requestID = null;
try {
    //code...
    $auth = new OneLogin_Saml2_Auth($advancedSettings);
    if (isset($_SESSION) && isset($_SESSION['AuthNRequestID'])) {
        $requestID = $_SESSION['AuthNRequestID'];
    } else {
        $requestID = null;
    }

    $auth->processResponse($requestID);
} catch (\Throwable $th) {
    //throw $th;
    echo createView('SSO Login not completed', 'Errors occurred within the request process. <hr/> <strong>' . $th->getMessage() . '</strong>', BASE_URI);
    exit;
}

$errors = $auth->getErrors();

if (!empty($errors)) {
    if ($errors[0] == 'invalid_response') {
        echo createView('SSO Login not completed', 'Errors occurred within request', 'Error: The response sent is invalid. Reason: ' . $auth->getLastErrorReason(), BASE_URI);
        exit;
    }
    echo createView('SSO Login not completed', 'Errors occurred within the request process.', BASE_URI);
    exit;
    //echo '<p>', implode(', ', $errors), '</p>'; //not good to print these errors to user
}

if (!$auth->isAuthenticated()) {
    echo createView('Not Authenticated', 'You are not authenticated.', BASE_URI);
    exit();
}


$_SESSION['IdPSessionIndex'] = $auth->getSessionIndex();
$attributes = $auth->getAttributes();
$nameId = $auth->getNameId();
if (is_array($nameId)) {
    $nameId = $nameId[0];
}
//make it lowercase
$nameId = strtolower($nameId);

$nameIdFormat = $auth->getNameIdFormat();
$nameIdQualifier = $auth->getNameIdNameQualifier();
$nameIdServiceNameQualifier = $auth->getNameIdSPNameQualifier();
$sessionIndex = $auth->getSessionIndex();
unset($_SESSION['AuthNRequestID']);

//check for attributes
$attributesNames = array(
    SAML2_ATTR_EMAIL,
    SAML2_ATTR_FIRSTNAME,
    SAML2_ATTR_LASTNAME
);
$attributeEmail = false;
$attributeRole = 0; //assume level 0 (client user)
$attributeGivenNames = false;
foreach ($attributes as $attributeName => $attributeValue) {
    if ($attributeName == $attributesNames[0]) {

        $attributeEmail = $attributeValue;
        if (is_array($attributeEmail)) {
            $attributeEmail = $attributeEmail[0];
        }
    }
    if ($attributeName == $attributesNames[1]) {
        $attributeGivenNames = $attributeValue;
        if (is_array($attributeGivenNames)) {
            $attributeGivenNames = $attributeGivenNames[0];
        }
    }
    if ($attributeName == $attributesNames[2] && !empty($attributeGivenNames)) {
        if (is_array($attributeValue)) {
            $attributeGivenNames .= ' ' . $attributeValue[0];
        } else {
            $attributeGivenNames .= ' ' . $attributeValue;
        }
    }
}

if (empty($attributeEmail) || empty($attributeGivenNames)) {
    //incorrect assertions.
    echo createView("Authentication Assertion Error", "<p>You were not authenticated properly. Some Identity Assertion Attributes are missing.</p>", BASE_URI);
    exit;
}


//check if this user exists or not.
$statement = $dbh->prepare("SELECT * FROM " . TABLE_USERS . " WHERE user= :username OR email= :email");
if (array_key_exists(intval($attributeRole), $allowed_levels)) {
    $attributeRole = intval($attributeRole);
} else {
    $attributeRole = 0; //defaults to client user.
}

$statement->execute(
    array(
        ':username'    => $nameId,
        ':email'    => $attributeEmail
    )
);
$count_user = $statement->rowCount();
if ($count_user > 0) {
    //check if nameId has matched
    $userInfo = $statement->fetch(PDO::FETCH_ASSOC);
    if ($userInfo['user'] == $nameId) {
        //this user is already created by vsmr, login the user
        if ($userInfo['active'] != 0) {
            $access_string = 'admin';
            /** Set SESSION values */
            $_SESSION['loggedin']  = html_output($userInfo['user']);
            $_SESSION['userlevel']  = $userInfo['level'];
            $_SESSION['lang'] = SITE_LANG;

            if ($userInfo['level'] != 0) {
                $access_string    = 'admin';
                $_SESSION['access']  = $access_string;
            } else {
                $access_string    = html_output($userInfo['user']);
                $_SESSION['access']  = html_output($userInfo['user']);
            }

            /** Record the action log */
            $new_log_action = new LogActions();
            $log_action_args = array(
                'action' => 1,
                'owner_id' => $userInfo['id'],
                'owner_user' => $userInfo['name'],
                'affected_account_name' => $userInfo['name']
            );
            $new_record_action = $new_log_action->log_action_save($log_action_args);
        } else {
            echo createView('Your account is deactivated', 'Your account is not active. Contact system admin.');
            exit;
        }
    } else {
        if ($userInfo['email'] == $attributeEmail) {
            //this user is created but not via vsmr. should edit his user nameId and Name and log them in
            $statement = $dbh->prepare("UPDATE " . TABLE_USERS . " SET user = :user, name = :name WHERE email = :email");
            $statement->execute(array(
                ':user' => $nameId,
                ':name' => $attributeGivenNames,
                ':email' => $attributeEmail
            ));
            if ($statement->rowCount() < 1) {
                echo createView("Account not connected", "<p>Your account could not be connected. Error code DBERR_QUERYFAIL</p>", BASE_URI);
                exit;
            }

            if ($userInfo['active'] != 0) {
                $access_string = 'admin';
                /** Set SESSION values */
                $_SESSION['loggedin']  = html_output($nameId);
                $_SESSION['userlevel']  = $userInfo['level'];
                $_SESSION['lang'] = SITE_LANG;

                if ($userInfo['level'] != 0) {
                    $access_string    = 'admin';
                    $_SESSION['access']  = $access_string;
                } else {
                    $access_string    = html_output($nameId);
                    $_SESSION['access']  = html_output($nameId);
                }

                /** Record the action log */
                $new_log_action = new LogActions();
                $log_action_args = array(
                    'action' => 1,
                    'owner_id' => $userInfo['id'],
                    'owner_user' => $userInfo['name'],
                    'affected_account_name' => $userInfo['name']
                );
                $new_record_action = $new_log_action->log_action_save($log_action_args);
            } else {
                echo createView('Your account is deactivated', 'Your account is not active. Please contact system admin.', BASE_URI);
                exit;
            }
        }
    }
} else {
    if(defined('NO_AUTO_REGISTER') && NO_AUTO_REGISTER == 1){
        //auto registration via IDP Response not allowed. exit here
        echo createView("Account not found.", "<p>Account not found. <br/><b>The email: $attributeEmail</b> did not match any account at this server. Please contact your administrator for details.</p>", BASE_URI);
        exit;
    }
    //this is a new user and is registered via vsmr. register them and log in
    //find if we have this email already
    $statement = $dbh->prepare("SELECT COUNT(*) AS counted FROM " . TABLE_USERS . " WHERE email = :email");
    $statement->execute(array(
        ':email' => $attributeEmail
    ));
    $count_user_x = $statement->rowCount();
    if ($count_user_x > 0) {
        $count_user_xy = $statement->fetch(PDO::FETCH_ASSOC);
        if ($count_user_xy['counted'] > 0) {
            //user exists.
            echo createView("Account setup error", "<p>Could create account. This email is already taken. ($attributeEmail)</p>", BASE_URI);
            exit;
        }
    } else {
        echo createView("SSO Login Error", "<p>Could not log in. Internal error code is: DBERR_QUERYFAIL</p>", BASE_URI);
        exit;
    }
    //proceed with registration
    $new_user = new UserActions();
    $new_arguments = array(
        'id' => '',
        'username' => $nameId,
        'password' => $defaultPassword,
        //'password_repeat' => $_POST['add_user_form_pass2'],
        'name' => $attributeGivenNames,
        'email' => $attributeEmail,
        'role' => $attributeRole,
        'active' => 1,
        'max_file_size'    => 500,
        'notify_account' => 0,
        'type' => 'new_user'
    );

    /** Validate the information from the posted form. */
    $new_validate = $new_user->validate_user($new_arguments);

    /** Create the user if validation is correct. */
    if ($new_validate == 1) {
        $new_response = $new_user->create_user($new_arguments);
    } else {
        echo createView("Account not created", "Could not create your account. One or more parameters are invalid: " . $valid_me->error_msg, BASE_URI);
        exit;
    }
    $access_string = 'admin';
    /** Set SESSION values */
    $_SESSION['loggedin']  = html_output($nameId);
    $_SESSION['userlevel']  = $attributeRole;
    $_SESSION['lang'] = SITE_LANG;

    if ($attributeRole != 0) {
        $access_string    = 'admin';
        $_SESSION['access']  = $access_string;
    } else {
        $access_string    = html_output($nameId);
        $_SESSION['access']  = html_output($nameId);
    }
}

if (isset($_POST['RelayState']) && OneLogin_Saml2_Utils::getSelfURL() != $_POST['RelayState']) {
    $auth->redirectTo($_POST['RelayState']);
} else {
    $location_ = BASE_URI . 'home.php';
    header("Location: $location_");
}
