<?php
header("X-Frame-Options: DENY");
header("Content-Security-Policy: frame-ancestors none");

$allowed_levels = array(9, 8, 7, 0);
require_once('sys.includes.php');

$page_title = __('You Logged Out', 'cftp_admin');

$is_logged_in_ = check_for_session(false);
if ($is_logged_in_) {
    header('Location: home.php');
    exit;
}
if (!isset($_GET['x_sso_session']) || !isset($_SESSION['IdPSessionIndex']) || $_GET['x_sso_session'] != $_SESSION['IdPSessionIndex']) {
    //cannot show logout page if you did not just log out.
    exit;
}
include('header-unlogged.php');
?>
<div class="col-xs-12 col-sm-12 col-lg-6 col-lg-offset-3">

    
    <style>
        .white-box-interior h1 {
            color: black;
            text-align: center;
            font-size: 18px;
            line-height: 18px;
        }

        .white-box-interior h4 {
            line-height: 4em;
            text-align: center;
        }

        .white-box-interior a {
            text-decoration: underline;
            line-height: 3em;
            display: block;
            text-align: center;
            width: 100%;
        }
        .backend .branding_unlogged img{
            max-height: 100% !important;
            max-width: 100% !important;
            user-select: none;
        }
    </style>
    <?php echo generate_branding_layout(); ?>
    <div class="white-box">
        <div class="white-box-interior">
            <h1>Thank you for using the 3M Partner Portal. You are now logged off</h1>
            <hr />
            <div class="jumbotron">
                <h4>Here are some suggested next steps</h4>
                <div class="row">
                    <div class="col-xs12 col-sm-12 col-lg-12">
                        <a href="http://3m.com.au">Visit 3M.COM.AU</a>
                    </div>
                    <div class="col-xs12 col-sm-12 col-lg-12">
                        <a href="<?php echo SAML2_IDP_SSO_URL; ?>">Login to 3M Partner Portal Again</a>
                    </div>
                </div>
                <div style="text-align: center; color:grey;margin-top: 6em">
                    &copy;<?php echo date('Y'); ?>&nbsp;&nbsp; 3M Company. All rights reserved.
                </div>
            </div>
        </div>
    </div>
    <?php
    include('footer.php');
    ?>