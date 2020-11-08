<?php
header("X-Frame-Options: DENY");
header("Content-Security-Policy: frame-ancestors none");

$allowed_levels = array(9, 8, 7, 0);
require_once('sys.includes.php');

$page_title = __('You Logged Out', 'cftp_admin');

$is_logged_in_ = check_for_session();
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

    <?php echo generate_branding_layout(); ?>

    <div class="white-box">
        <div class="white-box-interior">
            <h1>Thanks for using 3M Partner Portal. You are now logged off</h1>
            <hr />
            <div class="jumbotron">
                <h4>Here are some important links:</h4>
                <div class="row">
                    <div class="col-xs12 col-sm-12 col-lg-6">
                        <a href="http://3m.com.au">Visit 3M.COM.AU</a>
                    </div>
                    <div class="col-xs12 col-sm-12 col-lg-6">
                        <a href="<?php echo SAML2_IDP_SSO_URL; ?>">Login to 3M Partner Portal Again</a>
                    </div>
                </div>
                <div style="text-align: center; color:grey">
                &copy;<?php echo date('Y');?> 3M Company. All rights reserved.
                </div>
            </div>
        </div>
    </div>
    <?php
    include('footer.php');
    ?>