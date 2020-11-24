<?php

/**
 * Class that handles the log out and file download actions.
 *
 * @package		ProjectSend
 */
$allowed_levels = array(9, 8, 7, 0);
require_once('sys.includes.php');

$_SESSION['last_call']	= time();

$header = 'header.php';
/**
 * #securityFixNeeded
 * 1. Fix issue associated with insecure form submission
 * should check the submitting file for wrong VERB GET['username'], GET['password'] and fix [FIXED] ✔️
 * ----------------------------------------------------------------------------------------
 * 2. Fix session fixation issue by refreshing the session ID  [FIXED] ✔️
 */

/**
 * Check SAML SSO
 * If GET['do'] = saml2_sso_flow, send browser to the signon service
 */
if (isset($_GET['do']) && $_GET['do'] == 'saml2_sso_flow') {
	if (SAML2_SSO_ENABLED == 1) {
		if (isset($_SESSION['loggedin'])) {

			header('Location: home.php');
		} else {
			header('Location: ' . SAML2_IDP_SSO_URL);
			exit;
		}
	}
}

/**
 * Check SAML SLO
 * if logout and SSO enabled, redirect to SAML logout endpoint.
 */
if (isset($_GET['do']) && $_GET['do'] == 'logout') {
	if (SAML2_SSO_ENABLED == 1) {
		header("Cache-control: private");
		$loggedin_ = $_SESSION['loggedin'];

		unset($_SESSION['loggedin']);
		unset($_SESSION['access']);
		unset($_SESSION['userlevel']);
		unset($_SESSION['lang']);
		unset($_SESSION['last_call']);
		//session_destroy();
		$saml_session_index = '138410309451';
		if(isset($_SESSION['IdPSessionIndex'])){
			$saml_session_index = $_SESSION['IdPSessionIndex'];
		}

		/** If there is a cookie, unset it */
		setcookie("loggedin", "", time() - COOKIE_EXP_TIME);
		setcookie("password", "", time() - COOKIE_EXP_TIME);
		setcookie("access", "", time() - COOKIE_EXP_TIME);
		setcookie("userlevel", "", time() - COOKIE_EXP_TIME);
		/**Set sso_session index for outgoing session */

		/** Record the action log */
		if (defined('CURRENT_USER_ID') && !empty(CURRENT_USER_ID)) {
			$new_log_action = new LogActions();
			$log_action_args = array(
				'action'	=> 31,
				'owner_id'	=> CURRENT_USER_ID,
				'affected_account_name' => $loggedin_
			);
			$new_record_action = $new_log_action->log_action_save($log_action_args);
		}
		/**redirect to Thank you page after logout url*/
		if(isset($_GET['timeout'])){
			$_SESSION['session_timeout'] = 1;
		}
		if(!empty(SAML2_IDP_SLO_URL)){
			$location_ = SAML2_IDP_SLO_URL. '?TARGET='. BASE_URI . 'sso_logout_fin.php?x_sso_session=' . $saml_session_index;
			header("Location: $location_");
			exit;
		}
		
		$location_ = BASE_URI . 'sso_logout_fin.php?x_sso_session=' . $saml_session_index;
		header("Location: $location_");
		exit;
	}
}

if (!empty($_GET['do']) && $_GET['do'] == 'login') {
	if (SAML2_SSO_ENABLED == 1) {
		header('Location: process.php?do=saml2_sso_flow');
		exit;
	}
} else {
	require_once($header);
}

class process
{
	function __construct()
	{
		global $dbh;
		$this->dbh = $dbh;
		$this->process();
	}

	function process()
	{
		switch ($_GET['do']) {
			case 'login':
				$this->login();
				break;
			case 'logout':
				$this->logout();
				break;
			case 'download':
				$this->download_file();
				break;
			case 'zip_download':
				$this->download_zip();
				break;
			default:
				header('Location: ' . BASE_URI);
				break;
		}
	}

	private function login()
	{
		if ($_SERVER['REQUEST_METHOD'] == 'POST') {
			/** If request method is POST, go ahead and login */
			global $hasher;
			$this->sysuser_password		= $_POST['password'];
			$this->selected_form_lang	= (!empty($_POST['language'])) ? $_POST['language'] : SITE_LANG;

			/** Look up the system users table to see if the entered username exists */
			$this->statement = $this->dbh->prepare("SELECT * FROM " . TABLE_USERS . " WHERE user= :username OR email= :email");
			$this->statement->execute(
				array(
					':username'	=> $_POST['username'],
					':email'	=> $_POST['username'],
				)
			);
			$this->count_user = $this->statement->rowCount();
			if ($this->count_user > 0) {
				/**
				 * Add session refresh logic
				 * Fixated PHPSESSIONID is a security vulnerability
				 */
				try {
					session_regenerate_id(false);
				} catch (Exception $exx) {
					//throw $th;
				}

				/** If the username was found on the users table */
				$this->statement->setFetchMode(PDO::FETCH_ASSOC);
				while ($this->row = $this->statement->fetch()) {
					$this->sysuser_username	= html_output($this->row['user']);
					$this->db_pass			= $this->row['password'];
					$this->user_level		= $this->row["level"];
					$this->active_status	= $this->row['active'];
					$this->logged_id		= $this->row['id'];
					$this->logged_mail = $this->row['email'];
					$this->global_name		= html_output($this->row['name']);
				}

				$this->max_attempts = intval(MAX_LOGIN_ATTEMPTS) > 0 ? intval(MAX_LOGIN_ATTEMPTS) : 6;
				$this->attempts_interval = intval(MAX_LOGIN_INTERVAL) > 0 ? intval(MAX_LOGIN_INTERVAL) : 900;
				$this->attempts_lockout_duration = intval(MAX_LOGIN_LOCKOUT_DURATION) > 0 ? intval(MAX_LOGIN_LOCKOUT_DURATION) : 1800;

				$this->tryAfter = false;
				try {
					$this->statement = $this->dbh->prepare('SELECT `time_when`, `is_lock_point` FROM ' . TABLE_LOGIN_ATTEMPTS . ' WHERE `uid` = :uid ORDER BY `time_when` DESC LIMIT 2');

					$this->statement->bindParam(':uid', $this->logged_id, PDO::PARAM_INT);

					$this->statement->execute();
					$count = $this->statement->rowCount();

					if ($count > 0) {
						$this->statement->setFetchMode(PDO::FETCH_ASSOC);
						$this->row = $this->statement->fetch();
						$this->lastFailed = intval($this->row['time_when']);
						$this->hasLock = $this->row['is_lock_point'] > 0;
						$this->tryAfter = $this->attempts_lockout_duration - (time() - intval(($this->lastFailed)));
					} //if any attempt found

					if ($this->hasLock && $this->tryAfter > 0) {

						$this->errorstate = 'max_login_attempts_reached';
					} //has lock
					else {
						if ($this->tryAfter !== false && $this->tryAfter <= 0) {
							//reset the database to allow login asap
							$this->statement = $this->dbh->prepare('DELETE FROM ' . TABLE_LOGIN_ATTEMPTS . ' WHERE `uid` = :uid');
							$this->statement->bindParam(':uid', $this->logged_id, PDO::PARAM_INT);
							$this->statement->execute();
						}

						$this->statement = $this->dbh->prepare('SELECT COUNT(`uid`) AS `attempts` FROM ' . TABLE_LOGIN_ATTEMPTS . ' WHERE `time_when` > :t_minus AND `time_when` AND `uid` = :uid');
						$time_now = time();
						$t_minus = $time_now - $this->attempts_interval;

						$this->statement->bindParam(':t_minus', $t_minus, PDO::PARAM_INT);
						$this->statement->bindParam(':uid', $this->logged_id, PDO::PARAM_INT);
						$this->statement->execute();

						$this->statement->setFetchMode(PDO::FETCH_ASSOC);
						$this->row = $this->statement->fetch();
						$this->attemptsCounted = $this->row['attempts'];

						if (intval($this->attemptsCounted) >= $this->max_attempts) {

							$this->statement = $this->dbh->prepare('SELECT `time_when` FROM ' . TABLE_LOGIN_ATTEMPTS . ' WHERE `uid` = :uid ORDER BY `time_when` DESC LIMIT 2');

							$this->statement->bindParam(':uid', $this->logged_id, PDO::PARAM_INT);

							$this->statement->execute();
							$this->statement->setFetchMode(PDO::FETCH_ASSOC);
							$this->row = $this->statement->fetch();
							$this->lastFailed = intval($this->row['time_when']);
							$this->tryAfter = $this->attempts_lockout_duration - (time() - intval(($this->lastFailed)));
							if ($this->tryAfter <= 0) {
								$this->tryAfter = 60; //avoid illegal division or negative time
							}
							//acquire lock

							$this->statement = $this->dbh->prepare('UPDATE ' . TABLE_LOGIN_ATTEMPTS . ' SET `is_lock_point` = 1 WHERE `uid` = :uid AND `time_when` = :lastfailed');

							$this->statement->bindParam(':uid', $this->logged_id, PDO::PARAM_INT);
							$this->statement->bindParam(':lastfailed', $this->lastFailed, PDO::PARAM_INT);
							$this->statement->execute();
							$this->errorstate = 'max_login_attempts_reached';
						} else {
							//max attempts not reached

							$this->check_password = $hasher->CheckPassword($this->sysuser_password, $this->db_pass);
							if ($this->check_password) {
								/**remove login attempts */
								$this->statement = $this->dbh->prepare('DELETE FROM ' . TABLE_LOGIN_ATTEMPTS . ' WHERE uid = :uid');
								$this->statement->bindParam(':uid', $this->logged_id, PDO::PARAM_INT);
								$this->statement->execute();

								//check if password is expired
								$expires_after = CLIENT_PASSWORD_EXPIRE_AFTER;
								if ($this->user_level != '0') {
									$expires_after = SYS_PASSWORD_EXPIRE_AFTER;
								}
								$rowCount = 20;
								$this->passwordExpired = false;

								$no_expire_check = intval($expires_after) < 1;
								if (!$no_expire_check) {
									$this->statement = $this->dbh->prepare('SELECT creation_time FROM ' . TABLE_PASSWORD_HISTORY . ' WHERE uid = :uid ORDER BY creation_time DESC LIMIT 2');

									$this->statement->bindParam(':uid', $this->logged_id, PDO::PARAM_INT);
									$this->statement->execute();
									$rowCount = $this->statement->rowCount();

									if ($rowCount > 0) {
										$this->statement->setFetchMode(PDO::FETCH_ASSOC);
										$row = $this->statement->fetch();
										$creation_time = $row['creation_time'];
										$time_ = time();
										$expires_after = intval($expires_after);
										if (($expires_after + $creation_time) < $time_) {
											$this->passwordExpired = true;
										}
									}
								}

								if (($this->passwordExpired || $rowCount < 1) && !$no_expire_check) {
									//do stuff
									$this->errorstate = 'password_expired';
								} else {
									//if ($db_pass == $sysuser_password) {






									if ($this->active_status != '0') {
										/** Set SESSION values */
										$_SESSION['loggedin']	= html_output($this->sysuser_username);
										$_SESSION['userlevel']	= $this->user_level;
										$_SESSION['lang']		= $this->selected_form_lang;

										/**
										 * Language cookie
										 * TODO: Implement.
										 * Must decide how to refresh language in the form when the user
										 * changes the language <select> field.
										 * By using a cookie and not refreshing here, the user is
										 * stuck in a language and must use it to recover password or
										 * create account, since the lang cookie is only at login now.
										 */
										//setcookie('projectsend_language', $selected_form_lang, time() + (86400 * 30), '/');

										if ($this->user_level != '0') {
											$this->access_string	= 'admin';
											$_SESSION['access']		= $this->access_string;
										} else {
											$this->access_string	= $this->sysuser_username;
											$_SESSION['access']		= html_output($this->sysuser_username);
										}

										/** Record the action log */
										$this->new_log_action = new LogActions();
										$this->log_action_args = array(
											'action' => 1,
											'owner_id' => $this->logged_id,
											'owner_user' => $this->global_name,
											'affected_account_name' => $this->global_name
										);
										$this->new_record_action = $this->new_log_action->log_action_save($this->log_action_args);

										$results = array(
											'status'	=> 'success',
											'message'	=> __('Login success. Redirecting...', 'cftp_admin'),
										);
										if ($this->user_level == '0') {
											$results['location']	= BASE_URI . "my_files/";
										} else {
											$results['location']	= BASE_URI . "home.php";
										}

										/** Using an external form */
										if (!empty($_GET['external']) && $_GET['external'] == '1' && empty($_GET['ajax'])) {
											/** Success */
											if ($results['status'] == 'success') {
												header('Location: ' . $results['location']);
												exit;
											}
										}

										echo json_encode($results);
										exit;
									} else {
										$this->errorstate = 'inactive_client';
									}
								}
								//end password check ok
							} else {
								//$errorstate = 'wrong_password';
								try {
									//code...
									$this->statement = $this->dbh->prepare('INSERT INTO ' . TABLE_LOGIN_ATTEMPTS . ' (uid,time_when) VALUES (:uid,:time_when)');

									$time_nows = time();
									$this->statement->bindParam(':uid', $this->logged_id, PDO::PARAM_INT);
									$this->statement->bindParam(':time_when', $time_nows, PDO::PARAM_INT);

									$this->statement->execute();
								} catch (PDOException $th) {
									//throw $th;
									exit('db_error');
								}
								$this->errorstate = 'invalid_credentials';
							}
						} //max attempts not reached
					} //check if we need to lock



				} catch (PDOException $th) {
					//throw $th;

					exit('db_error');
				}
			} else {
				//$errorstate = 'wrong_username';
				$this->errorstate = 'invalid_credentials';
			}
		} else {
			$this->errorstate = 'invalid_request_method';
		}


		if (isset($this->errorstate)) {

			switch ($this->errorstate) {
				case 'invalid_request_method':
					$this->login_err_message = __("The request method used in this request is not valid.", 'cftp_admin');
					break;
				case 'invalid_credentials':
					$this->login_err_message = __("The supplied credentials are not valid.", 'cftp_admin');
					break;
				case 'wrong_username':
					$this->login_err_message = __("The supplied username doesn't exist.", 'cftp_admin');
					break;
				case 'wrong_password':
					$this->login_err_message = __("The supplied password is incorrect.", 'cftp_admin');
					break;
				case 'inactive_client':
					$this->login_err_message = __("This account is not active.", 'cftp_admin');
					if (CLIENTS_AUTO_APPROVE == 0) {
						$this->login_err_message .= ' ' . __("If you just registered, please wait until a system administrator approves your account.", 'cftp_admin');
					}
					break;
				case 'no_self_registration':
					$this->login_err_message = __('Client self registration is not allowed. If you need an account, please contact a system administrator.', 'cftp_admin');
					break;
				case 'no_account':
					$this->login_err_message = __('Sign-in with Google cannot be used to create new accounts at this time.', 'cftp_admin');
					break;
				case 'access_denied':
					$this->login_err_message = __('You must approve the requested permissions to sign in with Google.', 'cftp_admin');
					break;
				case 'max_login_attempts_reached':
					$unit_ = 'minutes';
					$after_ = round($this->tryAfter / 60, 2);
					if ($after_ >= 60) {
						$after_ = round($after_ / 60, 2);
						$unit_ = 'hours';
					}
					$this->login_err_message = __('You have tried to login more times than allowed within ' . round($this->attempts_interval / 60) . ' minutes. Please try again after ' . $after_ . ' ' . $unit_, 'cftp_admin');
					break;
				case 'password_expired':
					$this->login_err_message = __('This password has exceeded the maximum lifetime allowed for your account type and must therefore be changed before you can login <br/><hr/> <a style="text-align:center;display:block" href="./reset-password.php?must_change_0=1&mail=' . $this->logged_mail . '">Change password now</a>');
					break;
			}
		}

		$results = array(
			'status'	=> 'error',
			'message'	=> $this->login_err_message,
		);

		/** Using an external form */
		if (!empty($_GET['external']) && $_GET['external'] == '1' && empty($_GET['ajax'])) {
			/** Error */
			if ($results['status'] == 'error') {
				header('Location: ' . BASE_URI . '?error=1');
			}
			exit;
		}
		echo json_encode($results);
		exit;
	}

	private function logout()
	{
		header("Cache-control: private");
		unset($_SESSION['loggedin']);
		unset($_SESSION['access']);
		unset($_SESSION['userlevel']);
		unset($_SESSION['lang']);
		unset($_SESSION['last_call']);
		session_destroy();

		/** If there is a cookie, unset it */
		setcookie("loggedin", "", time() - COOKIE_EXP_TIME);
		setcookie("password", "", time() - COOKIE_EXP_TIME);
		setcookie("access", "", time() - COOKIE_EXP_TIME);
		setcookie("userlevel", "", time() - COOKIE_EXP_TIME);

		/*
		$language_cookie = 'projectsend_language';
		setcookie ($language_cookie, "", 1);
		setcookie ($language_cookie, false);
		unset($_COOKIE[$language_cookie]);
		*/

		/** Record the action log */
		$new_log_action = new LogActions();
		$log_action_args = array(
			'action'	=> 31,
			'owner_id'	=> CURRENT_USER_ID,
			'affected_account_name' => $this->global_name
		);
		$new_record_action = $new_log_action->log_action_save($log_action_args);

		$redirect_to = 'index.php';
		if (isset($_GET['timeout'])) {
			$redirect_to .= '?error=timeout';
		}

		header("Location: " . $redirect_to);
		die();
	}

	private function download_file()
	{
		$this->check_level = array(9, 8, 7, 0);
		if (isset($_GET['id'])) {
			/** Do a permissions check for logged in user */
			if (isset($this->check_level) && in_session_or_cookies($this->check_level)) {

				/**
				 * Get the file name
				 */
				$this->statement = $this->dbh->prepare("SELECT url, original_url, expires, expiry_date FROM " . TABLE_FILES . " WHERE id=:id");
				$this->statement->bindParam(':id', $_GET['id'], PDO::PARAM_INT);
				$this->statement->execute();
				$this->statement->setFetchMode(PDO::FETCH_ASSOC);
				$this->row				= $this->statement->fetch();
				$this->filename_find	= $this->row['url'];
				$this->filename_save	= (!empty($this->row['original_url'])) ? $this->row['original_url'] : $this->row['url'];
				$this->expires			= $this->row['expires'];
				$this->expiry_date		= $this->row['expiry_date'];

				$this->expired			= false;
				if ($this->expires == '1' && time() > strtotime($this->expiry_date)) {
					$this->expired		= true;
				}

				$this->can_download = false;

				if (CURRENT_USER_LEVEL == 0) {
					if ($this->expires == '0' || $this->expired == false) {
						/**
						 * Does the client have permission to download the file?
						 * First, get the list of different groups the client belongs to.
						 */
						$this->get_groups		= new MembersActions();
						$this->get_arguments	= array(
							'client_id'	=> CURRENT_USER_ID,
							'return'	=> 'list',
						);
						$this->found_groups	= $this->get_groups->client_get_groups($this->get_arguments);

						/**
						 * Get assignments
						 */
						$this->params = array(
							':client_id'	=> CURRENT_USER_ID,
						);
						$this->fq = "SELECT * FROM " . TABLE_FILES_RELATIONS . " WHERE (client_id=:client_id";
						// Add found groups, if any
						if (!empty($this->found_groups)) {
							$this->fq .= ' OR FIND_IN_SET(group_id, :groups)';
							$this->params[':groups'] = $this->found_groups;
						}
						// Continue assembling the query
						$this->fq .= ') AND file_id=:file_id AND hidden = "0"';
						$this->params[':file_id'] = (int)$_GET['id'];

						$this->files = $this->dbh->prepare($this->fq);
						$this->files->execute($this->params);

						if ($this->files->rowCount() > 0) {
							$this->can_download = true;
						}

						/** Continue */
						if ($this->can_download == true) {
							/**
							 * The owner ID is generated here to prevent false results
							 * from a modified GET url.
							 */
							$log_action = 8;
							$log_action_owner_id = CURRENT_USER_ID;
						}
					}
				} else {
					$this->can_download = true;
					$log_action = 7;
					$global_user = get_current_user_username();
					$log_action_owner_id = CURRENT_USER_ID;
				}

				if ($this->can_download == true) {
					/**
					 * Add +1 to the download count
					 */
					$this->statement = $this->dbh->prepare("INSERT INTO " . TABLE_DOWNLOADS . " (user_id , file_id, remote_ip, remote_host) VALUES (:user_id, :file_id, :remote_ip, :remote_host)");
					$this->statement->bindValue(':user_id', CURRENT_USER_ID, PDO::PARAM_INT);
					$this->statement->bindParam(':file_id', $_GET['id'], PDO::PARAM_INT);
					$this->statement->bindParam(':remote_ip', $_SERVER['REMOTE_ADDR']);
					$this->statement->bindParam(':remote_host', $_SERVER['REMOTE_HOST']);
					$this->statement->execute();

					/** Record the action log */
					$new_log_action = new LogActions();
					$log_action_args = array(
						'action'				=> $log_action,
						'owner_id'				=> $log_action_owner_id,
						'affected_file'			=> (int)$_GET['id'],
						'affected_file_name'	=> $this->filename_find,
						'affected_account'		=> CURRENT_USER_ID,
						'affected_account_name'	=> CURRENT_USER_USERNAME,
						'get_user_real_name'	=> true,
						'get_file_real_name'	=> true
					);
					$new_record_action = $new_log_action->log_action_save($log_action_args);
					$this->real_file = UPLOADED_FILES_FOLDER . $this->filename_find;
					$this->save_file = UPLOADED_FILES_FOLDER . $this->filename_save;
					if (file_exists($this->real_file)) {
						session_write_close();
						while (ob_get_level()) ob_end_clean();
						header('Content-Type: application/octet-stream');
						header('Content-Disposition: attachment; filename=' . basename($this->save_file));
						header('Expires: 0');
						header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
						header('Pragma: public');
						header('Cache-Control: private', false);
						header('Content-Length: ' . get_real_size($this->real_file));
						header('Connection: close');
						//readfile($this->real_file);

						$context = stream_context_create();
						$file = fopen($this->real_file, 'rb', false, $context);
						while (!feof($file)) {
							//usleep(1000000); //Reduce download speed
							echo stream_get_contents($file, 2014);
						}

						fclose($file);
						exit;
					} else {
						header("HTTP/1.1 404 Not Found");
?>
						<div class="col-xs-12">
							<div class="file_404">
								<h2><?php _e('File not found', 'cftp_admin'); ?></h2>
							</div>
						</div>
<?php
						exit;
					}
				}
			}
		}
	}

	private function download_zip()
	{
		$this->check_level = array(9, 8, 7, 0);
		if (isset($_GET['files'])) {
			// do a permissions check for logged in user
			if (isset($this->check_level) && in_session_or_cookies($this->check_level)) {
				$file_list = array();
				$requested_files = $_GET['files'];
				foreach ($requested_files as $file_id) {
					$file_list[] = $file_id;
				}
				ob_clean();
				flush();
				echo implode(',', $file_list);
			}
		}
	}
}

$process = new process;
