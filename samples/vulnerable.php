<?php
// Deliberately vulnerable sample for testing the harness (do NOT deploy).

session_start();
if (!isset($_SESSION['user'])) {
    die('auth required');
}

// 1) Local File Inclusion — user input concatenated into require_once (phpIPAM-style)
$page = $_GET['page'];
require_once("pages/" . $page . ".php");

// 2) Command injection — parameter passed straight into exec (myVesta-style)
$ftp_user = $_POST['username'];
exec("/usr/local/bin/v-delete-ftp-user " . $ftp_user, $out, $rc);

// 3) SQL injection — string-built query
$id = $_GET['id'];
$db->query("SELECT * FROM subnets WHERE id = " . $id);

// 4) Hardcoded secret
$api_key = "sk_live_51H8xQ2eZvKmT9aBcDeFgHiJkLmNoPqRs";

echo "done";
