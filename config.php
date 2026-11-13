<?php
// config.php - CLEAN & WORKING

// config.php - mysqli version
$host = 'localhost';
$dbname = 'gmsspank_cashier';
$username = 'gmsspank_gmss';
$password = 'gmsspankshin2024';

$conn = new mysqli($host, $username, $password, $dbname);

if ($conn->connect_error) {
    error_log("Connection failed: " . $conn->connect_error);
    die("Connection failed: " . $conn->connect_error); // only during debug
}
?>