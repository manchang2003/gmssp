<?php
// Database Configuration
$host = "localhost";
$user = "gmsspank_gmss";
$pass = "gmsspankshin2024";
$db_name = "gmsspank_school_db";

// Create Connection
$conn = new mysqli($host, $user, $pass, $db_name);

// Check Connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>
