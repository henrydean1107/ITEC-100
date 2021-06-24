<?php
include_once 'config.php';

session_start();
//Logout log
$username = $_SESSION['username'];
if ($_SERVER["REQUEST_METHOD"] == "POST"){
  
  mysqli_query($link,"INSERT INTO activity_log (activity,username) VALUES('Logged out','$username')");
    

    
  header('location: login.php');
}

?>
<!DOCTYPE html>
<html>
<head>
  <link rel="stylesheet" type="text/css" href="css/home.css">
  <title>Welcome | ITEC 100</title>
</head>
<body>
  <form method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
  <div class="middle">
    <label id="title-auth">Welcome, <?php echo $username ?></label>
    <label id="tip-auth">Login Successful</label>
    <p id="tip-b">Created by: Henry Dean Cornico</p>
    <p id="tip-b">Year and Section: BSIT-3C</p>
    <p id="tip-b">Course Name: ITEC 100</p>
   <button type="submit" name="submit" class="logout-home">Log out</button>
  </div>
</form>
</body>
</html>
