<?php
date_default_timezone_set("Asia/Manila");

// Initialize the session
session_start();

/*// Check if the user is already logged in, if yes then redirect him to welcome page
if ((isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true) && (isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true)) {
    // Check if the user is already logged in and authenticated, if yes then redirect him to home page
    header('location: welcome.php');
    exit;
} elseif (isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true) {
    // Check if the user is already logged in and not authenticated, if yes then redirect him to enter authentication code page
    header('location: authentication.php');
    exit;
}*/

// Include config file

include_once "config.php";
// Define variables and initialize with empty values
$username = $password = "";
$username_err = $password_err = "";

// Processing form data when form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {

  // Check if username is empty
  if (empty(trim($_POST['uname']))) {
    $username_err = "Please enter username.";
  } else {
    $username = trim($_POST['uname']);
  }

  // Check if password is empty
  if (empty(trim($_POST['psw']))) {
    $password_err = "Please enter your password.";
  } else {
    $password = trim($_POST['psw']);
  }

  // Validate credentials
  if (empty($username_err) && empty($password_err)) {
    // Prepare a select statement
    $sql = "SELECT id, username, password FROM users WHERE username = ?";

    if ($stmt = mysqli_prepare($link, $sql)) {
      // Bind variables to the prepared statement as parameters
      mysqli_stmt_bind_param($stmt, "s", $param_username);

      // Set parameters
      $param_username = $username;

      // Attempt to execute the prepared statement
      if (mysqli_stmt_execute($stmt)) {
        // Store result
        mysqli_stmt_store_result($stmt);

        // Check if username exists, if yes then verify password
        if (mysqli_stmt_num_rows($stmt) == 1) {
          // Bind result variables
          mysqli_stmt_bind_result($stmt, $id, $username, $hashed_password);
          if (mysqli_stmt_fetch($stmt)) {
            
            if (password_verify($password, $hashed_password)) {
              // Store data in session variables
              $_SESSION["loggedin"] = true;
              $_SESSION["id"] = $id;
              $_SESSION["username"] = $username;
              $_SESSION['authenticated'] = false;
              $user_id = $_SESSION['id'];
              $code = rand(100000, 999999);
              $dateTime = new DateTime();
              $dateTimeFormat = 'Y-m-d H:i:s';
              $time = $dateTime->format($dateTimeFormat);
              $dateTime->add(new DateInterval('PT5M'));
              $expiration = $dateTime->format($dateTimeFormat);

              /*$sql = "INSERT INTO date_auth (user_id, code, time_added, expiration) VALUES ('$user_id', '$code', '$time', '$expiration')";*/

              $stmt1 = $link->prepare("INSERT INTO date_auth (user_id, code, time_added, expiration) VALUES (?, ?, ?, ?)");
              $stmt1->bind_param("ssss", $param_id, $param_code,$param_time, $param_expiration);

              // set parameters and execute
              $param_id = $user_id;
              $param_code = $code;
              $param_time = $time;
              $param_expiration = $expiration;
              
              $stmt1->execute();

               $stmt1 = $link->prepare("INSERT INTO activity_log (activity, username) VALUES (?, ?)");
               $stmt1->bind_param("ss", $activity, $username);

              // // set parameters and execute
               $activity = "Attempted Log in";
               $username = $username;
              
               $stmt1->execute();
               $stmt1->close();

              // Redirect user to authentication page
              header("location: authentication.php");
            } else {
              // Display an error message if password is not valid
              $password_err = "Incorrect Password, please try again.";
            }
          }
        } else {
          // Display an error message if username doesn't exist
          $username_err = "Username does not exist.";
        }
      } else {
        echo "Oops! Something went wrong. Please try again later.";
      }

      // Close statement
      mysqli_stmt_close($stmt);
    }
  }

  // Close connection
  mysqli_close($link);
}
?>
<!DOCTYPE html>
<html>

<head>
  <link rel="stylesheet" type="text/css" href="css/home.css">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title> Login | ITEC 100</title>
</head>

<body>
  <h1 align="center" class="header_text"> FAST FOOD SYSTEM <h1>
    <div class="form-login">
        <label class="form_name" >Employee Login </label><br>
        <label class="my_name">Please login to continue </label>

      <form method="POST" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
        <div class="container">
          <div class="fields">
          <label id="login_labels" for="username">Username:</label>
          <br>
          <input class="login_fields" type="text" name="uname" value="" required>
          <label class="help-block"><?php echo $username_err; ?></label>
          <label id="login_labels" for="password">Password:</label>
          <input class="login_fields" type="password" name="psw" value="" required>
          <label class="help-block"><?php echo $password_err; ?></label>
          <input type="submit" id="btn_login" name="btn_login" value="Login">
          </div>            
          <label id="register_labels">
            Don't have one? <a href="register.php">Sign up here.</a>
          </label>
          <label id="register_labels">
            <a href="forgotpass.php" id="forgotpass">Forgot Password?</a>
          </label>
        </div>
      </form>
</body>

</html>