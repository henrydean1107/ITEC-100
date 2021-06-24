<?php
// Include config file
include_once "config.php";

// Define variables and initialize with empty values
$username = $password = $confirm_password =  "";
$username_err = $password_err = $confirm_password_err =  "";
// Processing form data when form is submitted

if ($_SERVER["REQUEST_METHOD"] == "POST") {

  // Validate username
  if (empty(trim($_POST['uname']))) {
    $username_err = "Please enter your Username.";
  } else {
    // Prepare a select statement
    $sql = "SELECT username FROM users WHERE username = ?";

    if ($stmt = mysqli_prepare($link, $sql)) {
      // Bind variables to the prepared statement as parameters
      mysqli_stmt_bind_param($stmt, "s", $param_username);

      // Set parameters
      $param_username = trim($_POST['uname']);

      // Attempt to execute the prepared statement
      if (mysqli_stmt_execute($stmt)) {
        /* store result */
        mysqli_stmt_store_result($stmt);

        if (mysqli_stmt_num_rows($stmt) == 1) {
          $username = trim($_POST['uname']);
        } else {
          $username_err = "This Username does not exist";
        }
      } else {
        echo "Oops! Something went wrong. Please try again later.";
      }

      // Close statement
      mysqli_stmt_close($stmt);
    }
  }

  // Validate password
  $password = $_POST['psw'];
  $uppercase = preg_match('@[A-Z]@', $password);
  $lowercase = preg_match('@[a-z]@', $password);
  $number    = preg_match('@[0-9]@', $password);
  $specialChars = preg_match('@[^\w]@', $password);
  if (empty($password)) {
    $password_err = "Please enter a password.";
  } elseif (strlen(trim($_POST['psw'])) < 8) {
    $password_err = "Password must have atleast 8 characters.";
  } elseif (!$uppercase) {
    $password_err = "Password should contain atleast 1 upper case.";
  } elseif (!$lowercase) {
    $password_err = "Password should contain atleast 1 lower case.";
  } elseif (!$number) {
    $password_err = "Password should contain atleast 1 number.";
  } elseif (!$specialChars) {
    $password_err = "Password should contain atleast 1 special character.";
  } else {
    $password = trim($_POST['psw']);
  }

  // Validate confirm password
  if (empty(trim($_POST['psw-repeat']))) {
    $confirm_password_err = "Please confirm your password.";
  } else {
    $confirm_password = trim($_POST['psw-repeat']);
    if (empty($password_err) && ($password != $confirm_password)) {
      $confirm_password_err = "Password does not match.";
    }
  }


  // Check input errors before inserting in database
  if (empty($username_err) && empty($password_err) && empty($confirm_password_err)) {

    // Prepare an update statement
    $sql = "UPDATE users SET password = ? WHERE username = ?";
    
    if ($stmt = mysqli_prepare($link, $sql)) {
      // Bind variables to the prepared statement as parameters
      mysqli_stmt_bind_param($stmt, "ss", $param_password, $param_username);

      // Set parameters
      $param_password = password_hash($password, PASSWORD_DEFAULT); // Creates a password hash
      $param_username = $username;

      // Attempt to execute the prepared statement
      if (mysqli_stmt_execute($stmt)) {
        
        // prepare and bind
         $stmt1 = $link->prepare("INSERT INTO activity_log (activity, username) VALUES (?, ?)");
         $stmt1->bind_param("ss", $activity, $username);

        // // set parameters and execute
         $activity = "Reset a Password";
         $username = $username;
        
         $stmt1->execute();
         $stmt1->close();

        // Redirect to login page
        header("location: login.php");
      } else {
        echo "Something went wrong. Please try again later.";
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
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Reset Password | ITEC 100</title>
</head>

<body>

  <form method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
    <div class="container">
      <label id="header-text">Reset Password</label>
      <label id="sub-title">Reset your password.</label>
      <div class="form-group <?php echo (!empty($username_err)) ? 'has-error' : ''; ?>">
        <label for="uname" id="reset_labels">Username</label>
        <input type="text" name="uname" id="reset_fields" class="form-control" value="<?php echo $username; ?>">
        <span class="help-block">
          <?php echo $username_err; ?>
        </span>
      </div>

      <div class="form-group <?php echo (!empty($password_err)) ? 'has-error' : ''; ?>">
        <label for="psw" id="reset_labels">New Password</label>
        <input type="password" name="psw" id="reset_fields" class="form-control" value="<?php echo $password; ?>">
        <span class="help-block"><?php echo $password_err; ?></span>
      </div>

      <div class="form-group <?php echo (!empty($confirm_password_err)) ? 'has-error' : ''; ?>">
        <label for="psw-repeat" id="reset_labels">Repeat Password</b></label>
        <input type="password" name="psw-repeat" id="reset_fields" class="form-control" value="<?php echo $confirm_password; ?>">
        <span class="help-block"><?php echo $confirm_password_err; ?>

        </span>
      </div>
      <button type="submit" name="submit" class="registerbtn">Reset Password</button>
      <p class="signin-btn">Already have an account? <a href="login.php">Sign in</a>.</p>
    </div>
  </form>

</body>
  <style>
    body {
      background-color: #343434;
      font-family: "roboto";
      margin-top: 70px;
    }

    .container {
      background-color: #F7F7F7;
      width: 400px;
      margin: auto;
      margin-top: 1%;
      padding: 15px;
      border-radius: 15px;
      z-index: 100;
      background-color: #555555;
      overflow: hidden;
      transition: width 0.3s ease;
      cursor: pointer;
      box-shadow: 4px 7px 10px rgba(0, 0, 0, 0.4);
    }


    .registerbtn {
      text-align: center;
      font-size: 15px;
      width: 175px;
      color: white;
      background: #3498db;
      border: none;
      border-radius: 5px;
      text-shadow: 1px 1px 0px #2d7baf;
      box-shadow: 0px 1px 0px #2d7baf;

      padding: 10px;
      margin-top: 13px;
      margin-left: 31%;
      margin-right: 31%;
      }

    .registerbtn:hover {
      opacity: 1;
    }

    .signin-btn{
      font-size: 12px;
      color: white;
      font-family: "roboto";
      font-weight: 200;
      text-shadow: 1px 1px #181818;
      margin-top: 30px;
      margin-left: auto;
      margin-right: auto;

      text-align: center;
    }

    .signin-btn a{
      color: white;
    }

    .signin {
      background-color: #f1f1f1;
      text-align: center;
    }

    #header-text{
      font-size: 20px;
      text-align: center;
      color: white;
      margin-left: 30%;
      margin-right: 30%;
      padding-top: 20px;
      font-family: "roboto";
      font-weight: 100;
      display: block;
    }

    #sub-title{
      font-size: 12px;
      text-align: center;   
      color: white;
      margin-top: 25px;
      margin-bottom: 25px;
      font-family: "roboto";
      font-weight: 100;
      text-align: left;
      display: block;
    }

    #reset_labels {
      font-size: 12px;  
      color: white;
      font-family: "roboto";
      font-weight: 200;
      text-shadow: 1px 1px #181818;
      margin-bottom: 5px;
      margin-left: 25px;
      margin-right: auto;
      display: block;
    } 

    #reset_fields {
      font-size: 16px;
      text-align: left;
      
      height: 30px;
      width: 330px;

      border: 1px solid #646464;
      border-radius: 5px;

      padding-top: 2px;
      padding-bottom: 2px;
      padding-left: 5px;
      padding-right: 5px;
      
      margin-top: 5px;
      margin-left: 30px;      
      display: block;
    }

    .form-group{
      height: 90px;
      width: 400px;

    }

    .help-block{
      height: 30px;
      width: 270px;
      font-family: "roboto";
      font-weight: 100;
      color: #FE4B4B;
      font-size: 12px;
      margin-top: 5px;
      margin-bottom: 20px;
      margin-left: 40px;
      margin-right: 40px;
    }
  </style>
</html>