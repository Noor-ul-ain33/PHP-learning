<?php

session_start();

if (empty($_SESSION["user_name"])) {

    header("Location: login.php");
    exit;
}

$user_name = $_SESSION["user_name"];

?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Profile</title>

    <link rel="stylesheet" href="style.css">

</head>

<body>

<div class="profile-container">

    <div class="profile-card">

        <div class="profile-icon">
            👤
        </div>

        <h1>Welcome!</h1>

        <h2>
            <?php echo htmlspecialchars($user_name); ?>
        </h2>

        <p class="profile-text">
            You have successfully logged into your account.
        </p>

        <a href="logout.php" class="logout-btn">
            Logout
        </a>

    </div>

</div>

</body>
</html>
