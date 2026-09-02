<?php
include("connection.php");
session_start();

$error_flag = "";
$user_email_error = "";
$user_pass_error = "";

$user_email = "";

if (isset($_POST['login_submit'])) {

    $user_email = trim($_POST['user_email'] ?? "");
    $user_password = $_POST['user_password'] ?? "";


    /* EMAIL */
    if (empty($user_email)) {

        $error_flag = "yes";
        $user_email_error = "Please enter your email";

    } elseif (!filter_var($user_email, FILTER_VALIDATE_EMAIL)) {

        $error_flag = "yes";
        $user_email_error = "Please enter a valid email";
    }


    /* PASSWORD */
    if (empty($user_password)) {

        $error_flag = "yes";
        $user_pass_error = "Please enter your password";
    }


    /* LOGIN */
    if (empty($error_flag)) {

        $sql = "SELECT * FROM registration
                WHERE email = ?
                ORDER BY id
                LIMIT 1";

        $stmt = mysqli_prepare($connection, $sql);

        mysqli_stmt_bind_param(
            $stmt,
            "s",
            $user_email
        );

        mysqli_stmt_execute($stmt);

        $data = mysqli_stmt_get_result($stmt);

        if ($data->num_rows > 0) {

            $row = mysqli_fetch_assoc($data);

            if (password_verify($user_password, $row['password'])) {

                session_regenerate_id(true);

                $_SESSION["user_name"] = $row["name"];
                $_SESSION["user_id"] = $row["id"];

                header("Location: profile.php");
                exit;

            } else {

                $user_pass_error = "Email or password is incorrect";
            }

        } else {

            $user_email_error = "This email is not registered";
        }

        mysqli_stmt_close($stmt);
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Login</title>

    <link rel="stylesheet" href="style.css">

</head>

<body>

<div class="auth-container">

    <div class="auth-card">

        <div class="auth-header">

            <h1>Welcome Back</h1>

            <p>Login to your account</p>

        </div>


        <form method="post">

            <!-- EMAIL -->
            <div class="form-group">

                <label for="email">Email Address</label>

                <input
                    type="email"
                    name="user_email"
                    id="email"
                    placeholder="Enter your email"
                    value="<?php echo htmlspecialchars($user_email); ?>"
                >

                <?php if (!empty($user_email_error)) { ?>

                    <p class="error">
                        <?php echo htmlspecialchars($user_email_error); ?>
                    </p>

                <?php } ?>

            </div>


            <!-- PASSWORD -->
            <div class="form-group">

                <label for="pass">Password</label>

                <input
                    type="password"
                    name="user_password"
                    id="pass"
                    placeholder="Enter your password"
                >

                <?php if (!empty($user_pass_error)) { ?>

                    <p class="error">
                        <?php echo htmlspecialchars($user_pass_error); ?>
                    </p>

                <?php } ?>

            </div>


            <!-- BUTTON -->
            <button
                type="submit"
                name="login_submit"
                class="auth-btn"
            >
                Login
            </button>

        </form>


        <div class="auth-footer">

            <p>
                Don't have an account?
                <a href="index.php">Create Account</a>
            </p>

        </div>

    </div>

</div>

</body>
</html>
