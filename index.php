<?php
include("connection.php");
session_start();

$error_flag = "";
$user_name_error = "";
$user_email_error = "";
$user_pass_error = "";
$user_cpass_error = "";

$user_name = "";
$user_email = "";

if (isset($_POST['registration_submit'])) {

    $user_name = trim($_POST['user_name'] ?? "");
    $user_email = trim($_POST['user_email'] ?? "");
    $user_password = $_POST['user_password'] ?? "";
    $confirm_password = $_POST['confirm_password'] ?? "";

    /* NAME VALIDATION */
    if (empty($user_name)) {
        $error_flag = "yes";
        $user_name_error = "Please enter your username";
    }

    /* EMAIL VALIDATION */
    if (empty($user_email)) {

        $error_flag = "yes";
        $user_email_error = "Please enter your email";

    } elseif (!filter_var($user_email, FILTER_VALIDATE_EMAIL)) {

        $error_flag = "yes";
        $user_email_error = "Please enter a valid email";

    } else {

        $check_email = "SELECT email FROM registration WHERE email = ? LIMIT 1";
        $stmt = mysqli_prepare($connection, $check_email);

        mysqli_stmt_bind_param($stmt, "s", $user_email);
        mysqli_stmt_execute($stmt);

        $check_data = mysqli_stmt_get_result($stmt);

        if ($check_data->num_rows > 0) {
            $error_flag = "yes";
            $user_email_error = "This email is already registered";
        }

        mysqli_stmt_close($stmt);
    }

    /* PASSWORD VALIDATION */
    if (empty($user_password)) {

        $error_flag = "yes";
        $user_pass_error = "Please enter your password";

    } elseif (strlen($user_password) < 8) {

        $error_flag = "yes";
        $user_pass_error = "Password must be at least 8 characters";

    } elseif (!preg_match('/[A-Z]/', $user_password)) {

        $error_flag = "yes";
        $user_pass_error = "Password must contain one capital letter";

    } elseif (!preg_match('/[0-9]/', $user_password)) {

        $error_flag = "yes";
        $user_pass_error = "Password must contain one number";

    } elseif (!preg_match('/[!@#$%^&*]/', $user_password)) {

        $error_flag = "yes";
        $user_pass_error = "Password must contain one special character";
    }

    /* CONFIRM PASSWORD */
    if (empty($confirm_password)) {

        $error_flag = "yes";
        $user_cpass_error = "Please enter your confirm password";

    } elseif ($user_password !== $confirm_password) {

        $error_flag = "yes";
        $user_cpass_error = "Passwords do not match";
    }

    /* INSERT USER */
    if (empty($error_flag)) {

        $hash_password = password_hash(
            $user_password,
            PASSWORD_DEFAULT
        );

        $sql = "INSERT INTO registration (name, email, password)
                VALUES (?, ?, ?)";

        $stmt = mysqli_prepare($connection, $sql);

        mysqli_stmt_bind_param(
            $stmt,
            "sss",
            $user_name,
            $user_email,
            $hash_password
        );

        $result = mysqli_stmt_execute($stmt);

        if ($result) {

            header("Location: login.php");
            exit;

        } else {

            $user_email_error = "Something went wrong. Please try again.";
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

    <title>Registration</title>

    <link rel="stylesheet" href="style.css">

</head>

<body>

<div class="auth-container">

    <div class="auth-card">

        <div class="auth-header">
            <h1>Create Account</h1>
            <p>Register your account to get started</p>
        </div>

        <form method="post">

            <!-- NAME -->
            <div class="form-group">

                <label for="name">Full Name</label>

                <input
                    type="text"
                    name="user_name"
                    id="name"
                    placeholder="Enter your name"
                    value="<?php echo htmlspecialchars($user_name); ?>"
                >

                <?php if (!empty($user_name_error)) { ?>
                    <p class="error">
                        <?php echo htmlspecialchars($user_name_error); ?>
                    </p>
                <?php } ?>

            </div>


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

                <label for="password">Password</label>

                <input
                    type="password"
                    name="user_password"
                    id="password"
                    placeholder="Create a password"
                >

                <?php if (!empty($user_pass_error)) { ?>
                    <p class="error">
                        <?php echo htmlspecialchars($user_pass_error); ?>
                    </p>
                <?php } ?>

            </div>


            <!-- CONFIRM PASSWORD -->
            <div class="form-group">

                <label for="cpass">Confirm Password</label>

                <input
                    type="password"
                    name="confirm_password"
                    id="cpass"
                    placeholder="Confirm your password"
                >

                <?php if (!empty($user_cpass_error)) { ?>
                    <p class="error">
                        <?php echo htmlspecialchars($user_cpass_error); ?>
                    </p>
                <?php } ?>

            </div>


            <!-- SHOW PASSWORD -->
            <div class="show-password">

                <input
                    type="checkbox"
                    id="checkbox"
                    onclick="showPassword()"
                >

                <label for="checkbox">Show Password</label>

            </div>


            <!-- BUTTON -->
            <button
                type="submit"
                name="registration_submit"
                class="auth-btn"
            >
                Create Account
            </button>

        </form>


        <div class="auth-footer">

            <p>
                Already have an account?
                <a href="login.php">Login Here</a>
            </p>

        </div>

    </div>

</div>


<script>

function showPassword() {

    const password = document.getElementById("password");
    const confirmPassword = document.getElementById("cpass");

    if (password.type === "password") {

        password.type = "text";
        confirmPassword.type = "text";

    } else {

        password.type = "password";
        confirmPassword.type = "password";
    }
}

</script>

</body>
</html>
