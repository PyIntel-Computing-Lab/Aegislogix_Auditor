function togglePassword() {

    let x = document.getElementById("password");

    let y = document.getElementById("eye1");

    if (x.type === "password") {

        x.type = "text";

        y.classList.replace("fa-eye", "fa-eye-slash");

    } else {

        x.type = "password";

        y.classList.replace("fa-eye-slash", "fa-eye");

    }

}

function toggleConfirmPassword() {

    let x = document.getElementById("confirmPassword");

    let y = document.getElementById("eye2");

    if (x.type === "password") {

        x.type = "text";

        y.classList.replace("fa-eye", "fa-eye-slash");

    } else {

        x.type = "password";

        y.classList.replace("fa-eye-slash", "fa-eye");

    }

}