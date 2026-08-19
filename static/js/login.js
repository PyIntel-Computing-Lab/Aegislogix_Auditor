function togglePassword() {

    const password = document.getElementById("password");
    const eye = document.getElementById("eye");

    if (password.type === "password") {
        password.type = "text";

        // Change these two lines
        eye.classList.remove("fa-eye-slash");
        eye.classList.add("fa-eye");

    } else {
        password.type = "password";

        eye.classList.remove("fa-eye");
        eye.classList.add("fa-eye-slash");
    }

}