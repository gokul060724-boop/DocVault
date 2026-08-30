const loginForm = document.getElementById("loginForm");
const createAccount = document.getElementById("createAccount");
const forgotPassword = document.getElementById("forgotPassword");


// Login button
loginForm.addEventListener("submit", function (event) {
    event.preventDefault();

    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    if (!email || !password) {
        alert("Please enter Gmail and Password.");
        return;
    }

    alert("Login system will be connected to the server soon.");
});


// Create New Account
createAccount.addEventListener("click", function () {
    window.location.href = "/register.html";
});


// Forgot Password
forgotPassword.addEventListener("click", function (event) {
    event.preventDefault();

    window.location.href = "/forgot-password.html";
});