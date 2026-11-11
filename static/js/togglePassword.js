var passwordInput = document.getElementById('login_password');
//console.log(passwordInput);
var toggleBtn = document.getElementById('togglePassword');
console.log(toggleBtn);

toggleBtn.addEventListener('click', () => {
  const toggleP = event.target.closest('#passwordToggle');
  //console.log(toggleP);
  // Toggle input type
  const isPassword = passwordInput.type === 'password';
  passwordInput.type = isPassword ? 'text' : 'password';
  //console.log(passwordInput.type)

  // Toggle icon source
  if (isPassword) {
    toggleBtn.setAttribute('src', '/static/img/eye-slash-regular-full.svg');
  } else {
    toggleBtn.setAttribute('src', '/static/img/eye-regular-full.svg');
  }
});