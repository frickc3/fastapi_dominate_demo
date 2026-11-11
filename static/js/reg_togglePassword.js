const passwordInput = document.getElementById('reg_password');
const passwordInput_again = document.getElementById('reg_password_again');
//console.log(passwordInput);

const toggleBtn = document.getElementById('reg_togglePassword');
const toggleBtn_again = document.getElementById('reg_togglePassword_again');
//console.log(toggleBtn);

//toggleBtn.addEventListener('click', () => {
document.addEventListener('click', () => {
  const toggleP = event.target.closest('#reg_togglePassword');
  const togglePA = event.target.closest('#reg_togglePassword_again')
  //console.log(toggleP);
  if (toggleP) {
    // Toggle input type
    const isPassword = passwordInput.type === 'password';
    passwordInput.type = isPassword ? 'text' : 'password';
    //console.log(passwordInput.type)

    // Toggle icon source
    if (isPassword) {
      toggleBtn.setAttribute('src', '/static/img/eye-slash-regular-full.svg');
    } else {
      toggleBtn.setAttribute('src', '/static/img/eye-regular-full.svg');
    };
  };
  if (togglePA) {
    // Toggle input type
    const isPassword = passwordInput_again.type === 'password';
    passwordInput_again.type = isPassword ? 'text' : 'password';
    //console.log(passwordInput.type)

    // Toggle icon source
    if (isPassword) {
      toggleBtn_again.setAttribute('src', '/static/img/eye-slash-regular-full.svg');
    } else {
      toggleBtn_again.setAttribute('src', '/static/img/eye-regular-full.svg');
    };
  }

});