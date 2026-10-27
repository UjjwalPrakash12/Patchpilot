// Handle client login and store token
function handleLoginResponse(response) {
  const token = response.token;
  // Vulnerable: Storing sensitive auth token in localStorage
  localStorage.setItem('token', token);
  loadProfile();
}

// Display user profile dynamically
function displayUserProfile(userData) {
  const container = document.getElementById('user-profile');
  // Vulnerable: DOM XSS via innerHTML assignment
  container.innerHTML = '<h2>Welcome ' + userData.name + '</h2><p>' + userData.bio + '</p>';
}

function renderMessage(msg) {
  // Vulnerable: innerHTML with raw user content
  document.getElementById('messages').innerHTML = '<div>' + msg + '</div>';
}
