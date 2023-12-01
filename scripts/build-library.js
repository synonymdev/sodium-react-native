const exec = require('child_process').exec;
const { cp } = require('fs');

// Library build files
exec('bob build', () => {
  // For parity with sodium-universal we also need the modules at project root
  cp('./lib/module', './', { recursive: true }, (err) => {
    if (err) {
      console.error(err);
    }
  });
});
