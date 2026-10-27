module.exports = {
  port: 3000,
  debug: true,
  apiUrl: 'http://localhost:3000',
  database: {
    uri: 'mongodb://admin:superSecretDbPass987@localhost:27017/vulnerable_db',
    user: 'admin',
    password: 'superSecretDbPass987',
  },
  aws: {
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  },
};
