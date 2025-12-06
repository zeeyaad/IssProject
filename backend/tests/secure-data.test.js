const request = require('supertest');
const assert = require('assert');

// Import the Express app without starting the server
const app = require('../index.js');

async function run() {
  const username = `user${Date.now()}`;
  const password = 'strongPass123';
  const email = `${username}@example.com`;

  // Register
  let res = await request(app)
    .post('/register')
    .send({ username, password, email })
    .expect(201);
  assert.ok(res.body.userId, 'userId should be returned');

  // Login
  res = await request(app)
    .post('/login')
    .send({ username, password })
    .expect(200);
  const token = res.body.token;
  assert.ok(token, 'token should be returned');

  // Save secure data
  const sensitive = 'hello world';
  await request(app)
    .post('/api/secure-data')
    .set('Authorization', `Bearer ${token}`)
    .send({ sensitive_data: sensitive })
    .expect(200);

  // Retrieve secure data
  res = await request(app)
    .get('/api/secure-data')
    .set('Authorization', `Bearer ${token}`)
    .expect(200);
  assert.strictEqual(res.body.sensitive_data, sensitive, 'decrypted data should match original');

  // Invalid input: missing sensitive_data
  await request(app)
    .post('/api/secure-data')
    .set('Authorization', `Bearer ${token}`)
    .send({})
    .expect(400);

  // Invalid input: non-string
  await request(app)
    .post('/api/secure-data')
    .set('Authorization', `Bearer ${token}`)
    .send({ sensitive_data: { a: 1 } })
    .expect(400);

  // Unauthorized: no token
  await request(app)
    .post('/api/secure-data')
    .send({ sensitive_data: 'x' })
    .expect(401);

  // High load: concurrent reads should succeed
  const tasks = Array.from({ length: 20 }).map(() =>
    request(app)
      .get('/api/secure-data')
      .set('Authorization', `Bearer ${token}`)
      .expect(200)
  );
  await Promise.all(tasks);

  console.log('All tests passed');
}

run().catch((err) => {
  console.error('Test run failed:', err);
  process.exit(1);
});
