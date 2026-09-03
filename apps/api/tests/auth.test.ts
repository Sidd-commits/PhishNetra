import request from 'supertest';
import { createApp } from '../src/app';
import { prisma } from '../src/db/prisma';

const app = createApp();

describe('Authentication API Suite', () => {
  const testUser = {
    name: 'Analyst Jane',
    email: `jane.analyst.${Date.now()}@phishnetra.dev`,
    password: 'SecurePassword123!'
  };

  let authToken: string = '';

  beforeAll(async () => {
    // Mock prisma user methods if PostgreSQL daemon is offline during CI/local test
    try {
      await prisma.$connect();
    } catch {
      // Setup mock in-memory store for prisma
      const users: any[] = [];
      jest.spyOn(prisma.user, 'findUnique').mockImplementation((({ where }: any) => {
        const found = users.find(u => u.email === where.email || u.id === where.id);
        return Promise.resolve(found || null);
      }) as any);

      jest.spyOn(prisma.user, 'create').mockImplementation((({ data }: any) => {
        const newUser = {
          id: `usr_${Date.now()}`,
          ...data,
          createdAt: new Date(),
          updatedAt: new Date()
        };
        users.push(newUser);
        return Promise.resolve(newUser);
      }) as any);
    }
  });

  afterAll(async () => {
    try {
      await prisma.$disconnect();
    } catch {
      // ignore
    }
  });

  describe('POST /api/auth/register', () => {
    it('should successfully register a new user and return token', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send(testUser);

      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty('token');
      expect(res.body).toHaveProperty('user');
      expect(res.body.user.email).toBe(testUser.email.toLowerCase());
      expect(res.body.user).not.toHaveProperty('passwordHash');

      authToken = res.body.token;
    });

    it('should reject registration with invalid email format', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          name: 'Jane',
          email: 'not-an-email',
          password: 'Password123'
        });

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'Validation Error');
    });

    it('should reject registration with password under 8 characters', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          name: 'Jane',
          email: 'valid@example.com',
          password: 'short'
        });

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'Validation Error');
    });
  });

  describe('POST /api/auth/login', () => {
    it('should successfully login with valid credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: testUser.email,
          password: testUser.password
        });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('token');
      expect(res.body.user.email).toBe(testUser.email.toLowerCase());
    });

    it('should reject login with wrong password', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: testUser.email,
          password: 'WrongPassword999'
        });

      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty('error', 'Error');
    });
  });

  describe('GET /api/auth/me (Protected Route)', () => {
    it('should block access without Bearer token', async () => {
      const res = await request(app).get('/api/auth/me');
      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty('error', 'Unauthorized');
    });

    it('should allow access with valid Bearer token', async () => {
      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('user');
      expect(res.body.user.email).toBe(testUser.email.toLowerCase());
    });
  });
});
