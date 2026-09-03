import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { prisma } from '../db/prisma';
import { config } from '../config/env';
import {
  RegisterRequest,
  LoginRequest,
  AuthResponse,
  UserProfile,
  UserRole
} from '@phishnetra/shared';

export class AuthService {
  public async register(payload: RegisterRequest): Promise<AuthResponse> {
    const existing = await prisma.user.findUnique({
      where: { email: payload.email.toLowerCase() }
    });

    if (existing) {
      const error: any = new Error('An account with this email address already exists');
      error.statusCode = 409;
      throw error;
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(payload.password, salt);

    const user = await prisma.user.create({
      data: {
        name: payload.name.trim(),
        email: payload.email.toLowerCase().trim(),
        passwordHash,
        role: 'USER'
      }
    });

    const token = this.generateToken(user.id, user.role);

    return {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role as UserRole,
        createdAt: user.createdAt.toISOString()
      },
      token
    };
  }

  public async login(payload: LoginRequest): Promise<AuthResponse> {
    const user = await prisma.user.findUnique({
      where: { email: payload.email.toLowerCase().trim() }
    });

    if (!user) {
      const error: any = new Error('Invalid email or password');
      error.statusCode = 401;
      throw error;
    }

    const isValid = await bcrypt.compare(payload.password, user.passwordHash);
    if (!isValid) {
      const error: any = new Error('Invalid email or password');
      error.statusCode = 401;
      throw error;
    }

    const token = this.generateToken(user.id, user.role);

    return {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role as UserRole,
        createdAt: user.createdAt.toISOString()
      },
      token
    };
  }

  public async getProfile(userId: string): Promise<UserProfile> {
    const user = await prisma.user.findUnique({
      where: { id: userId }
    });

    if (!user) {
      const error: any = new Error('User profile not found');
      error.statusCode = 404;
      throw error;
    }

    return {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role as UserRole,
      createdAt: user.createdAt.toISOString()
    };
  }

  private generateToken(userId: string, role: string): string {
    return jwt.sign(
      { userId, role },
      config.jwt.secret,
      { expiresIn: config.jwt.expiresIn as any }
    );
  }
}

export const authService = new AuthService();
