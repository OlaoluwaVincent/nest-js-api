/* eslint-disable prettier/prettier */
import {
	Injectable,
	BadRequestException,
	ForbiddenException,
} from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { AuthDto } from './dto/authdto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { jwtSecret } from 'src/utils/constants';
import { Response } from 'express';

@Injectable({})
export class AuthService {
	constructor(private prisma: PrismaService, private jwt: JwtService) {}
	// logic for signUp route
	async signUp(dto: AuthDto, res: Response) {
		const { email, password } = dto;

		const foundUser = await this.prisma.user.findUnique({
			where: { email },
		});
		// Already existing user
		if (foundUser) {
			throw new BadRequestException(`${email} already exists!`);
		}
		// Hash password
		const hashedPassword = await this.hashPassword(password);

		// Create a new User
		const newUser = await this.prisma.user.create({
			data: {
				email,
				hashedPassword,
			},
		});
		if (newUser) {
			const data = { requestSuccessful: true, user: newUser };
			const token = await this.signToken({
				id: newUser.id,
				email: newUser.email,
			});
			if (!token) {
				throw new ForbiddenException('Unauthorized');
			}

			res.cookie('token', token);
			return res.status(201).json(data);
		}
	}

	// logic for login route
	async login(dto: AuthDto, res: Response) {
		const { email, password } = dto;

		const user = await this.prisma.user.findUnique({ where: { email } });
		if (!user) {
			throw new BadRequestException('Wrong Email or Password');
		}
		const isMatch = await this.comparePasswords({
			password,
			hash: user.hashedPassword,
		});
		if (!isMatch) {
			throw new BadRequestException('Wrong Email or Password');
		}

		// sign Jwt
		const token = await this.signToken({ id: user.id, email: user.email });

		if (!token) {
			throw new ForbiddenException('Unauthorized');
		}

		res.cookie('token', token);

		return res.status(200).json({ requestSuccessful: true, user });
	}

	signOut(res: Response) {
		res.clearCookie('token');
		res.status(200).json({ message: 'Logged out successfully' });
	}

	// Helper functions
	async hashPassword(password: string) {
		const salt = 10;
		return await bcrypt.hash(password, salt);
	}

	async comparePasswords(args: { password: string; hash: string }) {
		return await bcrypt.compare(args.password, args.hash);
	}

	async signToken(args: { id: string; email: string }) {
		const payload = args;

		return this.jwt.signAsync(payload, { secret: jwtSecret });
	}
}
