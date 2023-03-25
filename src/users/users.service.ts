/* eslint-disable prettier/prettier */
import {
	Injectable,
	NotFoundException,
	ForbiddenException,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { PrismaService } from 'prisma/prisma.service';

@Injectable()
export class UsersService {
	constructor(private prisma: PrismaService) {}

	async getAUser(id: string, res: Response, req: Request) {
		const user = await this.prisma.user.findUnique({
			where: { id },
			select: { id: true, email: true },
		});
		if (!user) {
			throw new NotFoundException('User does not exist');
		}
		const decodedUser = req.user as { id: string; email: string };
		if (user.id !== decodedUser.id) {
			throw new ForbiddenException('Unauthorized');
		}

		return res.status(200).json({ requestSuccessful: true, user });
	}

	async getAllUsers() {
		return await this.prisma.user.findMany({
			select: { id: true, email: true },
		});
	}
}
