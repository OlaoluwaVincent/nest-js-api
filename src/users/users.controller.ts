/* eslint-disable prettier/prettier */
import { Controller, Get, Param, UseGuards, Res, Req } from '@nestjs/common';
import { UsersService } from './users.service';
import { JWTAuthGuard } from 'src/auth/jwt.guard';

@Controller('users')
export class UsersController {
	constructor(private readonly usersService: UsersService) {}

	@UseGuards(JWTAuthGuard)
	@Get(':id')
	getUser(@Param() params: { id: string }, @Res() res, @Req() req) {
		return this.usersService.getAUser(params.id, res, req);
	}

	@Get()
	getUsers() {
		return this.usersService.getAllUsers();
	}
}
