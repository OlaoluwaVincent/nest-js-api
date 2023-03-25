/* eslint-disable prettier/prettier */
import { Body, Controller, Get, Post, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/authdto';

// route for this is /auth

@Controller('auth')
export class AuthController {
	// this gets the logic for inidividual routes
	constructor(private authService: AuthService) {}

	// endpoint is /auth/signup
	@Post('signup')
	signUp(@Body() dto: AuthDto, @Res() res) {
		return this.authService.signUp(dto, res);
	}

	// endpoint is /auth/login
	@Post('login')
	login(@Body() dto: AuthDto, @Res() res) {
		return this.authService.login(dto, res);
	}

	@Get('/signout')
	signOut(@Res() res) {
		return this.authService.signOut(res);
	}
}
