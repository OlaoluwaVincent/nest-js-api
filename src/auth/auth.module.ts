/* eslint-disable prettier/prettier */
import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';

// Moudle is the entry point
// Controllers are the routes i.e. Endpoints
// Services are the handlers of the logic when the user hits an endpoint.

@Module({
  imports: [JwtModule, PassportModule],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}
