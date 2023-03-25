import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { AuthenticationModule } from './authentication/authentication.module';
import { PrismaModule } from 'prisma/prisma.module';
import { UsersModule } from './users/users.module';

@Module({
  imports: [AuthModule, AuthenticationModule, PrismaModule, UsersModule],
})
export class AppModule {}
