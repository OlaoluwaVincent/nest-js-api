/* eslint-disable prettier/prettier */
import { IsNotEmpty, IsString, IsEmail, Length } from 'class-validator';

export class AuthDto {
  @IsEmail()
  public email: string;

  @IsNotEmpty()
  @IsString()
  @Length(6, 20, { message: 'Passwords has to be between 6 and 20 characters' })
  public password: string;
}
