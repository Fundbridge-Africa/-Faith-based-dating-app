import { IsBoolean, IsEmail, IsNotEmpty, IsOptional, MinLength } from 'class-validator';

export class LoginUserDto {
  @IsEmail()
  email!: string;

  @IsNotEmpty()
  @MinLength(8)
  password!: string;

  @IsOptional()
  @IsBoolean()
  rememberMe?: boolean; 
}