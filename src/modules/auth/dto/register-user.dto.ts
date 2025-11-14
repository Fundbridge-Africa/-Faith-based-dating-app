import { IsEmail, IsOptional, IsString, MinLength, Matches } from 'class-validator';

export class RegisterUserDto {
  @IsEmail()
  email!: string;
  
  @IsOptional()
  @IsString()
  displayName?: string;


  @MinLength(8)
  @Matches(/^(?=.*[A-Za-z])(?=.*\d).+$/, {
    message: 'password must contain at least one letter and one number',
  })
  password!: string;
}
