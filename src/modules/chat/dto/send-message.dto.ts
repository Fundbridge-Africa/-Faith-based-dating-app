import { IsOptional, IsString, MaxLength } from 'class-validator';

export class SendMessageDto {
  @IsOptional() @IsString() @MaxLength(5000)
  body?: string;
}
