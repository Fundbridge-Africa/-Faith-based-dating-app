import { ArrayNotEmpty, IsArray, IsBoolean, IsOptional, IsString, MaxLength } from 'class-validator';

export class CreateConversationDto {
  @IsArray() @ArrayNotEmpty()
  @IsString({ each: true })
  participantIds!: string[]; // exclude current user; we’ll add them in service

  @IsOptional() @IsBoolean()
  isGroup?: boolean;

  @IsOptional() @IsString() @MaxLength(120)
  title?: string;
}
