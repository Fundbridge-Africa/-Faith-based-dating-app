import { Body, Controller, Get, Param, Post, Query, UseGuards } from '@nestjs/common';
import { ChatService } from './chat.service';
import { JwtAuthGuard } from '../auth/jwt.guard';
import { CreateConversationDto } from './dto/create-conversation.dto';
import { SendMessageDto } from './dto/send-message.dto';
import { Delete, Patch } from '@nestjs/common';

@Controller('api/v1/chat')
@UseGuards(JwtAuthGuard)
export class ChatController {
  constructor(private svc: ChatService) {}

  // Helper to get user id from request (JwtAuthGuard sets req.user)
  private uid(req: any) { return req.user.sub as string; }

  @Post('conversations')
  async createConversation(@Body() dto: CreateConversationDto, req: any) {
    return this.svc.createConversation(this.uid(req), dto);
  }

  @Get('conversations')
  async listConversations(req: any) {
    return this.svc.listConversations(this.uid(req));
  }

  @Get('conversations/:id/messages')
  async listMessages(@Param('id') id: string, @Query('cursor') cursor: string | undefined, @Query('limit') limit = '20', req: any) {
    return this.svc.listMessages(id, this.uid(req), cursor, Math.min(+limit || 20, 50));
  }

  @Post('conversations/:id/messages')
  async send(@Param('id') id: string, @Body() dto: SendMessageDto, req: any) {
    return this.svc.sendMessage(id, this.uid(req), dto);
  }

  @Post('messages/:id/read')
  async markRead(@Param('id') id: string, req: any) {
    return this.svc.markRead(id, this.uid(req));
  }
  @Patch('messages/:id')
  async edit(@Param('id') id: string, @Body() dto: { body: string }, req: any) {
    return this.svc.editMessage(id, this.uid(req), dto.body);
  }

  @Delete('messages/:id')
  async remove(@Param('id') id: string, req: any) {
    return this.svc.deleteMessage(id, this.uid(req));
  }
}
