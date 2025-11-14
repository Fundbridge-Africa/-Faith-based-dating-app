import {
  ConnectedSocket, MessageBody, OnGatewayConnection, OnGatewayDisconnect,
  SubscribeMessage, WebSocketGateway, WebSocketServer
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import * as cookie from 'cookie';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../core/database/prisma.service';
import { ChatService } from './chat.service';
import { ACCESS_COOKIE } from '../auth/cookie.util';
import { Inject } from '@nestjs/common';
import { REDIS_PUB } from '../../core/redis/redis.module';
import type Redis from 'ioredis';

type WsAuth = { userId: string };

@WebSocketGateway({ namespace: '/ws', transports: ['websocket'] })
export class ChatGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer() io!: Server;

  constructor(
    private readonly jwt: JwtService,
    private readonly prisma: PrismaService,
    private readonly chat: ChatService,
    @Inject(REDIS_PUB) private readonly redis: Redis,
  ) {}

  private parseUserId(client: Socket): string | null {
    const raw = client.handshake.headers.cookie || '';
    const cookies = cookie.parse(String(raw));
    const token = cookies[ACCESS_COOKIE];
    if (!token) return null;
    try {
      const payload: any = this.jwt.verify(token);
      return payload?.sub ?? null;
    } catch {
      return null;
    }
  }

  async handleConnection(client: Socket) {
    const userId = this.parseUserId(client);
    if (!userId) {
      client.disconnect(true);
      return;
    }
    (client.data as WsAuth).userId = userId;

    // presence: track socket
    await this.redis.sadd(`user:sockets:${userId}`, client.id);
    await this.redis.set(`online:${userId}`, '1', 'EX', 60); // heartbeat TTL
    client.join(`user:${userId}`);
  }

  async handleDisconnect(client: Socket) {
    const userId = (client.data as WsAuth).userId;
    if (!userId) return;
    await this.redis.srem(`user:sockets:${userId}`, client.id);
    const remaining = await this.redis.scard(`user:sockets:${userId}`);
    if (remaining === 0) {
      await this.redis.del(`online:${userId}`);
    }
  }

  // client -> server: join a conversation room after HTTP created/listed it
  @SubscribeMessage('join:convo')
  async joinConversation(@ConnectedSocket() client: Socket, @MessageBody() body: { conversationId: string }) {
    const userId = (client.data as WsAuth).userId;
    if (!userId) return;

    const member = await this.prisma.conversationMember.findFirst({
      where: { conversationId: body.conversationId, userId },
      select: { id: true },
    });
    if (!member) return;

    client.join(`convo:${body.conversationId}`);
    client.emit('joined:convo', { conversationId: body.conversationId });
  }

  // send message (idempotent with clientKey)
  @SubscribeMessage('msg:send')
  async sendMessage(
    @ConnectedSocket() client: Socket,
    @MessageBody() payload: { conversationId: string; body?: string; clientKey?: string; replyToId?: string },
  ) {
    const userId = (client.data as WsAuth).userId;
    if (!userId) return;

    const msg = await this.chat.sendMessage(payload.conversationId, userId, {
      body: payload.body,
      // future: attachments, replyToId
    });

    // broadcast to conversation room
    this.io.to(`convo:${payload.conversationId}`).emit('msg:new', msg);
    client.emit('msg:ack', { tempKey: payload.clientKey, id: msg.id });
  }

  // typing indicator
  @SubscribeMessage('typing:start')
  async typingStart(@ConnectedSocket() client: Socket, @MessageBody() body: { conversationId: string }) {
    const userId = (client.data as WsAuth).userId;
    if (!userId) return;
    await this.redis.set(`typing:${body.conversationId}:${userId}`, '1', 'EX', 7);
    this.io.to(`convo:${body.conversationId}`).emit('typing', { conversationId: body.conversationId, userId, state: 'start' });
  }

  @SubscribeMessage('typing:stop')
  async typingStop(@ConnectedSocket() client: Socket, @MessageBody() body: { conversationId: string }) {
    const userId = (client.data as WsAuth).userId;
    if (!userId) return;
    await this.redis.del(`typing:${body.conversationId}:${userId}`);
    this.io.to(`convo:${body.conversationId}`).emit('typing', { conversationId: body.conversationId, userId, state: 'stop' });
  }

  // read receipts
  @SubscribeMessage('read:mark')
  async readMark(@ConnectedSocket() client: Socket, @MessageBody() body: { messageId: string }) {
    const userId = (client.data as WsAuth).userId;
    if (!userId) return;
    await this.chat.markRead(body.messageId, userId);
    // derive conversationId for broadcast
    const msg = await this.prisma.message.findUnique({
      where: { id: body.messageId },
      select: { conversationId: true },
    });
    if (msg) {
      this.io.to(`convo:${msg.conversationId}`).emit('read:updated', { messageId: body.messageId, userId });
    }
  }
  @SubscribeMessage('msg:edit')
  async wsEdit(@ConnectedSocket() client: Socket, @MessageBody() b: { id: string; body: string }) {
    const userId = (client.data as WsAuth).userId;
    if (!userId) return;
    const updated = await this.chat.editMessage(b.id, userId, b.body);
    this.io.to(`convo:${updated.conversationId}`).emit('msg:edited', updated);
  }

  @SubscribeMessage('msg:delete')
  async wsDelete(@ConnectedSocket() client: Socket, @MessageBody() b: { id: string }) {
    const userId = (client.data as WsAuth).userId;
    if (!userId) return;
    const deleted = await this.chat.deleteMessage(b.id, userId);
    this.io.to(`convo:${deleted.conversationId}`).emit('msg:deleted', deleted);
  }
}
