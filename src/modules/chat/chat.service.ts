import { ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../core/database/prisma.service';
import { CreateConversationDto } from './dto/create-conversation.dto';


const MEMBER_SELECT_LIGHT = { id: true, userId: true } as const;
function pairKeyFor(a: string, b: string) {
  return [a, b].sort().join(':'); // consistent ordering
}

@Injectable()
export class ChatService {
  constructor(private prisma: PrismaService) {}

  async createConversation(currentUserId: string, dto: CreateConversationDto) {
    const participants = Array.from(new Set(dto.participantIds.filter(id => id !== currentUserId)));
    if (participants.length === 0) throw new ForbiddenException('Need at least one other participant');

    const isGroup = dto.isGroup ?? participants.length > 1;
    const title = isGroup ? (dto.title ?? null) : null;

    // one-on-one conversation
    if (!isGroup && participants.length === 1) {
      const key = pairKeyFor(currentUserId, participants[0]);
      const existing = await this.prisma.conversation.findUnique({ where: { pairKey: key } });
      if (existing) return existing;
      return this.prisma.conversation.create({
        data: {
          isGroup: false,
          pairKey: key,
          members: {
            create: [
              { userId: currentUserId },
              { userId: participants[0] },
            ],
          },
        },
      });
    }

    // group conversation
    return this.prisma.conversation.create({
      data: {
        isGroup: true,
        title: title ?? undefined,
        members: {
          create: [{ userId: currentUserId }, ...participants.map(id => ({ userId: id }))],
        },
      },
    });
  }

  async listConversations(currentUserId: string) {
    return this.prisma.conversation.findMany({
      where: { members: { some: { userId: currentUserId } } },
      orderBy: { lastMessageAt: 'desc' },
      select: {
        id: true, isGroup: true, title: true, lastMessageAt: true, createdAt: true,
        members: { select: { userId: true } },
      },
    });
  }

  private async ensureMember(conversationId: string, userId: string) {
    const member = await this.prisma.conversationMember.findFirst({
      where: { conversationId, userId },
      select: { id: true },
    });
    if (!member) throw new ForbiddenException('Not a member of this conversation');
  }

  async listMessages(conversationId: string, userId: string, cursor?: string, limit = 20) {
    await this.ensureMember(conversationId, userId);

    return this.prisma.message.findMany({
      where: { conversationId },
      orderBy: { createdAt: 'asc' },
      take: limit,
      ...(cursor ? { skip: 1, cursor: { id: cursor } } : {}),
      select: {
        id: true, senderId: true, body: true, createdAt: true, editedAt: true, deletedAt: true,
      },
    });
  }

  async sendMessage(conversationId: string, senderId: string, dto: { body?: string; clientKey?: string; replyToId?: string }) {
    await this.ensureMember(conversationId, senderId);
    if (!dto.body /* && !attachments later */) {
      throw new NotFoundException('Empty message');
    }

    // 1)   Check for duplicate via clientKey
    if (dto.clientKey) {
      const existing = await this.prisma.message.findFirst({
        where: { conversationId, clientKey: dto.clientKey },
        select: { id: true, conversationId: true, senderId: true, body: true, createdAt: true },
      });
      if (existing) return existing;
    }

    const now = new Date();

    // 2) Get conversation members
    const members = await this.prisma.conversationMember.findMany({
      where: { conversationId },
      select: MEMBER_SELECT_LIGHT,
    });

    // 3) Create message and update conversation lastMessageAt in transaction
    const [msg] = await this.prisma.$transaction([
      this.prisma.message.create({
        data: {
          conversationId,
          senderId,
          body: dto.body ?? null,
          replyToId: dto.replyToId ?? undefined,
          clientKey: dto.clientKey ?? undefined,
        },
        select: { id: true, conversationId: true, senderId: true, body: true, createdAt: true },
      }),
      this.prisma.conversation.update({
        where: { id: conversationId },
        data: { lastMessageAt: now },
      }),
    ]);

    // 4) Update read/unread statuses
    const updates: any[] = [];
    for (const m of members) {
      if (m.userId === senderId) {
        updates.push(
          this.prisma.conversationMember.update({
            where: { conversationId_userId: { conversationId, userId: senderId } },
            data: { lastReadMsgId: msg.id, lastReadAt: now },
          }),
          this.prisma.messageReceipt.upsert({
            where: { messageId_userId: { messageId: msg.id, userId: senderId } },
            create: { messageId: msg.id, userId: senderId, status: 'READ' },
            update: { status: 'READ', at: now },
          }),
        );
      } else {
        updates.push(
          this.prisma.conversationMember.update({
            where: { conversationId_userId: { conversationId, userId: m.userId } },
            data: { unreadCount: { increment: 1 } },
          }),
          this.prisma.messageReceipt.upsert({
            where: { messageId_userId: { messageId: msg.id, userId: m.userId } },
            create: { messageId: msg.id, userId: m.userId, status: 'DELIVERED' },
            update: {}, // keep earliest delivery time
          }),
        );
      }
    }
    await Promise.allSettled(updates);

    return msg;
  }

  async markRead(messageId: string, userId: string) {
    const message = await this.prisma.message.findUnique({
      where: { id: messageId },
      select: { id: true, conversationId: true, createdAt: true },
    });
    if (!message) throw new NotFoundException('Message not found');

    await this.ensureMember(message.conversationId, userId);

    const now = new Date();

    // Update read marker + receipt
    await this.prisma.$transaction([
      this.prisma.conversationMember.update({
        where: { conversationId_userId: { conversationId: message.conversationId, userId } },
        data: { lastReadMsgId: message.id, lastReadAt: now },
      }),
      this.prisma.messageReceipt.upsert({
        where: { messageId_userId: { messageId, userId } },
        create: { messageId, userId, status: 'READ' },
        update: { status: 'READ', at: now },
      }),
    ]);

    // Recompute unreadCount (simple & safe)
    const unread = await this.prisma.message.count({
      where: {
        conversationId: message.conversationId,
        createdAt: { gt: message.createdAt },
        senderId: { not: userId },
        deletedAt: null,
      },
    });

    await this.prisma.conversationMember.update({
      where: { conversationId_userId: { conversationId: message.conversationId, userId } },
      data: { unreadCount: unread },
    });

    return { ok: true };
  }
  async editMessage(messageId: string, editorId: string, body: string) {
    const msg = await this.prisma.message.findUnique({ where: { id: messageId }, select: { senderId: true, conversationId: true } });
    if (!msg) throw new NotFoundException('Message not found');
    await this.ensureMember(msg.conversationId, editorId);
    if (msg.senderId !== editorId) throw new ForbiddenException('Cannot edit another user message');

    return this.prisma.message.update({
      where: { id: messageId },
      data: { body, editedAt: new Date() },
      select: { id: true, conversationId: true, senderId: true, body: true, editedAt: true },
    });
  }

  async deleteMessage(messageId: string, requesterId: string) {
    const msg = await this.prisma.message.findUnique({ where: { id: messageId }, select: { senderId: true, conversationId: true } });
    if (!msg) throw new NotFoundException('Message not found');
    await this.ensureMember(msg.conversationId, requesterId);
    if (msg.senderId !== requesterId) throw new ForbiddenException('Cannot delete another user message');

    return this.prisma.message.update({
      where: { id: messageId },
      data: { deletedAt: new Date(), body: null },
      select: { id: true, conversationId: true, deletedAt: true },
    });
  }
}
