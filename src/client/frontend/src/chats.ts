import { esc, stamp } from "./format";
import type { Conversation } from "./types";

export function chatList(conversations: Conversation[], selected: string) {
  return conversations.map(c => `<button class="conversation ${selected === c.id ? "active" : ""}" data-conversation="${c.id}"><span class="avatar ${c.kind === "group" ? "group" : ""}">${c.kind === "group" ? "#" : c.title.slice(0, 2)}</span><span class="conversation-copy"><b>${esc(c.title)}</b><small>${esc(c.preview ?? "No messages yet")}</small></span><span class="conversation-meta"><small>${stamp(c.timestamp)}</small>${c.unread ? `<em>${c.unread}</em>` : ""}</span></button>`).join("") || `<p class="empty">No conversations yet. Add a signed contact card to begin.</p>`;
}
