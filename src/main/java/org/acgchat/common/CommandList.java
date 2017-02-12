package org.acgchat.common;

import org.acgchat.server.Server;

/**
 * Created by NEOPETS on 12/2/2017.
 */
public class CommandList implements Command{


    @Override
    public String getName() {
        return "/list";
    }

    @Override
    public String getShortHelp() {
        return "List all the users online in the server.";
    }

    @Override
    public String[] getLongHelp() {
        return new String[]{"Usage: /list", getShortHelp()};
    }

    @Override
    public boolean execute(Server server, Server.ClientThread clientThread, String[] args) {
        clientThread.writeMsg(new ChatMessage(ChatMessage.ChatMessageType.COMMAND, "SYSTEM", "List of online users:"));
        for (Object s: server.getLoggedIn().keySet())
            clientThread.writeMsg(new ChatMessage(ChatMessage.ChatMessageType.COMMAND, "SYSTEM", s));
        return true;
    }

    @Override
    public boolean isAdminCommand() {
        return false;
    }
}
