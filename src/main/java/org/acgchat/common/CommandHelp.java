package org.acgchat.common;

import org.acgchat.server.Server;

/**
 * Authors: Kelvin, Darren, QiuRong, Jonathan
 * Class: DISM/FT/2B/02
 */
public class CommandHelp implements Command{
    @Override
    public String getName() {
        return "/help";
    }

    @Override
    public String getShortHelp() {
        return "Shows the help messages";
    }

    @Override
    public String[] getLongHelp() {
        return new String[]{"Usage: /help [command]",  getShortHelp()};
    }

    @Override
    public boolean execute(Server server, Server.ClientThread clientThread, String[] args) {
        if (args.length == 1) {
            clientThread.writeMsg(new ChatMessage(ChatMessage.ChatMessageType.COMMAND, "SYSTEM", "List of available commands:"));
            for (Command c: CommandsHandler.getCommands()) {
                clientThread.writeMsg(new ChatMessage(ChatMessage.ChatMessageType.COMMAND, "SYSTEM", c.getName() + ": \t"  + c.getShortHelp()));
            }
            return true;
        } else {
            Command c = CommandsHandler.getCommand(args[1]);
            if (c != null) {
                for (String s: c.getLongHelp())
                    clientThread.writeMsg(new ChatMessage(ChatMessage.ChatMessageType.COMMAND, "SYSTEM", s));
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean isAdminCommand() {
        return false;
    }
}
